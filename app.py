from datetime import datetime, timedelta

from flask import Flask, render_template, jsonify, request, g
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from Database.models import db, PreKeyBundle, User, OneTimeKeys, Nonce
from utils.crypto import verify_signature

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leftovers.db'
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_DECODE_LEEWAY'] = timedelta(seconds=30)

print(f"DEBUG: Flask app loaded JWT_SECRET_KEY as: '{app.config['JWT_SECRET_KEY']}'")

jwt = JWTManager(app)
db.init_app(app)
with app.app_context():
    db.create_all()

@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({"status": "error", "message": "Missing or invalid token"}), 401

@jwt.invalid_token_loader
def invalid_token_response(callback):
    return jsonify({"status": "error", "message": "Signature verification failed"}), 403 # Forbidden

@jwt.expired_token_loader
def expired_token_response(callback):
    return jsonify({"status": "error", "message": "Token has expired"}), 401

@jwt.revoked_token_loader
def revoked_token_response(callback):
    return jsonify({"status": "error", "message": "Token has been revoked"}), 401



@app.route("/hello", methods=['POST'])
def hello_world():
    return render_template('index.html')


@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    required_fields = [
        'username',
        'identityPublicKey',
        'signedPreKeyPublicKey',
        'signedPreKeySignature',
        'oneTimeKeys'
    ]
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing field: {field}"}), 400

    username = data['username']
    identity_Public_Key = data['identityPublicKey']
    signed_Pre_Key_Public_Key = data['signedPreKeyPublicKey']
    signed_Pre_Key_Signature = data['signedPreKeySignature']
    one_Time_Keys_list = data['oneTimeKeys']

    # Checking that the oneTimeKeys are an array of strings
    if not isinstance(one_Time_Keys_list, list):
        return jsonify({"status": "error", "message": "oneTimeKeys must be an array"}), 400
    if not all(isinstance(k, str) for k in one_Time_Keys_list):
        return jsonify({"status": "error", "message": "All oneTimeKeys must be strings"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"status": "error", "message": "Username already exists"}), 400
    try:
        new_user = User(
            username=username,
            public_key=identity_Public_Key
        )
        db.session.add(new_user)
        db.session.flush()

        new_signed_pre_key = PreKeyBundle(
            user_id=new_user.id,
            public_key=signed_Pre_Key_Public_Key,
            signature=signed_Pre_Key_Signature,
            is_active=True,
            is_revoked=False,
        )
        db.session.add(new_signed_pre_key)

        for otk_public_key in one_Time_Keys_list:
            new_one_time_key = OneTimeKeys(
                user_id=new_user.id,
                public_key=otk_public_key,
                is_used=False
            )
            db.session.add(new_one_time_key)

        db.session.commit()

        return jsonify({"status": "success", "message": "User created successfully"}), 201

    except Exception as e:
        db.session.rollback()
        print('Error during user Registration: ', e)
        return jsonify({"status": "error", "message": "Error during user Registration"}), 500


@app.route('/auth/challenge', methods=['GET'])
def send_Challenge():
    username = request.args.get('username')
    if not username:
        return jsonify({"status": "error", "message": "Missing username in query parameters"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    import secrets
    nonce_value = secrets.token_hex(16)
    try:
        # Delete any existing active nonces for this user (optional, but good for cleanup)
        Nonce.query.filter_by(user_id=user.id, is_used=False).delete()
        db.session.commit()

        # Create and save the new nonce
        new_nonce = Nonce(
            user_id=user.id,
            nonce_value=nonce_value,
            is_used=False,
            expires_at=datetime.utcnow() + timedelta(minutes=5)  # Nonce valid for 5 minutes
        )
        db.session.add(new_nonce)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saving nonce for user {username}: {e}")
        return jsonify({"status": "error", "message": "Failed to generate challenge"}), 500
        # --- END ADDITION ---

    return jsonify({"status": "success", "message": "Challenge sent successfully", "nonce": nonce_value})


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    app.logger.debug(f"Received JSON data: {data}")  # Changed to app.logger.debug
    app.logger.debug(f"Type of received_nonce: {type(data.get('nonce'))}, value: '{data.get('nonce')}'")  # Changed
    app.logger.debug( f"Type of received_signature: {type(data.get('signature'))}, value: '{data.get('signature')}'")  # Changed
    required_fields = ['username', 'nonce', 'signature']
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing field: {field}"}), 400

    username = data['username']
    received_nonce = data['nonce']
    received_signature = data['signature']

    try:
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        identity_Public_Key = user.public_key
        issued_nonce = Nonce.query.filter_by(
            user_id=user.id,
            nonce_value=received_nonce
        ).first()

        if not issued_nonce:
            # Nonce not found, or not issued to this user, or already deleted
            return jsonify({"status": "error", "message": "Invalid or expired nonce"}), 401  # 401 Unauthorized

        if issued_nonce.is_used:
            # Nonce has already been used (replay attempt)
            return jsonify({"status": "error", "message": "Nonce already used"}), 401

        if issued_nonce.expires_at < datetime.utcnow():
            # Nonce has expired
            db.session.delete(issued_nonce)  # Clean up expired nonce
            db.session.commit()
            return jsonify({"status": "error", "message": "Invalid or expired nonce"}), 401

        is_valid_signature = verify_signature(
            public_key_b64=identity_Public_Key,
            message_b64=received_nonce,
            signature_b64=received_signature,
            algorithm='ed25519'
        )
        if not is_valid_signature:
            app.logger.warning(f"Login attempt with invalid signature for user: {username}")
            return jsonify({"status": "error", "message": "Invalid signature"}), 401  # 401 Unauthorized

            # 5. Mark nonce as used to prevent replay
        issued_nonce.is_used = True
        db.session.add(issued_nonce)  # Persist the change
        db.session.commit()

        access_token = create_access_token(identity=user.id)

        app.logger.info(f"User '{username}' logged in successfully.")
        return jsonify({
            "status": "success",
            "message": "Login successful!",
            "access_token": access_token,
            "username": user.username  # Confirm username
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"An unexpected error occurred during login for '{username}': {e}", exc_info=True)
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500
@app.route('/protected', methods=['GET'])
@jwt_required() # This decorator protects the route
def protected_route():
    current_user_id = get_jwt_identity() # Get the identity from the JWT
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"status": "error", "message": "User not found from token"}), 404
    return jsonify({"status": "success", "message": f"Hello, {user.username}! You have access to protected data."}), 200


@app.route('/users/', methods=['GET'])
@jwt_required()
def get_pre_keys():
    current_user_id = get_jwt_identity()
    app.logger.debug(f"Authenticated user ID: {current_user_id}")
    username = request.args.get('username')
    if not username:
        return jsonify({"status": "error", "message": "Missing username in query parameters"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    try:
        public_key = User.query.filter_by(username=username).first().public_key
        user_id = User.query.filter_by(username=username).first().id
        public_pre_key = PreKeyBundle.query.filter_by(user_id=user_id, is_active=True).first().public_key
        pre_key_signature = PreKeyBundle.query.filter_by(user_id=user_id, is_active=True).first().signature




        return jsonify({"status": "success", "message": "Pre Key Bundle Sent Successfully", "Public Key": public_key,
                "Public Pre Key": public_pre_key, "Pre Key Signature": pre_key_signature})

    except Exception as e:
        # Rollback the session in case of any database-related errors within the try block
        db.session.rollback()
        app.logger.error(f"Error during pre key retrieval for user {username}: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Error during pre key retrieval"}), 500



if __name__ == '__main__':
    # For production server deployment
    app.run(debug=False, host='0.0.0.0', port=3333)
