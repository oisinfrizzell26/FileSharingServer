from datetime import datetime, timedelta

from flask import Flask, render_template, jsonify, request, g
from Database.models import db, PreKeyBundle, User, OneTimeKeys, Nonce
from utils.crypto import verify_signature

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leftovers.db'
db.init_app(app)
with app.app_context():
    db.create_all()


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
            messsage_b64=received_nonce,
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

        #session_token = secrets.token_urlsafe(32)

        app.logger.info(f"User '{username}' logged in successfully.")
        return jsonify({
            "status": "success",
            "message": "Login successful!",
            #"token": session_token,
            "username": user.username  # Confirm username
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"An unexpected error occurred during login for '{username}': {e}", exc_info=True)
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500


if __name__ == '__main__':
    # For production server deployment
    app.run(debug=False, host='0.0.0.0', port=3333)
