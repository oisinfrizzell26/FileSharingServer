from datetime import datetime, timedelta, timezone

from flask import Flask, render_template, jsonify, request, g
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from Database.models import db, PreKeyBundle, User, Nonce, Files
from utils.crypto import verify_signature
from validation import UsernameValidator
from file_service import FileService
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leftovers.db'
app.config['JWT_SECRET_KEY'] = '82974171858986152797271650255250123'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_LEEWAY'] = timedelta(minutes=5)

print(f"DEBUG: Flask app loaded JWT_SECRET_KEY as: '{app.config['JWT_SECRET_KEY']}'")
print(f"Current server time (from inside app): {datetime.now(timezone.utc).isoformat()}")

jwt = JWTManager(app)
db.init_app(app)

file_service = FileService()
file_service.init_app(app)

with app.app_context():
    db.create_all()

@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({"status": "error", "message": "Missing or invalid token"}), 401

@jwt.invalid_token_loader
def invalid_token_response(error_string):
    app.logger.warning(f"JWT invalid: {error_string}. Token: {request.headers.get('Authorization')}")
    return jsonify({"status": "error", "message": "Signature verification failed (detailed)"}), 403

@jwt.expired_token_loader
def expired_token_response(jwt_header, jwt_payload):
    app.logger.info(f"JWT expired. Header: {jwt_header}, Payload: {jwt_payload}. Token: {request.headers.get('Authorization')}")
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
        'signedPreKeySignature'
    ]
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing field: {field}"}), 400

    username = data['username']
    # Username validation
    is_valid, error_msg = UsernameValidator.validate(username)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg}), 400
    identity_Public_Key = data['identityPublicKey']
    signed_Pre_Key_Public_Key = data['signedPreKeyPublicKey']
    signed_Pre_Key_Signature = data['signedPreKeySignature']

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
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)  # Nonce valid for 5 minutes
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

        # issued_nonce.expires_at is likely a naive datetime from SQLite, representing UTC.
        # datetime.now(timezone.utc) is an aware datetime.
        # To compare, make datetime.now(timezone.utc) naive as well for an apples-to-apples comparison of UTC times.
        current_time_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)

        if issued_nonce.expires_at < current_time_utc_naive:
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

        access_token = create_access_token(identity=str(user.id))

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

@app.route('/upload_data', methods=['POST'])
@jwt_required()
def upload_encrypted_file():
    current_user_id_str = get_jwt_identity()
    try:
        owner_id = int(current_user_id_str) # Assuming user ID in token is a string representation of an int
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid user ID format in token"}), 400

    if 'encrypted_file' not in request.files:
        return jsonify({"status": "error", "message": "Missing encrypted_file part in request"}), 400
    
    client_file_uuid = request.form.get('file_uuid')
    if not client_file_uuid:
        return jsonify({"status": "error", "message": "Missing file_uuid in form data"}), 400

    uploaded_file = request.files['encrypted_file']

    if uploaded_file.filename == '':
        return jsonify({"status": "error", "message": "No selected file"}), 400

    try:
        encrypted_data = uploaded_file.read()
        if not encrypted_data:
            return jsonify({"status": "error", "message": "Uploaded file is empty"}), 400

        # Use the global file_service instance initialized earlier
        file_record = file_service.store_file(
            file_uuid=client_file_uuid, 
            encrypted_data=encrypted_data, 
            owner_id=owner_id
        )
        
        return jsonify({
            "status": "success", 
            "message": "File uploaded successfully", 
            "file_id_in_db": file_record.id, # The auto-incremented ID from Files table
            "client_uuid": file_record.uuid, 
            "disk_path": file_record.disk_file_path
        }), 201

    except FileNotFoundError as e: # Catch specific errors from FileService/FileStorageHandler if defined
        app.logger.error(f"File storage error during upload: {e}")
        return jsonify({"status": "error", "message": str(e)}), 404
    # You might want to catch other specific exceptions from your file storage handler, e.g., FileSizeExceededError
    # from files import FileSizeExceededError, FileStorageError (if these are defined and raised)
    # except FileSizeExceededError as e:
    #     return jsonify({"status": "error", "message": str(e)}), 413 # Payload Too Large
    # except FileStorageError as e:
    #     app.logger.error(f"File storage error during upload: {e}")
    #     return jsonify({"status": "error", "message": "Could not store file due to storage error"}), 500
    except Exception as e:
        # Log the full error for debugging
        app.logger.error(f"Unexpected error during file upload: {e}", exc_info=True)
        # Provide a generic error message to the client
        return jsonify({"status": "error", "message": "An unexpected error occurred during file upload"}), 500

if __name__ == '__main__':
    # For production server deployment
    app.run(debug=False, host='0.0.0.0', port=3333)