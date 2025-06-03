from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), nullable=False)
    public_key = db.Column(db.String, nullable=False)

class Files(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String, nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    disk_file_path = db.Column(db.String, nullable=False, unique=True)
    created_at = db.Column(db.DateTime, nullable=False)

class Messages(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    receiver_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ephemeral_key = db.Column(db.String, nullable=False)
    encrypted_file_metadata = db.Column(db.String, nullable=False)
    encrypted_metadata_nonce = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    isread = db.Column(db.Boolean, default=False)

class PreKeyBundle(db.Model):
    __tablename__ = 'pre_key_bundle'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    public_key = db.Column(db.String, nullable=False)
    signature = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_revoked = db.Column(db.Boolean, default=False)

class Nonce(db.Model):
    __tablename__ = 'nonces'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    nonce_value = db.Column(db.String, unique=True, nullable=False) # The actual nonce string
    issued_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False, nullable=False)
