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
    uuid = db.Column(db.String, nullable=False)
    encrypted_file_data = db.Column(db.String, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

class ReturnMessages(db.Model):
    __tablename__ = 'return_messages'
    associated_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    ephemeral_key = db.Column(db.String, nullable=False)
    encrypted_file_entry = db.Column(db.String, nullable=False)
    otp_key = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

class PreKeyBundle(db.Model):
    __tablename__ = 'pre_key_bundle'
    username = db.Column(db.String(80), db.ForeignKey('users.username'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    pre_key = db.Column(db.String)
    signed_pre_key = db.Column(db.String)

class OneTimeKeys(db.Model):
    __tablename__ = 'one_time_keys'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    username = db.Column(db.String(80), db.ForeignKey('users.username'))
    otk = db.Column(db.String)
    used = db.Column(db.Boolean)

    # file_path = uploads_dir/ uuid :)))))