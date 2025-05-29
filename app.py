from urllib import request

from flask import Flask, render_template, jsonify
from Database.models import db, PreKeyBundle

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leftovers.db'
db.init_app(app)
with app.app_context():
    db.create_all()
@app.route("/hello", methods=['POST'])
def hello_world():
    return render_template('index.html')

@app.route('/auth/register', methods= ['POST'])
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
        return None
    return None

    username = data['username']
    identity_Public_Key = data['identityPublicKey']
    signed_Pre_Key_Public_Key = data['signedPreKeyPublicKey']
    signed_Pre_Key_Signature = data['signedPreKeySignature']
    one_Time_Keys_list = data['oneTimeKeys']


# Checking that the oneTimeKeys are an array of strings
    if not isinstance(one_time_keys_list, list):
        return jsonify({"status": "error", "message": "oneTimeKeys must be an array"}), 400
    if not all(isinstance(k, str) for k in one_time_keys_list):
        return jsonify({"status": "error", "message": "All oneTimeKeys must be strings"}), 400\

    if users.query.filter_by(username=username).first():
        return jsonify({"status": "error", "message": "Username already exists"}), 400
    try:
        new_user = User(
            username=username,
            identity_Public_Key=identity_Public_Key
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



if __name__ == '__main__':
    # For production server deployment
    app.run(debug=False, host='0.0.0.0', port=3333) 