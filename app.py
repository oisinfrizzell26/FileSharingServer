from flask import Flask, render_template
from Database.models import db
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leftovers.db'
db.init_app(app)
with app.app_context():
    db.create_all()
@app.route("/hello", methods=['POST'])
def hello_world():
    return render_template('index.html')

if __name__ == '__main__':
    # For production server deployment
    app.run(debug=False, host='0.0.0.0', port=3333) 