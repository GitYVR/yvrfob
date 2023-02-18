import re
import time

from datetime import datetime

from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, set_access_cookies, jwt_required, unset_jwt_cookies
from flask_sqlalchemy import SQLAlchemy

from yvrfob.auth import authenticate
from yvrfob.secrets import SECRET_KEY

# Using flask so we can host a webpage AND an API at the same time easily

# Flask app
app = Flask(__name__)

app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yvrfob.sqlite3'
app.config['JWT_SECRET_KEY'] = SECRET_KEY
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Already have JWT enabled lol


# Templating
@app.template_filter()
def format_datetime(value):
    return datetime.fromtimestamp(value).strftime("%d/%m/%Y, %H:%M:%S")


@app.template_filter()
def has_expired(value):
    return datetime.now() > datetime.fromtimestamp(value)


@app.template_filter()
def has_expired_str(value):
    return 'Yes' if has_expired(value) else 'No'


# JWT
jwt = JWTManager(app)

# Simple ORM
db = SQLAlchemy(app)


class Fob(db.Model):
    """
    Fob database object
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    fob_key = db.Column(db.String(32), unique=True)
    expire_timestamp = db.Column(db.Integer)


@app.route('/fob/user', methods=['GET'])
def fob_name():
    fob_key = request.args.get('fob_key')
    fob = Fob.query.filter_by(fob_key=str(fob_key)).first()
    if fob is None:
        return jsonify({'user': None})
    return jsonify({'user': fob.name})


@app.route('/fob/valid', methods=['GET'])
def fob_valid():
    fob_key = request.args.get('fob_key')
    fob = Fob.query.filter_by(fob_key=str(fob_key)).first()
    if fob is None:
        return jsonify({'valid': False})
    if time.time() > fob.expire_timestamp:
        return jsonify({'valid': False})
    return jsonify({'valid': True})


@app.route('/fob/add', methods=['POST'])
@jwt_required()
def add_fob():
    username = request.form.get('username', None)
    fob_key = request.form.get('fob_key', None)
    expire_timestamp = request.form.get('expire_timestamp', None)

    if (username == '' or username is None or fob_key is None or fob_key == '' or expire_timestamp is None or expire_timestamp == ''):
        return jsonify({'error': 'Expecting fields username, fod_id and expire_timestamp'}), 401

    # Remove all non-word characters
    fob_key = re.sub(r"[^\w\s]", '', fob_key)
    fob = Fob(name=username, fob_key=fob_key,
              expire_timestamp=expire_timestamp)
    db.session.add(fob)
    db.session.commit()
    return redirect('/')


@app.route('/fob/delete', methods=['POST'])
@jwt_required()
def delete_fob():
    fob_key = request.form.get('fob_key', None)

    if fob_key is None:
        return jsonify({'error': 'Expecting field fob_key'}), 401

    fob = Fob.query.filter_by(fob_key=fob_key).first()
    db.session.delete(fob)
    db.session.commit()
    return redirect('/')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    elif request.method == 'POST':
        username = request.form.get("username", None)
        password = request.form.get("password", None)

        if not authenticate(username, password):
            return make_response(render_template('login.html', login_unsuccessful=True))

        access_token = create_access_token(identity=username)
        resp = make_response(render_template(
            'login.html', login_successful=True))
        set_access_cookies(resp, access_token)
        return resp


@app.route("/logout", methods=["POST"])
def logout():
    response = redirect('/')
    unset_jwt_cookies(response)
    return response


@app.route('/')
def home():
    access_token_cookie = request.cookies.get('access_token_cookie', None)
    if access_token_cookie is None:
        return redirect(url_for('login'))
    verify_jwt_in_request()
    fobs = Fob.query.all()
    return render_template('fob-list.html', fobs=fobs)


@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return redirect('/login')


# Entry point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
    # When not running in prod
    # app.run(host='0.0.0.0', port=8080, debug=True)
