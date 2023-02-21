import os
import re
import time

from datetime import timedelta, timezone, datetime

from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, set_access_cookies, jwt_required, unset_jwt_cookies, get_jwt, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy

from yvrfob.auth import authenticate
from yvrfob.secrets import SECRET_KEY

"""
Flask Configuration, should probably break this up into
smaller files, but that sounds like a job for the future
"""
# Using flask so we can host a webpage AND an API at the same time easily

# Flask app
app = Flask(__name__)
csrf = CSRFProtect()

app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yvrfob.sqlite3'
app.config['JWT_SECRET_KEY'] = SECRET_KEY
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # No need to mix CSRF and JWT
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config['WTF_CSRF_CHECK_DEFAULT'] = False # Selectively enable CSRF protection
app.config['SECRET_KEY'] = SECRET_KEY

# CORS for frontend apps
CORS(app)

# CSRF for form
csrf.init_app(app)

# JWT For REST based AUTH
jwt = JWTManager(app)

# Database ORM
db = SQLAlchemy(app)


"""
Templating - Extending Jinja2
"""


# Templating
@app.template_filter()
def format_datetime(value):
    return datetime.fromtimestamp(value).strftime("%d/%m/%Y, %H:%M:%S")


@app.template_filter()
def has_expired(value):
    return datetime.now() > datetime.fromtimestamp(value)


@app.template_filter()
def is_membership_active(value):
    return 'No' if has_expired(value) else 'Yes'


class Fob(db.Model):
    """
    Fob database object
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    fob_key = db.Column(db.String(32), unique=True)
    expire_timestamp = db.Column(db.Integer)


"""
REST APIs
"""


@app.route('/auth', methods=['POST'])
def auth():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if not authenticate(username, password):
        return jsonify({'error': 'Bad username or password'}), 401

    access_token = create_access_token(identity=username)
    return jsonify({'access_token': access_token})


@app.route('/fob/<fob_key>/user', methods=['GET'])
def fob_user(fob_key):
    fob = Fob.query.filter_by(fob_key=fob_key).first()
    if fob is None:
        return jsonify({'name': None, 'expire_timestamp': None})
    return jsonify({'name': fob.name, 'expire_timestamp': fob.expire_timestamp})


@app.route('/fob/<fob_key>/valid', methods=['GET'])
def fob_valid(fob_key):
    fob = Fob.query.filter_by(fob_key=str(fob_key)).first()
    if fob is None:
        return jsonify({'valid': False})
    if time.time() > fob.expire_timestamp:
        return jsonify({'valid': False})
    return jsonify({'valid': True})


@app.route('/fob/<fob_key>/update', methods=['POST'])
@jwt_required()
def modify_fob(fob_key):
    username = request.json.get('username', None)
    expire_timestamp = request.json.get('expire_timestamp', None)

    fob = Fob.query.filter_by(fob_key=str(fob_key)).first()
    if fob is None:
        return jsonify({'error': 'fob_key ' + fob_key + ' not found'})

    try:
        int(expire_timestamp)
    except:
        return jsonify({'error': 'expire_timestamp needs to be an integer'}), 401

    if username is not None:
        fob.name = username
    if expire_timestamp is not None:
        fob.expire_timestamp = int(expire_timestamp)

    db.session.commit()
    return jsonify({'success': 'fob_key ' + fob_key + ' updated'})


"""
Rendered views, yes I know, probably can clean these up...
But alas...
"""


@app.route('/add', methods=['POST'])
@jwt_required()
def add_fob():
    username = request.form.get('username', None)
    fob_key = request.form.get('fob_key', None)
    expire_timestamp = request.form.get('expire_timestamp', None)

    if (username == '' or username is None or fob_key is None or fob_key == '' or expire_timestamp is None or expire_timestamp == ''):
        return jsonify({'error': 'Expecting fields username, fob_key and expire_timestamp'}), 401

    # Remove all non-word characters
    fob_key = re.sub(r"[^\w\s]", '', fob_key)

    # See if the fob already exists
    fob_exists = Fob.query.filter_by(fob_key=str(fob_key)).first()
    if fob_exists is not None:
        return redirect(url_for('.dashboard', supplied_fob_key=fob_key, fob_key_exists=True))

    fob = Fob(name=username, fob_key=fob_key,
              expire_timestamp=expire_timestamp)
    db.session.add(fob)
    db.session.commit()
    return redirect(url_for('.dashboard', fob_key_added=True, fob_key=fob_key))

# uses POST cuz forms only have POST/GET reeee


@app.route('/update', methods=['POST'])
@jwt_required()
def update_fob():
    fob_key = request.form.get('fob_key', None)
    expire_timestamp = request.form.get('expire_timestamp', None)
    username = request.form.get('name', None)

    if fob_key is None or expire_timestamp is None or username is None:
        return jsonify({'error': 'Expecting field fob_key, expiry_time, and username'}), 401

    fob = Fob.query.filter_by(fob_key=fob_key).first()
    fob.name = username
    fob.expire_timestamp = expire_timestamp
    db.session.commit()
    return redirect(url_for('.dashboard', fob_key_updated=True, fob_key=fob_key))

# uses POST cuz forms only have POST/GET reeee


@app.route('/delete', methods=['POST'])
@jwt_required()
def delete_fob():
    fob_key = request.form.get('fob_key', None)

    if fob_key is None:
        return jsonify({'error': 'Expecting field fob_key'}), 401

    fob = Fob.query.filter_by(fob_key=fob_key).first()
    db.session.delete(fob)
    db.session.commit()
    return redirect('/dashboard')


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


@app.route('/dashboard')
def dashboard():
    access_token_cookie = request.cookies.get('access_token_cookie', None)
    if access_token_cookie is None:
        return redirect(url_for('login'))
    verify_jwt_in_request()
    fobs = Fob.query.all()
    return render_template('dashboard.html', fobs=fobs, **request.args)


@app.route('/new', methods=["POST"])
def new_user():
    csrf.protect()

    username = request.form.get('username', None)
    fob_key = request.form.get('fob_key', None)
    expire_timestamp = int(datetime.now().timestamp())

    if (username == '' or username is None or fob_key is None or fob_key == '' or expire_timestamp is None or expire_timestamp == ''):
        return jsonify({'error': 'Expecting fields username, fob_key'}), 401

    # Remove all non-word characters
    fob_key = re.sub(r"[^\w\s]", '', fob_key)

    # See if the fob already exists
    fob_exists = Fob.query.filter_by(fob_key=str(fob_key)).first()
    if fob_exists is not None:
        return redirect(url_for('.home', supplied_fob_key=fob_key, fob_key_exists=True))

    fob = Fob(name=username, fob_key=fob_key,
              expire_timestamp=expire_timestamp)
    db.session.add(fob)
    db.session.commit()
    return redirect(url_for('.home', username=username, new_user=True, fob_key=fob_key))


@app.route('/membership', methods=["POST", "GET"])
def membership():
    if request.method == 'POST':
        fob_key = request.form.get('fob_key', None)

        # See if the fob exists
        fob = Fob.query.filter_by(fob_key=str(fob_key)).first()

        # Not exist
        if fob is None:
            return render_template('membership.html', fob_key=fob_key, fob_key_not_found=True)

        cur_timestamp = int(datetime.now().timestamp())
        return render_template('membership.html', username=fob.name, expired=fob.expire_timestamp < cur_timestamp, expire_timestamp=fob.expire_timestamp, fob_key=fob_key, fob_key_found=True)

    return render_template('membership.html', **request.args)


@app.route('/')
def home():
    return render_template('index.html', **request.args)


"""
JWT Token Handling
"""

# Using an `after_request` callback, we refresh any token that is within 30
# minutes of expiring. Change the timedeltas to match the needs of your application.


@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response


@jwt.expired_token_loader
def force_login_on_token_expire(jwt_header, jwt_payload):
    return redirect('/login')


# Entry point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    if os.environ.get('DEV'):
        app.run(port=8080, debug=True)
    else:
        app.run()
