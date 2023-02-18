from hmac import compare_digest

from yvrfob.secrets import USERNAME_TABLE, USERID_TABLE

# Bare bones authentication, taken from https://pythonhosted.org/Flask-JWT/


def authenticate(username, password):
    user = USERNAME_TABLE.get(username, None)
    if user and compare_digest(user.password.encode('utf-8'), password.encode('utf-8')):
        return user


def identity(payload):
    user_id = payload['identity']
    return USERID_TABLE.get(user_id, None)

