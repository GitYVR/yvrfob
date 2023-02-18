from yvrfob.models import User

SECRET_KEY = 'SECRET'

# Simple auth yes I know
ADMINS = [
    User(1, 'username', 'password')
]

ADMINNAME_TABLE = {u.username: u for u in ADMINS}
ADMINID_TABLE = {u.id: u for u in ADMINS}