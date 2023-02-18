from yvrfob.models import User

SECRET_KEY = 'SECRET'

# Simple auth yes I know
USERS = [
    User(1, 'username', 'password')
]

USERNAME_TABLE = {u.username: u for u in USERS}
USERID_TABLE = {u.id: u for u in USERS}