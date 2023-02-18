# YVRFOB

Quick and dirty monorepo for fob key management.

Create `yvrfob/secrets.py`, referencing `yvrfob/secrets.example.py`

```
pyenv install 3.8.10
pyenv shell 3.8.10
curl -s https://bootstrap.pypa.io/get-pip.py | python
pip install -r requirements.txt
pip install gunicorn

# Run in dev
DEV=1 python app.py

# Run in prod
gunicorn --bind 0.0.0.0:8080 --chdir $(pwd) app:app
```