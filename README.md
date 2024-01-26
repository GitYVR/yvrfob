# YVRFOB

Quick and dirty monorepo for fob key management.

## Prerequisites
1. Install `pyenv`: https://github.com/pyenv/pyenv
2. Install python build dependencies: https://github.com/pyenv/pyenv/wiki#suggested-build-environment

3. Create `yvrfob/secrets.py`, referencing `yvrfob/secrets.example.py`

4. Run the following:
```
pyenv install 3.12.1
pyenv shell 3.12.1
curl -s https://bootstrap.pypa.io/get-pip.py | python
pip install -r requirements.txt
pip install gunicorn

# Run in dev
DEV=1 python app.py

# Run in prod
gunicorn --bind 0.0.0.0:8080 --chdir $(pwd) app:app
```

## Onchain Fob management -- Covalent
Fob management is moving onchain: https://github.com/ori-wagmi/DCTRLMEMBERSHIP

YVRFOB uses Covalent to read the expiration date of the given fob_key. 