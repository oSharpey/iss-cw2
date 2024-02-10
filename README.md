<div align="center">
  
# ⇁ ISS CW2 - St John's Clinic Demo Web App
This is a demo web app meant to demonstrate cryptographic functions and SSO through Google OpenID Connect

![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Nginx](https://img.shields.io/badge/nginx-%23009639.svg?style=for-the-badge&logo=nginx&logoColor=white)
![Gunicorn](https://img.shields.io/badge/gunicorn-%298729.svg?style=for-the-badge&logo=gunicorn&logoColor=white)

---
</div>

[![](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

## ⇁ Installation 

### Install SqlCipher
Ubuntu/Debian:
```bash
sudo apt update && sudo apt upgrade
sudo apt install sqlcipher libsqlcipher-dev libsqlcipher0
```

Fedora/RedHat based:
```bash
sudo dnf update --refresh
sudo dnf install sqlcipher sqlcipher-devel
```

### Create a Python virtual environment and install dependencies 
- Created on python 3.12.3
- Create a python venv to install dependencies
```
python3 -m venv venv
pip3 install -r requirements.txt 
```

### Set up DB
```
sqlcipher datbase_enc.db
sqlite> .read schema.sql
```

### Set up the Hashicorp vault server
- Pull the docker image from dockerhub
```
docker pull hashicorp/vault
```
- Run the container in development mode (note: you can change the token to what you wish, just remember to set it in .env)
```
docker run --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' hashicorp/vault
```

### Set up your `.env` file
The app expects the values below in the `.env` file
```
HASHI_TOKEN=<token you set when starting vault server>
OAUTH_CLIENT_ID=<client id provided by google when you create an oauth client>
OAUTH_CLIENT_SECRET=<client secret provided by google when you create an oauth client>
DBPASS=<database passphrase used to decrypt database, by default this is 'UntitledEntailGradedCrumb' set in schema.sql (you can change this)>
APP_SECRET=<random string used to sign session cookies>
```

