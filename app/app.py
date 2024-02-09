from pysqlcipher3 import dbapi2 as sqlite
from binascii import unhexlify
import os
import shutil 
import tempfile
from flask import Flask, render_template, redirect, url_for, session, request, flash, send_file, current_app
from werkzeug.exceptions import abort
from werkzeug.utils import secure_filename
from functools import wraps
from authlib.integrations.flask_client import OAuth
from flask_session import Session
import hvac
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

load_dotenv()


###########################################
########## ASSUMPTIONS & CONTEXT ##########
###########################################

## - In a real production app, each system would be running as separete apps on differnet subdomains (careconnect.example.com, medicloud.example.com, etc)
## - For this demo and simulation, we will just have them as different routes
## - This is to simulate the SSO requirement
## - Having the on differnt routes instead of subdomains means i dont need to configure multiple docker containers and a reverse proxy for the system
## - This is just a demo, so it is fine to have them on different routes
## - In a prod app the user would still be authenticated using the same set of google credentials, fufilling the SSO requirement
## - The RBAC simulated in this demo would be implemented using a production RBAC system like Keycloak with Redis or Auth0

## The following roles are simulated in this demo:
## - admin
## - finance
## - doctor
## - patient
## - external

## The KMS used in this simulation is Hashicorp Vault
## Hashicorp vault is used to store the encryption keys for each file in the cloud system
## This has been simulated using the free tier which provides key value pair storage (it also provides a KMS but that is in the enterprise version)
## In a real production app, the KMS would be a paid service like AWS KMS or Azure Key Vault to provide better salability and control over the key management cycle

## The database used to store all data is encrypted at rst using SQLCipher
## SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption (CBC) of database files
## The passphrase SQLCiphers uses to generate the key is stored in the environment variables which similates the KMS
## In a real production app, the passphrase would be stored in the KMS and retrieved at runtime

## This implementation uses a single database file to store all the data
## In a real production app, there would be multiple databases each being encrypted with its own key
## For example, the user health records would be in a different database file from the financial records
## This is to provide better isolation between user records and sensitive financial data

## This implementation uses dummy self signed certificates provided by flask for TLS/SSL
## In a real production app, we would use a certificate from a CA like LetsEncrypt or Comodo

## Files that are uploaded to the medicloud system are encrypted using AES-GCM
## In this simulation keys are generated using PBKDF2 and stored in hashicorp vault along with the salt and nonce
## The key used to encrypt the file is stored in the KMS (Hashicorp Vault)
## The key is retrieved at runtime and used to decrypt the file



client = hvac.Client(
    url='http://172.17.0.2:8200',
    token=os.getenv("HASHI_TOKEN"),
)


app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET")
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["TMP_FOLDER"] = "tmp"
app.config['UPLOAD_EXTENSIONS'] = ['.pdf', '.txt', '.odf', '.doc', '.docx', '.png', '.jpg', '.jpeg']
app.config["SESSION_COOKIE_NAME"] = "session"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_SECURE"] = True
Session(app)

IV_LENGTH = 12
ITERATION_COUNT = 100000
KEY_LENGTH = 32
SALT_LENGTH = 16
TAG_LENGTH = 16


oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.getenv("OAUTH_CLIENT_ID"),
    client_secret=os.getenv("OAUTH_CLIENT_SECRET"),
    access_token_params=None,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    api_base_url="https://www.googleapis.com/oauth2/v3/",
    userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",  # This is only needed if using openId to fetch user info
    client_kwargs={
        "scope": "openid profile email",
        'code_challenge_method': 'S256'
    },
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
)


def get_db_connection():
    conn = sqlite.connect("database_enc.db")
    conn.row_factory = sqlite.Row
    return conn


def get_record(user_id):
    conn = get_db_connection()
    conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
    record = conn.execute("SELECT * FROM healthrecords WHERE userid = ?", (user_id,)).fetchone()
    conn.close()
    if record is None:
        return []
    return record



# This function is a decorator that checks if the user is authenticated, if not it returns a 401 error
def needs_auth():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user" not in session:
                return abort(401)
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator



# This simple decorator checks if the user has a role in the session
def needs_role(needed_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs): 
            user_roles = session.get("user_roles", [])
            if not any(role in user_roles for role in needed_roles):
                abort(403) # returns 403 forbidden if user does not have a role 
            return func(*args, **kwargs)
        return wrapper
    return decorator


################
#### Routes ####
################





###########################
##### Authen & Author #####
###########################
@app.route("/login")
def login():
    google = oauth.create_client("google")
    redirect_uri = url_for("authorize", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/authorize")
def authorize():
    google = oauth.create_client("google")
    token = google.authorize_access_token()
    userinfo = token["userinfo"]
    session["user"] = userinfo
    
    conn = get_db_connection()
    conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
    # In a real app, the user should be added to the database here if not already
    # The userid would be stored along with the role in the database
    # For this demo, we will just hard code the roles

    if session["user"]["email"] == "oscarsharpe2003@gmail.com":
        session["user_roles"] = ["admin"]
        medrecord = conn.execute("SELECT * FROM healthrecords WHERE userid = ?", (session["user"]["sub"],)).fetchone()
        if medrecord is None:
            conn.execute("INSERT INTO healthrecords (userid, name, dob, bloodtype, notes) VALUES (?, ?, ?, ?, ?)", (session["user"]["sub"], session["user"]["name"], "2000-01-01", "AB+", "n/a"))
            conn.commit()
    if session["user"]["email"] == "isspatientcw2@gmail.com":
        session["user_roles"] = ["patient"]
        medrecord = conn.execute("SELECT * FROM healthrecords WHERE userid = ?", (session["user"]["sub"],)).fetchone()
        if medrecord is None:
            conn.execute("INSERT INTO healthrecords (userid, name, dob, bloodtype, notes) VALUES (?, ?, ?, ?, ?)", (session["user"]["sub"], session["user"]["name"], "2000-01-01", "AB+", "n/a"))
            conn.commit()
    if session["user"]["email"] == "issdoctorcw2@gmail.com":
        session["user_roles"] = ["doctor"]

    if session["user"]["email"] == "issfinancecw2@gmail.com":
        session["user_roles"] = ["finance"]

    if session["user"]["email"] == "issexternalcw2@gmail.com":
        session["user_roles"] = ["external"]
    conn.close()
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/")
def index():
    return render_template("index.html", session=session.get("user", None), roles=session.get("user_roles", []))


############################
###### FINCARE SYSTEM ######
############################

@app.route("/fincare")
@needs_auth()
@needs_role(["finance", "admin"])
def fincare():
    conn = get_db_connection()
    conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
    transactions = conn.execute("SELECT * FROM transactions ORDER BY id desc").fetchall()
    return render_template("fincare.html", session=session.get("user", None), roles=session.get("user_roles", []), transactions=transactions)
    #return "You are authenticated and have the finance role"




###############################
###### MEDRECORDS SYSTEM ######
###############################

@app.route("/medrecords")
@needs_auth()
@needs_role(["doctor", "admin"])
def medrecords():
    conn = get_db_connection()
    conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
    records = conn.execute("SELECT * FROM healthrecords").fetchall()
    conn.close()
    return render_template("medrecords.html", session=session.get("user", None), roles=session.get("user_roles", []), records=records)


@app.route("/medrecords/add", methods=("GET", "POST"))
@needs_auth()
@needs_role(["doctor", "admin"])
def add_record():
    conn = get_db_connection()
    conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
    record = conn.execute("SELECT * FROM healthrecords WHERE userid = ?", (request.args.get("patient"),)).fetchone() 

    if request.method == "POST":
        note = request.form["note"]
        conn.execute("UPDATE healthrecords SET notes = ? WHERE userid = ?", (note, request.args.get("patient")))
        conn.commit()
        return redirect(url_for("medrecords"))
    conn.close()
    return render_template("add_record.html", session=session.get("user", None), roles=session.get("user_roles", []), record=record)



##############################
##### CareConnect System #####
##############################

@app.route("/careconnect")
@needs_auth()
@needs_role(["patient", "admin"])
def careconnect():
    record = get_record(session["user"]["sub"])
    conn = get_db_connection()
    conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
    appointments = conn.execute("SELECT * FROM appointments WHERE userid = ?", (session["user"]["sub"],)).fetchall()
    prescriptions = conn.execute("SELECT * FROM prescriptions WHERE patient = ?", (session["user"]["name"],)).fetchall()
    conn.close()

    return render_template("careconnect.html", record=record,  session=session.get("user", None), roles=session.get("user_roles", []), appointments=appointments, prescriptions=prescriptions)


# Sytsem to schedule appointments
@app.route("/careconnect/schedule", methods=("GET", "POST"))
@needs_auth()
@needs_role(["patient", "admin"])
def schedule():

    if request.method == "POST":
        # Adds the appointment to the db:
        doctor = request.form["doctor"]
        date = request.form["date"]
        time = request.form["time"]
        notes = request.form["notes"]

        if not doctor or not date or not time:
            flash("Doctor, date, and time are required")
        else:
            conn = get_db_connection()
            conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
            conn.execute("INSERT INTO appointments (userid, doctor, date, time, notes) VALUES (?, ?, ?, ?, ?)", (session["user"]["sub"], doctor, date, time, notes))
            conn.commit()
            conn.close()
            return redirect(url_for("careconnect"))
    return render_template("schedule.html", session=session.get("user", None), roles=session.get("user_roles", []))

@app.route("/careconnect/pay", methods=("GET", "POST"))
@needs_auth()
@needs_role(["patient", "admin"])
def pay():
    if request.method == "POST":
        conn = get_db_connection()
        conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
        userid = session["user"]["sub"]
        amount = 9.65
        id = request.args.get("id")
        prescription = conn.execute("SELECT patient FROM prescriptions WHERE id = ?", (id,)).fetchone()
        print("here")
        if prescription is None:
            conn.close()
            return redirect(url_for("careconnect"))
        else:
            print("here2")
            description = f"Payment for prescription ID:{id}"
            conn.execute("INSERT INTO transactions (userid, price, description) VALUES (?, ?, ?)", (userid, amount, description))
            conn.execute("UPDATE prescriptions SET isPaid = 1 WHERE id = ?", (id,))
            conn.commit()
            conn.close()
            return redirect(url_for("careconnect"))
    else:
        return redirect(url_for("careconnect"))


#######################
##### EPS System #####
#######################

@app.route("/eps")
@needs_auth()
@needs_role(["doctor", "admin"])
def eps():
    conn = get_db_connection()
    conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
    prescriptions = conn.execute("SELECT * FROM prescriptions WHERE doctor = ?", (session["user"]["name"],)).fetchall()
    conn.close() 
    return render_template("eps.html",  session=session.get("user", None), roles=session.get("user_roles", []), prescriptions=prescriptions)

@app.route("/eps/prescribe", methods=("GET", "POST"))
@needs_auth()
@needs_role(["doctor", "admin"])
def create_prescription():
    if request.method == "POST":
        # Adds the prescription to the db:
        patient = request.form["patient"]
        drug = request.form["name"]
        dosage = request.form["dosage"]
        frequency = request.form["freq"]
        doctor = session["user"]["name"]
        notes = request.form["notes"]

        if not patient or not drug or not dosage:
            flash("Patient, drug, and dosage are required")
        else:
            conn = get_db_connection()
            conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
            conn.execute("INSERT INTO prescriptions (patient, name, dosage, frequency, notes, doctor) VALUES (?, ?, ?, ?, ?, ?)", (patient, drug, dosage, frequency, notes, doctor))
            conn.commit()
            conn.close()
            return redirect(url_for("eps"))
    conn = get_db_connection()
    conn.execute(f"PRAGMA KEY='{os.getenv("DBPASS")}'")
    patients = conn.execute("SELECT name FROM healthrecords").fetchall()
    conn.close()
    return render_template("prescribe.html", session=session.get("user", None), roles=session.get("user_roles", []), patients=patients)



############################
##### MediCloud System #####
############################


def get_secret_key(password,salt):
    return hashlib.pbkdf2_hmac("SHA512", password, salt, ITERATION_COUNT, KEY_LENGTH)


def encrypt_file(file):
    passphrase = get_random_bytes(16)
    salt = get_random_bytes(SALT_LENGTH)
    nonce = get_random_bytes(IV_LENGTH)
    key = get_secret_key(passphrase, salt)

    kms_stored_secret = salt.hex() + ":" + nonce.hex() + ":" + key.hex()
    
    client.secrets.kv.v2.create_or_update_secret(path=file.filename,secret=dict(password=kms_stored_secret))
    
    encryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = encryptor.encrypt_and_digest(file.read())
    enc_file = ciphertext + tag 
    return enc_file


def decrypt_file(filename):
    kms_stored_secret = client.secrets.kv.v2.read_secret_version(path=filename)
    salt, nonce, key = kms_stored_secret["data"]["data"]["password"].split(":")
    salt = unhexlify(salt)
    nonce = unhexlify(nonce)
    key = unhexlify(key)
    
    filename = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    with open(filename, "rb") as file:
        file = file.read()
        tag = file[-TAG_LENGTH:]
        ciphertext = file[:-TAG_LENGTH]
        decryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = decryptor.decrypt_and_verify(ciphertext, tag)
        return plaintext



@app.route("/medicloud")
@needs_auth()
@needs_role(["external", "doctor", "admin"])
def medicloud():
    files = os.listdir(app.config["UPLOAD_FOLDER"]) 
    return render_template("medicloud.html", session=session.get("user", None), roles=session.get("user_roles", []), files=files)


@app.route("/medicloud/upload", methods=["POST"])
@needs_auth()
@needs_role(["external", "doctor", "admin"])
def upload_file():
    file = request.files["file"]
    filename = secure_filename(file.filename)
    currentfiles = os.listdir(app.config["UPLOAD_FOLDER"])
    if filename in currentfiles:
        flash("File with this name already exists")
        return redirect(url_for("medicloud"))
    if filename != "":
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            flash("Invalid file type")
            return redirect(url_for("medicloud"))
        enc_file = encrypt_file(file)
        with open(os.path.join(app.config["UPLOAD_FOLDER"], filename), "wb") as file:
            file.write(enc_file)
        #enc_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return redirect(url_for("medicloud"))


@app.route("/medicloud/download/<filename>", methods=["GET", "POST"])
@needs_auth()
@needs_role(["external", "doctor", "admin"])
def download_file(filename):
    file = decrypt_file(filename)
     
    # save file to tmp folder
    path = os.path.join(app.config["TMP_FOLDER"], filename)
    with open(path, "wb") as f:
        f.write(file)
    
    # save file in a temporary file and send it to the user
    # ensures that an unencrypted version of the file is not stored on the server
    cache = tempfile.NamedTemporaryFile()
    with open(path, "rb") as f:
        shutil.copyfileobj(f, cache)
        cache.flush()
    cache.seek(0)
    os.remove(path)

    return send_file(cache, as_attachment=True, download_name=filename)

@app.route("/medicloud/delete/<filename>", methods=["GET", "POST"])
@needs_auth()
@needs_role(["external", "doctor", "admin"])
def delete_file(filename):
    client.secrets.kv.v2.delete_metadata_and_all_versions(path=filename)
    os.remove(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return redirect(url_for("medicloud"))

@app.errorhandler(413)
def too_large(e):
    return "File is too large", 413
    

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
