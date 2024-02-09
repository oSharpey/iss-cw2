import hvac
import sys
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from binascii import unhexlify

ITERATION_COUNT = 100000
KEY_LENGTH = 32
SALT_LENGTH = 16
IV_LENGTH = 12
TAG_LENGTH = 16
UPLOAD_FOLDER = "uploads"


client = hvac.Client(
    url="http://172.17.0.2:8200",
    token=os.getenv("HASHI_TOKEN")
)


def get_secret_key(password,salt):
    return hashlib.pbkdf2_hmac("SHA512", password, salt, ITERATION_COUNT, KEY_LENGTH)


def encrypt_file(file, filename):
    passphrase = get_random_bytes(16)
    salt = get_random_bytes(SALT_LENGTH)
    nonce = get_random_bytes(IV_LENGTH)
    key = get_secret_key(passphrase, salt)

    kms_stored_secret = salt.hex() + ":" + nonce.hex() + ":" + key.hex()
    
    client.secrets.kv.v2.create_or_update_secret(path=filename,secret=dict(password=kms_stored_secret))
    
    encryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = encryptor.encrypt_and_digest(file)
    enc_file = ciphertext + tag 
    return enc_file


def decrypt_file(filename):
    kms_stored_secret = client.secrets.kv.v2.read_secret_version(path=filename, raise_on_deleted_version=True)
    salt, nonce, key = kms_stored_secret["data"]["data"]["password"].split(":")
    salt = unhexlify(salt)
    nonce = unhexlify(nonce)
    key = unhexlify(key)
   
    filename = os.path.join(UPLOAD_FOLDER, filename)

    with open(filename, "rb") as file:
        file = file.read()
        tag = file[-TAG_LENGTH:]
        ciphertext = file[:-TAG_LENGTH]
        decryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = decryptor.decrypt_and_verify(ciphertext, tag)
        return plaintext


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 key_compromised.py <filename>")
        sys.exit(1)

    filepath = sys.argv[1]
    filename = os.path.basename(filepath)

    if not os.path.exists(filepath):
        print(f"File {filename} does not exist")
        sys.exit(1)

    file = decrypt_file(filename)
    print("[+] File decrypted successfully")
    
    client.secrets.kv.v2.delete_metadata_and_all_versions(path=filename)
    print("[+] Secret deleted successfully")

    enc_file = encrypt_file(file, filename)

    with open (os.path.join(UPLOAD_FOLDER, filename), "wb") as file:
        file.write(enc_file)

    print("[+] File encrypted successfully")
    print("[+] New secret stored successfully")
    
    print(f"\n\n[+] Key for file {filename} has been rotated successfully\n\n")
     


if __name__ == "__main__":
    main()
