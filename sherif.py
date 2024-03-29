import argparse
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets
import base64
import getpass

def generate_salt(size=16):
    return  secrets.token_bytes(size)

def load_salt():
    return open("salt.salt", "rb").read()

def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    if load_existing_salt:
        salt = load_salt()
    elif save_salt:
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)

def encrypt(filename, key):
    f = Fernet(key)

    with open(filename, 'rb') as file:
        file_data = file.read()

    encrypted_data = f.encrypt(file_data)

    with open(filename, 'wb') as file:
        file.write(encrypted_data)

def decrypt(file_name, key):
    f = Fernet(key)
    with open(file_name, "rb") as file:
        encrypted_data = file.read()

    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("ERROR")
        return

    with open(file_name, "wb") as file:
        file.write(decrypted_data)

    print("File success encrypted")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="S.H.E.R.I.F - script from encrypt/decrypt files")
    parser.add_argument("file", help="File from encrypting/decrypting")
    parser.add_argument("-s", "--salt-size", help="if this argument take, generated new salt", type=int)
    parser.add_argument("-e", "--encrypt", action="store_true",  help="Encrypt file")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt file")


    args = parser.parse_args()
    file = args.file
    if args.encrypt:
        password = getpass.getpass("Input password for encrypted: ")
        print(password)
    elif args.decrypt:
        password = getpass.getpass("Input password, before you used to encrypt: ")

    if args.salt_size:
        key = generate_key(password, salt_size=args.salt_size, save_salt=True)
    else:
        key = generate_key(password, load_existing_salt=True)

    encrypt_ = args.encrypt
    decrypt_ = args.decrypt

    if encrypt_ and decrypt_:
        raise TypeError("Please, enter, you have encrypt/decrypt this file")
    elif encrypt_:
        encrypt(file, key)
    elif decrypt_:
        decrypt(file, key)
    else:
        raise TypeError("Please, enter, you have encrypt/decrypt this file")
