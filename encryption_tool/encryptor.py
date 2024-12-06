# encryption_tool/encryptor.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def encrypt_file(file_path, password):
    """
    Encrypt a file using AES encryption.

    :param file_path: Path to the file to encrypt
    :param password: Password to derive the encryption key
    """
    # Generate a random 16-byte salt
    salt = os.urandom(16)

    # Derive a key from the password using PBKDF2 and the salt
    key = derive_key(password, salt)

    # Initialize the AES cipher in CBC mode
    iv = os.urandom(16)  # 16-byte IV for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the file data and apply padding to make it a multiple of block size
    with open(file_path, 'rb') as f:
        file_data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the padded file data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted data to a new file with .enc extension
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(salt + iv + encrypted_data)

    print(f"File encrypted successfully: {encrypted_file_path}")

def derive_key(password, salt):
    """
    Derive a key from the given password and salt using PBKDF2.

    :param password: The password to derive the key from
    :param salt: The salt to use in the key derivation
    :return: The derived key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key
