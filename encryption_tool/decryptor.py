# encryption_tool/decryptor.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Import the derive_key function from encryptor.py
from encryption_tool.encryptor import derive_key

def decrypt_file(file_path, password):
    """
    Decrypt a file using AES encryption.

    :param file_path: Path to the file to decrypt
    :param password: Password to derive the decryption key
    """
    # Read the encrypted file
    with open(file_path, 'rb') as enc_file:
        file_data = enc_file.read()

    # Extract salt, IV, and encrypted data
    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    # Derive the key using the same password and salt
    key = derive_key(password, salt)

    # Initialize the AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the file data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Determine the decrypted file path
    if file_path.endswith(".enc"):
        decrypted_file_path = file_path.replace(".enc", ".dec")
    else:
        decrypted_file_path = file_path + ".dec"

    # Save the decrypted data to a new file
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(unpadded_data)

    print(f"File decrypted successfully: {decrypted_file_path}")
