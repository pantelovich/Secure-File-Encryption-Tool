# Secure File Encryption Tool

A simple command-line tool to securely encrypt and decrypt files using AES-256 encryption with PBKDF2 key derivation.

## Features

- AES-256 encryption and decryption with CBC mode.
- PBKDF2 key derivation from a user-provided password.
- Supports encrypting and decrypting files with .enc extension.
- Secure padding with PKCS7 before encryption and removal after decryption.

## Installation

1. Clone the repository

    ```bash
    git clone https://github.com/pantelovich/Secure-File-Encryption-Tool.git
    cd Secure-File-Encryption-Tool
    ```

2. Set up the virtual environment

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # On Windows, use .venv\Scripts\activate
    ```

3. Install dependencies

    ```bash
    pip install -r requirements.txt
    ```

    Alternatively, if you're using the cryptography package directly, install it with:

    ```bash
    pip install cryptography
    ```

## Usage

1. Encrypt a file

    To encrypt a file, use the following command:

    ```bash
    python3 main.py --encrypt /path/to/your/file.txt --password your_password
    ```

    This will create an encrypted file with a .enc extension.

2. Decrypt a file

    To decrypt the encrypted file, use the following command:

    ```bash
    python3 main.py --decrypt /path/to/your/file.txt.enc --password your_password
    ```