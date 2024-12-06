# main.py

import argparse
from encryption_tool.encryptor import encrypt_file
from encryption_tool.decryptor import decrypt_file

def main():
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt a file")
    parser.add_argument('--encrypt', help="Path to file to encrypt")
    parser.add_argument('--decrypt', help="Path to file to decrypt")
    parser.add_argument('--password', help="Password for encryption/decryption", required=True)

    args = parser.parse_args()

    if args.encrypt:
        encrypt_file(args.encrypt, args.password)
    elif args.decrypt:
        decrypt_file(args.decrypt, args.password)
    else:
        print("Please specify --encrypt or --decrypt")

if __name__ == "__main__":
    main()
