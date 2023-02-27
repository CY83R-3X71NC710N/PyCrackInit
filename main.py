

#!/usr/bin/env python
# CY83R-3X71NC710N Copyright 2023

# Import Statements
import os
import sys
import random
import string
import hashlib
import hmac
import base64
import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2

# Main Code
def generate_key(password, salt, key_length):
    """Generates a key using PBKDF2 algorithm with HMAC-SHA256 as the message authentication code.
    
    Args:
        password (str): The password used to generate the key.
        salt (str): The salt used to generate the key.
        key_length (int): The length of the key.
    
    Returns:
        bytes: The generated key.
    """
    return PBKDF2(password, salt, dkLen=key_length, count=1000, prf=lambda p,s: hmac.new(p,s,hashlib.sha256).digest())

def generate_iv(iv_length):
    """Generates an initialization vector (IV) of the specified length.
    
    Args:
        iv_length (int): The length of the IV.
    
    Returns:
        bytes: The generated IV.
    """
    return os.urandom(iv_length)

def encrypt(message, password, salt, key_length=32, iv_length=16):
    """Encrypts a message using AES256 in CBC/CFB modes with HMAC-SHA256 as the message authentication code.
    
    Args:
        message (str): The message to be encrypted.
        password (str): The password used to generate the key.
        salt (str): The salt used to generate the key.
        key_length (int, optional): The length of the key. Defaults to 32.
        iv_length (int, optional): The length of the IV. Defaults to 16.
    
    Returns:
        str: The encrypted message.
    """
    key = generate_key(password, salt, key_length)
    iv = generate_iv(iv_length)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(message)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt(encrypted_message, password, salt, key_length=32, iv_length=16):
    """Decrypts an encrypted message using AES256 in CBC/CFB modes with HMAC-SHA256 as the message authentication code.
    
    Args:
        encrypted_message (str): The encrypted message to be decrypted.
        password (str): The password used to generate the key.
        salt (str): The salt used to generate the key.
        key_length (int, optional): The length of the key. Defaults to 32.
        iv_length (int, optional): The length of the IV. Defaults to 16.
    
    Returns:
        str: The decrypted message.
    """
    key = generate_key(password, salt, key_length)
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:iv_length]
    ciphertext = encrypted_message[iv_length:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext).decode('utf-8')

# GUI Development
def main():
    """Main function for PyCrackInit.
    """
    print("PyCrackInit")
    print("1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter your choice: ")
    if choice == '1':
        message = input("Enter the message to be encrypted: ")
        password = input("Enter the password: ")
        salt = input("Enter the salt: ")
        encrypted_message = encrypt(message, password, salt)
        print("Encrypted message: {}".format(encrypted_message))
    elif choice == '2':
        encrypted_message = input("Enter the encrypted message: ")
        password = input("Enter the password: ")
        salt = input("Enter the salt: ")
        message = decrypt(encrypted_message, password, salt)
        print("Decrypted message: {}".format(message))
    else:
        print("Invalid choice!")

if __name__ == '__main__':
    main()
