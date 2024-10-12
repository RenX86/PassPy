import os
import base64
import sqlite3
import csv
import secrets
import string
import validators
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DB_FILE = "passwords.db"
SALT_FILE = "salt.bin"
KEY_LENGTH = 32
ITERATIONS = 100000
DEFAULT_PASSWORD_LENGTH = 16

# Database Initialization
def initialize_database():
    """Initialize the password database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, site_name TEXT, url TEXT, username TEXT, password TEXT, salt BLOB)''')
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error initializing database: {e}")
    finally:
        conn.close()

# Encryption and Decryption Functions
def encrypt(plaintext, key):
    """Encrypts a plaintext string using AES encryption."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encrypted).decode()

def decrypt(ciphertext, key):
    """Decrypts a ciphertext string using AES decryption."""
    try:
        data = base64.urlsafe_b64decode(ciphertext)
        iv = data[:16]
        encrypted = data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted.decode()
    except (ValueError, InvalidKey) as e:
        logging.error(f"Decryption failed: {e}")
        return None

# Key Generation
def generate_key(master_password, salt):
    """Generates a key using the master password and a salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

def get_master_key():
    """Prompt the user for the master password and generate a key."""
    master_password = input("Enter your master password: ")
    if len(master_password) < 8:
        logging.warning("Master password is too short! Use at least 8 characters.")
        return None
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    else:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()

    return generate_key(master_password, salt), salt

# Storing and Retrieving Passwords
def store_password(site_name, url, username, password, key, salt):
    """Stores an encrypted password in the database."""
    if not validators.url(url):
        logging.error(f"Invalid URL: {url}")
        return
    encrypted_password = encrypt(password, key)
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO passwords (site_name, url, username, password, salt) VALUES (?, ?, ?, ?, ?)",
                  (site_name, url, username, encrypted_password, salt))
        conn.commit()
        logging.info(f"Password for {site_name} stored successfully.")
    except sqlite3.Error as e:
        logging.error(f"Error storing password: {e}")
    finally:
        conn.close()

def retrieve_passwords_by_keyword(keyword, key):
    """Retrieve and decrypt passwords by keyword search."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT site_name, url, username, password FROM passwords WHERE site_name LIKE ?", ('%' + keyword + '%',))
        rows = c.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Error retrieving passwords: {e}")
        return
    finally:
        conn.close()

    if rows:
        logging.info(f"\nResults for site keyword '{keyword}':")
        for row in rows:
            site_name, url, username, encrypted_password = row
            password = decrypt(encrypted_password, key)
            if password:
                print(f"Site Name: {site_name}\nURL: {url}\nUsername: {username}\nPassword: {password}")
                print("-" * 30)
            else:
                logging.warning(f"Failed to decrypt password for {site_name}.")
    else:
        logging.info(f"No results found for the site keyword '{keyword}'.")

# CSV Import
def import_passwords_from_csv(file_path, key, salt):
    """Imports passwords from a CSV file."""
    try:
        with open(file_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                site_name = row.get('site_name')
                url = row.get('url')
                username = row.get('username')
                password = row.get('password')
                if not all([site_name, url, username, password]):
                    logging.error(f"Invalid row in CSV: {row}")
                    continue
                store_password(site_name, url, username, password, key, salt)  # Ensure salt is passed here
                logging.info(f"Imported {site_name} with username {username} successfully.")
    except FileNotFoundError as e:
        logging.error(f"File not found: {file_path}")


# Password Generation
def generate_password(length=DEFAULT_PASSWORD_LENGTH):
    """Generates a strong random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Menu Helpers
def handle_store_password(key, salt):
    """Handle storing a new password."""
    site_name = input("Enter site name: ")
    url = input("Enter URL: ")
    username = input("Enter username: ")
    password = getpass("Enter password: ")
    store_password(site_name, url, username, password, key, salt)

def handle_retrieve_password(key):
    """Handle retrieving passwords."""
    keyword = input("Enter site keyword to search: ")
    retrieve_passwords_by_keyword(keyword, key)  # Only pass key here, no need for salt

def handle_generate_password():
    """Handle generating a new password."""
    length = int(input(f"Enter the password length (default {DEFAULT_PASSWORD_LENGTH}): ") or DEFAULT_PASSWORD_LENGTH)
    password = generate_password(length)
    print(f"Generated password: {password}")

def handle_import_passwords(key, salt):
    """Handle importing passwords from CSV."""
    file_path = input("Enter the CSV file path: ")
    import_passwords_from_csv(file_path, key, salt)

# Main Program
def main():
    logging.info("Welcome to the Password Manager")
    key, salt = get_master_key()
    if not key:
        return

    # Initialize the database if not already
    initialize_database()

    while True:
        print("\nOptions:")
        print("1. Store a new password")
        print("2. Retrieve a password")
        print("3. Generate a strong password")
        print("4. Import passwords from CSV")
        print("5. Quit")

        choice = input("Choose an option: ")
        if choice == "1":
            handle_store_password(key, salt)
        elif choice == "2":
            handle_retrieve_password(key)
        elif choice == "3":
            handle_generate_password()
        elif choice == "4":
            handle_import_passwords(key, salt)
        elif choice == "5":
            logging.info("Goodbye!")
            break
        else:
            logging.warning("Invalid option. Please choose again.")

if __name__ == "__main__":
    main()
