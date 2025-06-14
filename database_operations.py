# database_operations.py
import sqlite3
import pyotp
from passlib.hash import pbkdf2_sha256

def create_database():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            secret_key TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

def insert_credential(user_id, website, username, encrypted_password, notes=""):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO password_entries (user_id, website, username, encrypted_password, notes)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, website, username, encrypted_password, notes))
    conn.commit()
    conn.close()

def fetch_credentials(user_id):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT website, username FROM password_entries WHERE user_id = ?', (user_id,))
    credentials = cursor.fetchall()
    conn.close()
    return credentials

def fetch_password(user_id, website, username):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_password FROM password_entries WHERE user_id = ? AND website = ? AND username = ?',
                   (user_id, website, username))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def get_user_id(username):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def verify_user(username, password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_password_hash = result[0]
        return pbkdf2_sha256.verify(password, stored_password_hash)

    return False

def register_user(username, password):
    hashed_password = pbkdf2_sha256.hash(password)
    secret_key = pyotp.random_base32()
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password_hash, secret_key) VALUES (?, ?, ?)', (username, hashed_password, secret_key))
        conn.commit()
        return secret_key
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_2fa_secret(user_id):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT secret_key FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def update_credential(user_id, website, username, new_website, new_username, new_password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE password_entries
        SET website = ?, username = ?, encrypted_password = ?
        WHERE user_id = ? AND website = ? AND username = ?
    ''', (new_website, new_username, new_password, user_id, website, username))
    conn.commit()
    conn.close()

def delete_credential(user_id, website, username):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM password_entries
        WHERE user_id = ? AND website = ? AND username = ?
    ''', (user_id, website, username))
    conn.commit()
    conn.close()
