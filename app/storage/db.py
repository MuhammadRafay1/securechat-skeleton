import os
import pymysql
from dotenv import load_dotenv
from typing import Optional
import binascii, hashlib, secrets

load_dotenv()

HOST = os.getenv('MYSQL_HOST','127.0.0.1')
PORT = int(os.getenv('MYSQL_PORT','3306'))
USER = os.getenv('MYSQL_USER','root')
PASSWORD = os.getenv('MYSQL_PASSWORD','')
DB = os.getenv('MYSQL_DB','securechat')

def get_conn():
    return pymysql.connect(host=HOST, port=PORT, user=USER, password=PASSWORD, db=DB, autocommit=True)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        email VARCHAR(255),
        username VARCHAR(255) UNIQUE,
        salt VARBINARY(16),
        pwd_hash CHAR(64)
    ) ENGINE=InnoDB;""")
    cur.close()
    conn.close()

def register_user(email: str, username: str, password: str) -> bool:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT username FROM users WHERE username=%s OR email=%s', (username, email))
    if cur.fetchone():
        cur.close(); conn.close(); return False
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    cur.execute('INSERT INTO users(email, username, salt, pwd_hash) VALUES(%s,%s,%s,%s)',
                (email, username, salt, pwd_hash))
    cur.close()
    conn.close()
    return True

def verify_user(email: str, password: str) -> bool:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT salt, pwd_hash FROM users WHERE email=%s', (email,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        return False
    salt, stored = row
    if isinstance(salt, str):
        salt = salt.encode()
    calc = hashlib.sha256(salt + password.encode()).hexdigest()
    return secrets.compare_digest(calc, stored)
