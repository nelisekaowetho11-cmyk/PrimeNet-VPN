import os, sqlite3, secrets, hashlib, hmac, json
from datetime import datetime, date
from urllib.parse import urlsplit, parse_qs, unquote
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, render_template_string, jsonify
from protocol_form import PROTOCOL_FORM


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DB = "primenet.db"

ADMIN_USER = os.environ.get("ADMIN_USER", "hemlock_protocol")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
ADMIN_PIN = os.environ.get("ADMIN_PIN", "")


class DBConnection:
    def __init__(self, db, postgres=False):
        self.db = db
        self.postgres = postgres

    def __enter__(self):
        self.db.__enter__()
        return self

    def __exit__(self, *args):
        return self.db.__exit__(*args)

    def execute(self, sql, params=()):
        if self.postgres:
            sql = sql.replace("?", "%s")
        return self.db.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self.db, name)


def connect():
    database_url = os.environ.get("DATABASE_URL")

    if database_url:
        import psycopg
        from psycopg.rows import dict_row
        database_url = database_url.replace("postgres://", "postgresql://", 1)
        db = psycopg.connect(database_url, row_factory=dict_row)
        return DBConnection(db, True)

    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return DBConnection(db)


def password_hash(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), 200000
    ).hex()
    return salt + ":" + hashed


def verify_password(password, stored):
    try:
        salt, expected = stored.split(":")
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), 200000
        ).hex()
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_text():
    return date.today().isoformat()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper
