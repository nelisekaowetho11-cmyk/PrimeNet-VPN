import os
import sqlite3
import secrets
import hashlib
import hmac
import json

from datetime import datetime, date
from functools import wraps
from urllib.parse import urlsplit, parse_qs, unquote

import psycopg
from psycopg.rows import dict_row

from flask import (
    Flask, request, redirect, url_for,
    session, flash, render_template_string, jsonify
)

from protocol_form import PROTOCOL_FORM

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DB = "primenet.db"

ADMIN_USER = os.environ.get("ADMIN_USER", "hemlock_protocol")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
ADMIN_PIN = os.environ.get("ADMIN_PIN", "")


def connect():
    database_url = os.environ.get("DATABASE_URL")

    if database_url:
        database_url = database_url.replace(
            "postgres://", "postgresql://", 1
        )
        return psycopg.connect(
            database_url,
            row_factory=dict_row
        )

    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def password_hash(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        bytes.fromhex(salt),
        200000
    ).hex()
    return salt + ":" + hashed


def verify_password(password, stored):
    try:
        salt, expected = stored.split(":")
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(salt),
            200000
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
