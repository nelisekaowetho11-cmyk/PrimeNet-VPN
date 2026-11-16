import os
import sqlite3
import secrets
import hashlib
import hmac
import json

from datetime import datetime, date
from functools import wraps
from contextlib import contextmanager
from urllib.parse import urlsplit, parse_qs, unquote

from flask import (
    Flask, request, redirect, url_for, session,
    flash, render_template_string, jsonify
)

from protocol_form import PROTOCOL_FORM


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)


# DATABASE CONNECTION

def connect():
    url = os.environ.get("DATABASE_URL")

    if url:
        import psycopg
        from psycopg.rows import dict_row

        url = url.replace("postgres://", "postgresql://", 1)

        return psycopg.connect(
            url,
            row_factory=dict_row
        )

    db = sqlite3.connect("primenet.db")
    db.row_factory = sqlite3.Row
    return db


@contextmanager
def database():
    db = connect()

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def execute(db, sql, params=()):
    if os.environ.get("DATABASE_URL"):
        sql = sql.replace("?", "%s")

    return db.execute(sql, params)


# PASSWORD FUNCTIONS

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


# DATABASE INITIALIZATION

def init_db():

    with database() as db:

        if os.environ.get("DATABASE_URL"):

            db.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            """)

            db.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    expires TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created TEXT NOT NULL,
                    password_text TEXT,
                    config_json TEXT
                )
            """)

            # FIX: IF NOT EXISTS prevents duplicate-column errors.
            # This avoids PostgreSQL's aborted-transaction problem.

            db.execute("""
                ALTER TABLE accounts
                ADD COLUMN IF NOT EXISTS password_text TEXT
            """)

            db.execute("""
                ALTER TABLE accounts
                ADD COLUMN IF NOT EXISTS config_json TEXT
            """)

        else:

            db.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )
            """)

            db.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    protocol TEXT,
                    expires TEXT,
                    status TEXT,
                    created TEXT,
                    password_text TEXT,
                    config_json TEXT
                )
            """)

            columns = {
                row["name"]
                for row in db.execute(
                    "PRAGMA table_info(accounts)"
                ).fetchall()
            }

            if "password_text" not in columns:
                db.execute("""
                    ALTER TABLE accounts
                    ADD COLUMN password_text TEXT
                """)

            if "config_json" not in columns:
                db.execute("""
                    ALTER TABLE accounts
                    ADD COLUMN config_json TEXT
                """)

        admin = execute(
            db,
            "SELECT id FROM admins LIMIT 1"
        ).fetchone()

        if not admin:

            username = os.environ.get(
                "ADMIN_USER",
                "hemlock_protocol"
            )

            password = os.environ.get("ADMIN_PASS", "")

            if not password:
                raise RuntimeError(
                    "ADMIN_PASS environment variable is required."
                )

            execute(
                db,
                """
                INSERT INTO admins (username, password)
                VALUES (?, ?)
                """,
                (username, password_hash(password))
            )


# PAGE TEMPLATE

def page(title, body, **context):

    template = """
    <!doctype html>
    <html>
    <head>
    <meta name="viewport"
          content="width=device-width, initial-scale=1">

    <title>{{ title }} - PRIME NET</title>

    <style>
    * {
        box-sizing: border-box;
    }

    body {
        margin: 0;
        background: #090d16;
        color: #edf2ff;
        font-family: Arial, sans-serif;
    }

    header {
        background: #111a2b;
        padding: 18px;
        text-align: center;
    }

    header h1 {
        color: #35d39a;
        margin: 0;
    }

    nav {
        padding: 12px;
        text-align: center;
        background: #101827;
    }

    nav a {
        color: #35d39a;
        margin: 8px;
        text-decoration: none;
    }

    main {
        max-width: 850px;
        margin: 25px auto;
        padding: 15px;
    }

    .card {
        background: #131e30;
        padding: 20px;
        border-radius: 13px;
        margin: 15px 0;
    }

    input, select, textarea {
        width: 100%;
        padding: 12px;
        margin: 8px 0 15px;
        background: #091321;
        color: white;
        border: 1px solid #34445e;
        border-radius: 7px;
    }

    button {
        background: #20b987;
        color: #06140f;
        padding: 12px 18px;
        border: 0;
        border-radius: 7px;
        font-weight: bold;
        cursor: pointer;
    }

    a {
        color: #35d39a;
    }

    .muted {
        color: #a9b6ca;
    }

    table {
        width: 100%;
        border-collapse: collapse;
    }

    td, th {
        padding: 9px;
        border-bottom: 1px solid #34445e;
        text-align: left;
    }
    </style>
    </head>

    <body>

    <header>
        <h1>✞ PRIME NET ✞</h1>
        <p>Private VPN Administration</p>
    </header>

    {% if session.get('admin') %}
    <nav>
        <a href="/">Dashboard</a>
        <a href="/create">Create Account</a>
        <a href="/records">Records</a>
        <a href="/settings">Settings</a>
        <a href="/logout">Logout</a>
    </nav>
    {% endif %}

    <main>

    {% for message in get_flashed_messages() %}
        <div class="card">{{ message }}</div>
    {% endfor %}

    """ + body + """

    </main>
    </body>
    </html>
    """

    return render_template_string(
        template,
        title=title,
        **context
    )


# LOGIN PROTECTION

def login_required(fn):

    @wraps(fn)
    def wrapped(*args, **kwargs):

        if not session.get("admin"):
            return redirect(url_for("login"))

        return fn(*args, **kwargs)

    return wrapped


# CLIPBOARD CONFIG IDENTIFICATION

def parse_config(link):

    try:
        parsed = urlsplit(link.strip())

        scheme = parsed.scheme.lower()

        if scheme not in ("vless", "trojan"):
            return None

        protocol = scheme.upper()
        host = parsed.hostname
        port = parsed.port
        secret = unquote(parsed.username or "")

        query = parse_qs(parsed.query)

        if not host or not port or not secret:
            return None

        return {
            "protocol": protocol,
            "server": host,
            "port": port,
            "secret": secret,
            "sni": query.get("sni", [""])[0],
            "name": unquote(parsed.fragment)
        }

    except Exception:
        return None


# LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        with database() as db:

            admin = execute(
                db,
                "SELECT * FROM admins WHERE username=?",
                (username,)
            ).fetchone()

        if admin and verify_password(
            password,
            admin["password"]
        ):

            session.clear()
            session["admin"] = admin["username"]

            return redirect(url_for("dashboard"))

        flash("Incorrect username or password.")

    return page(
        "Admin Login",
        """
        <div class="card">
            <h2>Admin Login</h2>

            <form method="post">

                <label>Username</label>
                <input name="username" required>

                <label>Password</label>
                <input name="password"
                       type="password"
                       required>

                <button>Login</button>

            </form>
        </div>
        """
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# DASHBOARD

@app.route("/")
@login_required
def dashboard():

    with database() as db:
        rows = execute(
            db,
            "SELECT * FROM accounts"
        ).fetchall()

    active = sum(
        1 for r in rows
        if r["status"] == "Active"
        and r["expires"] >= today_text()
    )

    killed = sum(
        1 for r in rows
        if r["status"] == "Killed"
    )

    return page(
        "Dashboard",
        """
        <div class="card">

            <h2>Welcome, {{ admin }}</h2>

            <p>Total accounts: {{ total }}</p>
            <p>Active accounts: {{ active }}</p>
            <p>Killed accounts: {{ killed }}</p>

            <a href="/create">
                Create a new account →
            </a>

        </div>
        """,
        admin=session["admin"],
        total=len(rows),
        active=active,
        killed=killed
    )


# CREATE ACCOUNT PAGE

@app.route("/create")
@login_required
def create():

    return page(
        "Create Account",
        """
        <div class="card">

            <h2>Create Private Account</h2>

            <form id="accountform"
                  method="post"
                  action="/create_account">

                <label>Customer username</label>
                <input name="username" required>

                <label>Customer password</label>
                <input name="password"
                       type="password"
                       required>

                <label>Expiry date</label>
                <input name="expires"
                       type="date"
                       required>

                """ + PROTOCOL_FORM + """

                <button>Create Account</button>

            </form>

        </div>

        <div class="card">

            <h2>Identify Clipboard Protocol</h2>

            <textarea id="clip"
                      style="height:85px"></textarea>

            <button type="button"
                    onclick="identify()">
                Identify
            </button>

            <p id="result"></p>

        </div>

        <script>
        async function identify() {

            let r = await fetch("/parse", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    link: document.getElementById("clip").value
                })
            });

            let d = await r.json();

            document.getElementById("result").innerText =
                d.protocol
                ? "Detected protocol: " + d.protocol
                : "Unsupported or invalid link";
        }
        </script>
        """
    )


# PARSE CLIPBOARD

@app.route("/parse", methods=["POST"])
@login_required
def parse():

    data = request.get_json(silent=True) or {}

    result = parse_config(
        data.get("link", "")
    )

    if not result:

        return jsonify({
            "error": "Invalid VLESS or Trojan link"
        }), 400

    return jsonify({
        "protocol": result["protocol"]
    })


# SAVE ACCOUNT

@app.route("/create_account", methods=["POST"])
@login_required
def create_account():

    username = request.form.get(
        "username", ""
    ).strip()

    password = request.form.get(
        "password", ""
    )

    expires = request.form.get(
        "expires", ""
    )

    protocol = request.form.get(
        "protocol", "VLESS"
    ).upper()

    if not username or not password or not expires:

        flash("Complete all required fields.")

        return redirect(url_for("create"))

    try:
        date.fromisoformat(expires)

    except ValueError:

        flash("Invalid expiry date.")

        return redirect(url_for("create"))

    if protocol not in (
        "VLESS",
        "VMESS",
        "TROJAN",
        "SHADOWSOCKS"
    ):

        flash("Unsupported protocol.")

        return redirect(url_for("create"))

    config = {
        key: value
        for key, value in request.form.items()
        if key not in (
            "username",
            "password",
            "expires"
        )
    }

    try:

        with database() as db:

            execute(
                db,
                """
                INSERT INTO accounts
                (
                    username,
                    password_hash,
                    protocol,
                    expires,
                    status,
                    created,
                    password_text,
                    config_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    password_hash(password),
                    protocol,
                    expires,
                    "Active",
                    now_text(),
                    None,
                    json.dumps(config)
                )
            )

    except Exception:

        app.logger.exception("Account creation failed")

        flash(
            "Account could not be created. "
            "Username may already exist."
        )

        return redirect(url_for("create"))

    flash("Account created successfully.")

    return redirect(url_for("records"))


# CUSTOMER RECORDS

@app.route("/records")
@login_required
def records():

    with database() as db:

        rows = execute(
            db,
            "SELECT * FROM accounts ORDER BY id DESC"
        ).fetchall()

    return page(
        "Records",
        """
        <div class="card">

            <h2>Customer Records</h2>

            <table>

                <tr>
                    <th>Username</th>
                    <th>Protocol</th>
                    <th>Expiry</th>
                    <th>Status</th>
                    <th>Action</th>
                </tr>

                {% for r in rows %}

                <tr>

                    <td>{{ r.username }}</td>

                    <td>{{ r.protocol }}</td>

                    <td>{{ r.expires }}</td>

                    <td>{{ r.status }}</td>

                    <td>
                        <button
                            type="button"
                            data-value="{{ r.username }}"
                            onclick="copyText(this.dataset.value)">
                            Copy username
                        </button>
                    </td>

                </tr>

                {% endfor %}

            </table>

        </div>

        <div class="card">

            <h2>Kill Account</h2>

            <form method="post" action="/kill">

                <label>Username</label>
                <input name="username" required>

                <button>Kill Account</button>

            </form>

        </div>

        <script>
        function copyText(t) {
            navigator.clipboard.writeText(t);
        }
        </script>
        """,
        rows=rows
    )


# KILL ACCOUNT

@app.route("/kill", methods=["POST"])
@login_required
def kill():

    username = request.form.get(
        "username", ""
    ).strip()

    with database() as db:

        result = execute(
            db,
            """
            UPDATE accounts
            SET status='Killed'
            WHERE username=?
            """,
            (username,)
        )

        found = result.rowcount

    if found:
        flash("Account disabled.")
    else:
        flash("Account not found.")

    return redirect(url_for("records"))


# ADMIN SETTINGS

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():

    if request.method == "POST":

        pin = request.form.get("pin", "")

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        correct_pin = os.environ.get(
            "ADMIN_PIN", ""
        )

        if not correct_pin or not hmac.compare_digest(
            pin,
            correct_pin
        ):

            flash("Incorrect security PIN.")

        elif not username or not password:

            flash("Enter a username and password.")

        else:

            try:

                with database() as db:

                    result = execute(
                        db,
                        """
                        UPDATE admins
                        SET username=?, password=?
                        WHERE username=?
                        """,
                        (
                            username,
                            password_hash(password),
                            session["admin"]
                        )
                    )

                    if not result.rowcount:
                        raise RuntimeError(
                            "Admin account was not found."
                        )

                session.clear()

                flash("Admin login updated.")

                return redirect(url_for("login"))

            except Exception:

                app.logger.exception(
                    "Admin login update failed"
                )

                flash(
                    "That admin username may already be in use."
                )

    return page(
        "Settings",
        """
        <div class="card">

            <h2>Change Admin Login</h2>

            <form method="post">

                <label>Five-digit security PIN</label>

                <input name="pin"
                       type="password"
                       minlength="5"
                       maxlength="5"
                       required>

                <label>New username</label>
                <input name="username" required>

                <label>New password</label>
                <input name="password"
                       type="password"
                       required>

                <button>Save Login</button>

            </form>

        </div>
        """
    )


# 404 PAGE

@app.errorhandler(404)
def not_found(error):

    return page(
        "Not Found",
        "<div class='card'>Page not found.</div>"
    ), 404


# START DATABASE

init_db()


# LOCAL RUN

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
)
