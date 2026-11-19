
import os
import sqlite3
import secrets
import hashlib
import hmac
import json
import base64
from datetime import datetime, date
from contextlib import contextmanager
from functools import wraps
from urllib.parse import urlsplit, parse_qs, unquote, urlencode, quote

from flask import (
    Flask, request, redirect, url_for,
    session, flash, render_template_string
)

from protocol_form import PROTOCOL_FORM


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True
)


# DATABASE

def connect():
    url = os.environ.get("DATABASE_URL")

    if url:
        import psycopg
        from psycopg.rows import dict_row
        url = url.replace("postgres://", "postgresql://", 1)
        return psycopg.connect(url, row_factory=dict_row)

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


# PASSWORD SECURITY

def password_hash(password):
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 200000
    )
    return salt.hex() + ":" + hashed.hex()


def verify_password(password, stored):
    try:
        salt, expected = stored.split(":", 1)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(),
            bytes.fromhex(salt), 200000
        ).hex()
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


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
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(accounts)")
            }
            if "password_text" not in columns:
                db.execute(
                    "ALTER TABLE accounts ADD COLUMN password_text TEXT"
                )
            if "config_json" not in columns:
                db.execute(
                    "ALTER TABLE accounts ADD COLUMN config_json TEXT"
                )

        admin = execute(
            db, "SELECT id FROM admins LIMIT 1"
        ).fetchone()

        if not admin:
            username = os.environ.get("ADMIN_USER", "")
            password = os.environ.get("ADMIN_PASS", "")
            if not username or not password:
                raise RuntimeError(
                    "ADMIN_USER and ADMIN_PASS must be configured."
                )
            execute(
                db,
                "INSERT INTO admins (username,password) VALUES (?,?)",
                (username, password_hash(password))
            )


init_db()


# CONFIGURATION IMPORT

def decode_config(link):
    link = link.strip()
    try:
        scheme = urlsplit(link).scheme.lower()

        if scheme == "vmess":
            raw = link[len("vmess://"):].split("#", 1)[0]
            raw += "=" * (-len(raw) % 4)
            data = json.loads(
                base64.urlsafe_b64decode(raw).decode()
            )
            return {
                "protocol": "VMESS",
                "server": data.get("add", ""),
                "port": str(data.get("port", "")),
                "secret": data.get("id", ""),
                "transport": data.get("net", ""),
                "security": data.get("tls", "none") or "none",
                "name": data.get("ps", ""),
                "path": data.get("path", ""),
                "host": data.get("host", ""),
                "alterid": data.get("aid", "0"),
                "encryption": data.get("scy", "auto")
            }

        if scheme in ("vless", "trojan"):
            parsed = urlsplit(link)
            query = parse_qs(parsed.query)
            return {
                "protocol": scheme.upper(),
                "server": parsed.hostname or "",
                "port": str(parsed.port or ""),
                "secret": unquote(parsed.username or ""),
                "transport": query.get("type", [""])[0],
                "security": query.get("security", ["none"])[0],
                "sni": query.get("sni", [""])[0],
                "path": query.get("path", [""])[0],
                "host": query.get("host", [""])[0],
                "flow": query.get("flow", [""])[0],
                "public_key": query.get("pbk", [""])[0],
                "short_id": query.get("sid", [""])[0],
                "fingerprint": query.get("fp", [""])[0],
                "spider_x": query.get("spx", [""])[0],
                "name": unquote(parsed.fragment)
            }

        if scheme == "ss":
            return {
                "protocol": "SHADOWSOCKS",
                "link": link,
                "name": unquote(urlsplit(link).fragment)
            }
    except Exception:
        return None
    return None


# CONFIGURATION GENERATOR

def make_config(config):
    if config.get("mode") == "clipboard":
        return config.get("link", "")

    protocol = str(config.get("protocol", "")).upper()
    server = str(config.get("server", "")).strip()
    port = str(config.get("port", "")).strip()
    secret = str(config.get("secret", "")).strip()

    if not server or not port or not secret:
        return "Configuration incomplete."

    profile = quote(
        str(config.get("profile_name") or "PRIME-NET"), safe=""
    )
    transport = str(config.get("transport", "")).lower()
    security = str(config.get("security", "none")).lower()

    query = {}
    if transport:
        query["type"] = transport
    if security:
        query["security"] = security

    fields = {
        "sni": "sni", "flow": "flow", "path": "path",
        "host": "host", "public_key": "pbk",
        "short_id": "sid", "fingerprint": "fp",
        "spider_x": "spx", "alpn": "alpn",
        "service_name": "serviceName", "grpc_mode": "mode",
        "header_type": "headerType", "seed": "seed"
    }

    for source, target in fields.items():
        value = config.get(source)
        if value:
            query[target] = str(value)

    if protocol == "VLESS":
        query["encryption"] = "none"
        return (
            f"vless://{quote(secret, safe='')}"
            f"@{server}:{port}?{urlencode(query)}#{profile}"
        )

    if protocol == "TROJAN":
        return (
            f"trojan://{quote(secret, safe='')}"
            f"@{server}:{port}?{urlencode(query)}#{profile}"
        )

    if protocol == "VMESS":
        data = {
            "v": "2",
            "ps": str(config.get("profile_name") or "PRIME-NET"),
            "add": server,
            "port": port,
            "id": secret,
            "aid": str(config.get("alterid", "0")),
            "scy": str(config.get("encryption", "auto")),
            "net": transport,
            "type": str(config.get("header_type", "none")),
            "host": str(config.get("host", "")),
            "path": str(config.get("path", "")),
            "tls": "" if security == "none" else security,
            "sni": str(config.get("sni", ""))
        }
        raw = base64.b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).decode()
        return "vmess://" + raw

    if protocol == "SHADOWSOCKS":
        method = str(config.get("method", "aes-256-gcm"))
        raw = base64.urlsafe_b64encode(
            f"{method}:{secret}".encode()
        ).decode().rstrip("=")
        return f"ss://{raw}@{server}:{port}#{profile}"

    return "Unsupported protocol."


# SAVED SETTINGS

SETTING_LABELS = {
    "transport": "Transport",
    "security": "Security",
    "flow": "Flow",
    "path": "Path",
    "host": "Host",
    "sni": "SNI",
    "fingerprint": "Fingerprint",
    "alpn": "ALPN",
    "public_key": "REALITY Public Key",
    "short_id": "REALITY Short ID",
    "spider_x": "SpiderX",
    "service_name": "gRPC Service Name",
    "grpc_mode": "gRPC Mode",
    "header_type": "Header Type",
    "seed": "mKCP Seed",
    "alterid": "Alter ID",
    "encryption": "Encryption",
    "method": "Shadowsocks Method",
    "mux_enabled": "Mux",
    "mux_protocol": "Mux Protocol",
    "mux_concurrency": "Mux Concurrency",
    "http_payload_proxy": "HTTP Payload Proxy",
    "payload_proxy": "Payload Proxy",
    "proxy_host": "Proxy Host",
    "proxy_port": "Proxy Port",
    "payload": "HTTP Payload"
}


def get_saved_settings(config):
    result = []
    for key, label in SETTING_LABELS.items():
        value = config.get(key)
        if value is None or str(value).strip() == "":
            continue
        if key == "mux_enabled":
            value = "Enabled" if str(value).lower() in (
                "true", "1", "yes", "enabled"
            ) else "Disabled"
        if key in ("http_payload_proxy", "payload_proxy"):
            value = "Enabled" if str(value).lower() in (
                "true", "1", "yes", "enabled"
            ) else "Disabled"
        result.append({"label": label, "value": str(value)})
    return result


# HTML DESIGN

BASE = """
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} - PRIME NET</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#090d16;color:#edf2ff;font-family:Arial,sans-serif}
header{background:#111a2b;padding:20px;text-align:center;position:relative}
header h1{color:#35d39a;margin:0;font-size:29px}
header p{margin:9px 0 0;color:#d5deed}
.menu{position:absolute;right:15px;top:14px}
.menu button{font-size:25px;padding:4px 12px;background:transparent;color:#35d39a}
.menu-content{display:none;position:absolute;right:0;top:42px;background:#18263b;min-width:205px;border:1px solid #34445e;border-radius:10px;z-index:5}
.menu-content a{display:block;padding:14px;color:#edf2ff;text-decoration:none}
nav{background:#101827;padding:12px;text-align:center}
nav a{color:#35d39a;margin:8px;text-decoration:none;display:inline-block}
main{max-width:900px;margin:20px auto;padding:14px}
.card{background:#131e30;padding:20px;border-radius:15px;margin:14px 0}
input,select,textarea{width:100%;padding:13px;margin:8px 0 15px;background:#091321;color:white;border:1px solid #34445e;border-radius:9px;font-size:16px}
textarea{min-height:115px}
button,.btn{background:#20b987;color:#06140f;padding:12px 17px;border:0;border-radius:8px;font-weight:bold;cursor:pointer;text-decoration:none;display:inline-block}
.secondary{background:#1c3045;color:#edf2ff;border:1px solid #34445e}
.danger{background:#9d3947;color:white}
.option{display:block;background:#10283a;border:1px solid #28516a;border-radius:13px;padding:21px;margin:13px 0;color:#edf2ff;text-decoration:none}
.option strong{display:block;color:#35d39a;font-size:19px;margin-bottom:7px}
table{width:100%;border-collapse:collapse;display:block;overflow-x:auto}
td,th{padding:10px;border-bottom:1px solid #34445e;text-align:left;white-space:nowrap}
.output{white-space:pre-wrap;overflow-wrap:anywhere;background:#091321;border:1px solid #34445e;padding:15px;border-radius:10px}
.small{color:#a9b6ca;font-size:13px}
.setting-row{padding:11px 0;border-bottom:1px solid #34445e;overflow-wrap:anywhere}
.setting-row strong{color:#35d39a}
@media(max-width:600px){main{padding:10px}header h1{font-size:25px}}
</style>
</head>
<body>
<header>
<h1>✞ PRIME NET ✞</h1>
<p>Private VPN Administration</p>
{% if session.get('admin') %}
<div class="menu">
<button onclick="toggleMenu()">⋮</button>
<div class="menu-content" id="menuContent">
<a href="/kill">Kill Account</a>
<a href="/settings">Change Login Method</a>
</div>
</div>
{% endif %}
</header>
{% if session.get('admin') %}
<nav>
<a href="/">Dashboard</a>
<a href="/create">Create Account</a>
<a href="/records">Records</a>
<a href="/logout">Logout</a>
</nav>
{% endif %}
<main>
{% for message in get_flashed_messages() %}
<div class="card">{{ message }}</div>
{% endfor %}
{{ body|safe }}
</main>
<script>
function toggleMenu(){
let m=document.getElementById("menuContent");
if(m){m.style.display=m.style.display==="block"?"none":"block";}
}
</script>
</body>
</html>
"""


def page(title, body, **data):
    inner = render_template_string(body, **data)
    return render_template_string(BASE, title=title, body=inner)


# LOGIN PROTECTION

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


# ADMIN LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        with database() as db:
            admin = execute(
                db,
                "SELECT * FROM admins WHERE username=?",
                (request.form.get("username", ""),)
            ).fetchone()

        if admin and verify_password(
            request.form.get("password", ""), admin["password"]
        ):
            session.clear()
            session["admin"] = admin["username"]
            return redirect(url_for("dashboard"))

        flash("Incorrect username or password.")

    return page("Admin Login", """
    <div class="card">
    <h2>Admin Login</h2>
    <form method="post">
    <label>Username</label>
    <input name="username" required>
    <label>Password</label>
    <input name="password" type="password" required>
    <button>Login</button>
    </form>
    </div>
    """)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# DASHBOARD

@app.route("/")
@login_required
def dashboard():
    with database() as db:
        rows = execute(db, "SELECT * FROM accounts").fetchall()

    today = date.today().isoformat()
    active = sum(
        1 for r in rows
        if r["status"] == "Active" and r["expires"] >= today
    )
    killed = sum(1 for r in rows if r["status"] == "Killed")

    return page(
        "Dashboard",
        """
        <div class="card">
        <h2>Welcome, {{ admin }}</h2>
        <p>Total accounts: {{ total }}</p>
        <p>Active accounts: {{ active }}</p>
        <p>Killed accounts: {{ killed }}</p>
        </div>
        <a class="option" href="/clipboard">
        <strong>▣ Copy with Clipboard</strong>
        Import a supported configuration link.
        </a>
        <a class="option" href="/manual">
        <strong>＋ Create Manually</strong>
        Enter configuration details yourself.
        </a>
        """,
        admin=session["admin"],
        total=len(rows),
        active=active,
        killed=killed
    )


@app.route("/create")
@login_required
def create():
    return redirect(url_for("dashboard"))


# SAVE ACCOUNT

def save_account(username, password, expires, protocol, config):
    with database() as db:
        result = execute(
            db,
            """
            INSERT INTO accounts
            (username,password_hash,protocol,expires,status,created,config_json)
            VALUES (?,?,?,?,?,?,?)
            RETURNING id
            """,
            (
                username,
                password_hash(password),
                protocol,
                expires,
                "Active",
                datetime.now().isoformat(),
                json.dumps(config)
            )
        )
        return result.fetchone()["id"]


# NEW COPY DETAILS SUCCESS PAGE

def account_created(account_id, username, password):
    message = (
        "𝐏𝐫𝐢𝐦𝐞𝐍𝐞𝐭 𝐕𝐏𝐍 𝐏𝐫𝐢𝐯𝐚𝐭𝐞 𝐏𝐥𝐮𝐠\n"
        "➮𝐔𝐬𝐞𝐫𝐧𝐚𝐦𝐞: " + username + "\n"
        "➮𝐏𝐚𝐬𝐬𝐰𝐨𝐫𝐝: " + password + "\n"
        "➮𝐒𝐭𝐚𝐭𝐮𝐬: 𝐀𝐜𝐭𝐢𝐯𝐞\n"
        "➮𝐌𝐞𝐬𝐬𝐚𝐠𝐞: 𝐓𝐡𝐚𝐧𝐤𝐬 𝐟𝐨𝐫 𝐛𝐮𝐲𝐢𝐧𝐠 𝐨𝐮𝐫 𝐏𝐥𝐮𝐠🇿🇦"
    )

    return page(
        "Account Created",
        """
        <div class="card">
        <h2>Account Created Successfully!</h2>
        <p>Your customer account has been saved.</p>
        <div class="output" id="customerMessage">{{ message }}</div>
        <button onclick="copyDetails()">Copy Details</button>
        <p id="copyStatus" class="small"></p>
        <a class="btn secondary" href="/account/{{ account_id }}">View Account</a>
        <a class="btn secondary" href="/records">Customer Records</a>
        </div>
        <script>
        function copyDetails(){
            const message=document.getElementById("customerMessage").innerText;
            const status=document.getElementById("copyStatus");

            function fallbackCopy(){
                const area=document.createElement("textarea");
                area.value=message;
                document.body.appendChild(area);
                area.select();
                const copied=document.execCommand("copy");
                area.remove();
                status.innerText=copied
                    ?"Details copied successfully!"
                    :"Copy failed. Please select and copy the message.";
            }

            if(navigator.clipboard && window.isSecureContext){
                navigator.clipboard.writeText(message)
                .then(()=>{status.innerText="Details copied successfully!";})
                .catch(fallbackCopy);
            }else{
                fallbackCopy();
            }
        }
        </script>
        """,
        account_id=account_id,
        message=message
    )


# MANUAL ACCOUNT

@app.route("/manual", methods=["GET", "POST"])
@login_required
def manual():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        expires = request.form.get("expires", "")
        protocol = request.form.get("protocol", "").upper()

        if not username or len(password) < 8:
            flash("Enter a username and password of at least 8 characters.")
            return redirect(url_for("manual"))

        try:
            date.fromisoformat(expires)
            if expires < date.today().isoformat():
                raise ValueError()
        except ValueError:
            flash("Choose a valid expiry date.")
            return redirect(url_for("manual"))

        if protocol not in ("VLESS", "VMESS", "TROJAN", "SHADOWSOCKS"):
            flash("Select a supported protocol.")
            return redirect(url_for("manual"))

        config = {
            key: value.strip()
            for key, value in request.form.items()
            if key not in ("username", "password", "expires")
        }
        config["mode"] = "manual"

        if not config.get("server") or not config.get("port"):
            flash("Server and port are required.")
            return redirect(url_for("manual"))

        try:
            port_number = int(config["port"])
            if not 1 <= port_number <= 65535:
                raise ValueError()
        except ValueError:
            flash("Enter a valid port number.")
            return redirect(url_for("manual"))

        if not config.get("secret"):
            flash("Enter the protocol credential.")
            return redirect(url_for("manual"))

        if not config.get("transport"):
            flash("Please choose a transport.")
            return redirect(url_for("manual"))

        if not config.get("security"):
            flash("Please choose a security option.")
            return redirect(url_for("manual"))

        if not config.get("mux_enabled"):
            flash("Please choose whether Mux is enabled or disabled.")
            return redirect(url_for("manual"))

        try:
            account_id = save_account(
                username, password, expires, protocol, config
            )
        except Exception:
            app.logger.exception("Manual account creation failed")
            flash("Could not create account. Username may already exist.")
            return redirect(url_for("manual"))

        return account_created(account_id, username, password)

    return page(
        "Create Manually",
        """
        <div class="card">
        <h2>Create Manually</h2>
        <form method="post" id="accountform">
        <label>Customer username</label>
        <input name="username" required>
        <label>Customer password (minimum 8 characters)</label>
        <input name="password" type="password" minlength="8" required>
        <label>Expiry date</label>
        <input name="expires" type="date" min="{{ today }}" required>
        """ + PROTOCOL_FORM + """
        <button>Create Account</button>
        </form>
        </div>
        <a class="btn secondary" href="/">Back</a>
        """,
        today=date.today().isoformat()
    )


# CLIPBOARD IMPORT

@app.route("/clipboard", methods=["GET", "POST"])
@login_required
def clipboard():
    if request.method == "POST":
        link = request.form.get("config", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        expires = request.form.get("expires", "")

        parsed = decode_config(link)

        if not parsed:
            flash("Unsupported configuration link.")
            return redirect(url_for("clipboard"))

        if not username or len(password) < 8:
            flash("Enter a username and password of at least 8 characters.")
            return redirect(url_for("clipboard"))

        try:
            date.fromisoformat(expires)
            if expires < date.today().isoformat():
                raise ValueError()
        except ValueError:
            flash("Choose a valid expiry date.")
            return redirect(url_for("clipboard"))

        config = {
            "mode": "clipboard",
            "link": link,
            "parsed": parsed
        }

        try:
            account_id = save_account(
                username, password, expires,
                parsed["protocol"], config
            )
        except Exception:
            app.logger.exception("Clipboard account creation failed")
            flash("Could not create account. Username may already exist.")
            return redirect(url_for("clipboard"))

        return account_created(account_id, username, password)

    return page(
        "Copy with Clipboard",
        """
        <div class="card">
        <h2>Copy with Clipboard</h2>
        <form method="post">
        <label>Paste VLESS / VMess / Trojan / Shadowsocks link</label>
        <textarea name="config" required></textarea>
        <label>Customer username</label>
        <input name="username" required>
        <label>Customer password (minimum 8 characters)</label>
        <input name="password" type="password" minlength="8" required>
        <label>Expiry date</label>
        <input name="expires" type="date" min="{{ today }}" required>
        <button>Import Account</button>
        </form>
        </div>
        <a class="btn secondary" href="/">Back</a>
        """,
        today=date.today().isoformat()
    )


# ACCOUNT DETAILS

@app.route("/account/<int:account_id>")
@login_required
def account(account_id):
    with database() as db:
        row = execute(
            db,
            "SELECT * FROM accounts WHERE id=?",
            (account_id,)
        ).fetchone()

    if not row:
        flash("Account not found.")
        return redirect(url_for("records"))

    config = json.loads(row["config_json"] or "{}")
    output = make_config(config)
    settings = get_saved_settings(config)

    return page(
        "Account Details",
        """
        <div class="card">
        <h2>Account Details</h2>
        <p><b>Username:</b> {{ username }}</p>
        <p><b>Protocol:</b> {{ protocol }}</p>
        <p><b>Expiry:</b> {{ expires }}</p>
        <p><b>Status:</b> {{ status }}</p>
        </div>

        <div class="card">
        <h2>Saved Settings</h2>
        {% if settings %}
            {% for item in settings %}
            <div class="setting-row">
            <strong>{{ item.label }}:</strong> {{ item.value }}
            </div>
            {% endfor %}
        {% else %}
            <p class="small">No additional settings saved.</p>
        {% endif %}
        </div>

        <div class="card">
        <h2>Configuration Link</h2>
        <div class="output" id="configOutput">{{ output }}</div>
        <button onclick="copyOutput()">Copy Configuration</button>
        </div>

        <div class="card">
        <p class="small">
        Mux and HTTP Payload Proxy settings are stored separately.
        They are not automatically included in VLESS or Trojan share links.
        A generated link does not create a working VPN server account.
        </p>
        </div>

        <script>
        function copyOutput(){
            let text=document.getElementById("configOutput").innerText;
            if(navigator.clipboard){
                navigator.clipboard.writeText(text)
                .then(function(){alert("Copied");})
                .catch(function(){fallbackCopy(text);});
            }else{
                fallbackCopy(text);
            }
        }
        function fallbackCopy(text){
            let area=document.createElement("textarea");
            area.value=text;
            document.body.appendChild(area);
            area.select();
            document.execCommand("copy");
            area.remove();
            alert("Copied");
        }
        </script>
        <a class="btn secondary" href="/records">Back to Records</a>
        """,
        username=row["username"],
        protocol=row["protocol"],
        expires=row["expires"],
        status=row["status"],
        output=output,
        settings=settings
    )


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
        <th>Open</th>
        </tr>
        {% for r in rows %}
        <tr>
        <td>{{ r.username }}</td>
        <td>{{ r.protocol }}</td>
        <td>{{ r.expires }}</td>
        <td>{{ r.status }}</td>
        <td><a href="/account/{{ r.id }}">View / Copy</a></td>
        </tr>
        {% endfor %}
        </table>
        </div>
        """,
        rows=rows
    )


# KILL ACCOUNT

@app.route("/kill", methods=["GET", "POST"])
@login_required
def kill():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        pin = request.form.get("pin", "")
        expected_pin = os.environ.get("ADMIN_PIN", "")

        with database() as db:
            row = execute(
                db,
                "SELECT * FROM accounts WHERE username=?",
                (username,)
            ).fetchone()

            if not row or not verify_password(
                password, row["password_hash"]
            ):
                flash("Customer username or password is incorrect.")
            elif (
                not expected_pin
                or not hmac.compare_digest(pin, expected_pin)
            ):
                flash("Incorrect security PIN.")
            else:
                execute(
                    db,
                    "UPDATE accounts SET status='Killed' WHERE id=?",
                    (row["id"],)
                )
                flash("Account marked as killed. Record preserved.")

        return redirect(url_for("records"))

    return page(
        "Kill Account",
        """
        <div class="card">
        <h2>Kill Customer Account</h2>
        <form method="post">
        <label>Customer username</label>
        <input name="username" required>
        <label>Customer password</label>
        <input name="password" type="password" required>
        <label>Five-digit security PIN</label>
        <input name="pin" type="password" minlength="5" maxlength="5" required>
        <button class="danger">Kill Account</button>
        </form>
        </div>
        """
    )


# CHANGE ADMIN LOGIN

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        pin = request.form.get("pin", "")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        expected = os.environ.get("ADMIN_PIN", "")

        if not expected or not hmac.compare_digest(pin, expected):
            flash("Incorrect security PIN.")
        elif not username or len(password) < 8:
            flash("Enter a username and password of at least 8 characters.")
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
                    if result.rowcount != 1:
                        raise RuntimeError("Admin record not found.")

                session.clear()
                flash("Admin login changed. Sign in again.")
                return redirect(url_for("login"))
            except Exception:
                app.logger.exception("Admin login update failed")
                flash("Could not update login. Username may already exist.")

    return page(
        "Change Login Method",
        """
        <div class="card">
        <h2>Change Admin Login</h2>
        <form method="post">
        <label>Five-digit security PIN</label>
        <input name="pin" type="password" minlength="5" maxlength="5" required>
        <label>New admin username</label>
        <input name="username" required>
        <label>New admin password (minimum 8 characters)</label>
        <input name="password" type="password" minlength="8" required>
        <button>Save Login</button>
        </form>
        </div>
        """
    )


# ==========================================
# PRIME NET VPN - ANDROID CLIENT API
# ==========================================

from client_api import register_client_api

register_client_api(
    app,
    database,
    execute,
    verify_password,
    make_config,
    decode_config
)


# ==========================================
# ERROR PAGE
# ==========================================

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return {
            "error": "API endpoint not found.",
            "code": "not_found"
        }, 404

    return page(
        "Not Found",
        "<div class='card'>Page not found.</div>"
    ), 404


# ==========================================
# START APPLICATION
# ==========================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
