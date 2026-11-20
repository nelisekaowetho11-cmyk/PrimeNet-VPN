
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


# =========================================================
# DATABASE
# =========================================================

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


# =========================================================
# PASSWORD SECURITY
# =========================================================

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
            "sha256",
            password.encode(),
            bytes.fromhex(salt),
            200000
        ).hex()
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# =========================================================
# DATABASE INITIALIZATION AND MIGRATIONS
# =========================================================

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
                    config_json TEXT,
                    creator_name TEXT,
                    ip_limit INTEGER DEFAULT 0,
                    ended TEXT,
                    dead_reason TEXT
                )
            """)

            migrations = [
                "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS password_text TEXT",
                "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS config_json TEXT",
                "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS creator_name TEXT",
                "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS ip_limit INTEGER DEFAULT 0",
                "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS ended TEXT",
                "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS dead_reason TEXT"
            ]

            for sql in migrations:
                db.execute(sql)

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
                    config_json TEXT,
                    creator_name TEXT,
                    ip_limit INTEGER DEFAULT 0,
                    ended TEXT,
                    dead_reason TEXT
                )
            """)

            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(accounts)")
            }

            additions = {
                "password_text": "TEXT",
                "config_json": "TEXT",
                "creator_name": "TEXT",
                "ip_limit": "INTEGER DEFAULT 0",
                "ended": "TEXT",
                "dead_reason": "TEXT"
            }

            for name, definition in additions.items():
                if name not in columns:
                    db.execute(
                        "ALTER TABLE accounts ADD COLUMN "
                        + name + " " + definition
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


# =========================================================
# ACCOUNT HELPERS
# =========================================================

def refresh_expired_accounts():
    today = date.today().isoformat()
    stamp = datetime.now().isoformat()

    with database() as db:
        execute(
            db,
            """
            UPDATE accounts
            SET status='Dead',
                ended=?,
                dead_reason='Time ended'
            WHERE status='Active'
              AND expires < ?
            """,
            (stamp, today)
        )


def get_account(account_id):
    with database() as db:
        return execute(
            db,
            "SELECT * FROM accounts WHERE id=?",
            (account_id,)
        ).fetchone()


def account_limit_value(value):
    try:
        value = int(value or 0)
        return max(0, value)
    except (ValueError, TypeError):
        return 0


def account_message(row):
    limit = account_limit_value(row["ip_limit"])

    accounts_text = (
        "Unlimited" if limit == 0
        else str(limit) + " Accounts"
    )

    creator = row["creator_name"] or "PrimeNet"

    return (
        "✞𝐏𝐫𝐢𝐦𝐞𝐍𝐞𝐭 𝐕𝐏𝐍 𝐋𝐨𝐠𝐢𝐧𝐬✞\n\n"
        "➮𝐀𝐜𝐜𝐨𝐮𝐧𝐭𝐬: " + accounts_text + "\n"
        "➮𝐔𝐬𝐞𝐫𝐧𝐚𝐦𝐞: " + row["username"] + "\n"
        "➮𝐏𝐚𝐬𝐬𝐰𝐨𝐫𝐝: " + (row["password_text"] or "") + "\n\n"
        "𝐂𝐫𝐞𝐚𝐭𝐞𝐝 𝐁𝐲 : " + creator + "\n"
        "> 𝐄𝐧𝐣𝐨𝐲 𝐎𝐮𝐫 𝐏𝐥𝐮𝐠"
    )


def account_status(row):
    if not row:
        return "Dead"

    if str(row["status"]).lower() != "active":
        return "Dead"

    try:
        expiry = date.fromisoformat(str(row["expires"])[:10])
    except Exception:
        return "Dead"

    return "Active" if expiry >= date.today() else "Dead"


# =========================================================
# CONFIGURATION IMPORT
# =========================================================

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
                "transport": data.get("net", "tcp"),
                "security": "tls" if data.get("tls") else "none",
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
                "transport": query.get("type", ["tcp"])[0],
                "security": query.get("security", ["none"])[0],
                "sni": query.get("sni", query.get("serverName", [""]))[0],
                "path": query.get("path", [""])[0],
                "host": query.get("host", [""])[0],
                "flow": query.get("flow", [""])[0],
                "public_key": query.get("pbk", [""])[0],
                "short_id": query.get("sid", [""])[0],
                "fingerprint": query.get("fp", [""])[0],
                "spider_x": query.get("spx", [""])[0],
                "alpn": query.get("alpn", [""])[0],
                "service_name": query.get("serviceName", [""])[0],
                "name": unquote(parsed.fragment)
            }

        if scheme == "ss":
            parsed = urlsplit(link)
            user_info = parsed.username or ""

            if not user_info and "@" in parsed.netloc:
                raw = parsed.netloc.split("@", 1)[0]
                raw += "=" * (-len(raw) % 4)
                user_info = base64.urlsafe_b64decode(
                    raw.encode()
                ).decode()

            method, separator, password = user_info.partition(":")

            return {
                "protocol": "SHADOWSOCKS",
                "server": parsed.hostname or "",
                "port": str(parsed.port or ""),
                "method": method if separator else "",
                "secret": password if separator else "",
                "transport": "tcp",
                "security": "none",
                "link": link,
                "name": unquote(parsed.fragment)
            }

    except Exception:
        app.logger.exception("Configuration import failed")
        return None

    return None


# =========================================================
# CONFIGURATION GENERATOR
# =========================================================

def make_config(config):
    if config.get("mode") == "clipboard":
        return config.get("link", "")

    protocol = str(config.get("protocol", "")).upper()
    server = str(config.get("server", "")).strip()
    port = str(config.get("port", "")).strip()
    secret = str(config.get("secret", "")).strip()

    if not server or not port or not secret:
        return ""

    profile = quote(
        str(config.get("profile_name") or "PRIME-NET"),
        safe=""
    )

    transport = str(config.get("transport", "tcp")).lower()
    security = str(config.get("security", "none")).lower()

    query = {
        "type": transport,
        "security": security
    }

    fields = {
        "sni": "sni",
        "flow": "flow",
        "path": "path",
        "host": "host",
        "public_key": "pbk",
        "short_id": "sid",
        "fingerprint": "fp",
        "spider_x": "spx",
        "alpn": "alpn",
        "service_name": "serviceName",
        "grpc_mode": "mode",
        "header_type": "headerType",
        "seed": "seed"
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

    return ""


# =========================================================
# SAVED SETTINGS
# =========================================================

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
    "method": "Shadowsocks Method"
}


def get_saved_settings(config):
    result = []

    for key, label in SETTING_LABELS.items():
        value = config.get(key)

        if value is None or str(value).strip() == "":
            continue

        result.append({
            "label": label,
            "value": str(value)
        })

    return result


# =========================================================
# SHARED HTML DESIGN
# =========================================================

BASE = """
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} - PRIME NET</title>
<style>
*{box-sizing:border-box}
body{
 margin:0;background:#090d16;color:#edf2ff;
 font-family:Arial,sans-serif;padding-bottom:90px
}
header{
 background:#111a2b;padding:20px;text-align:center;
 position:relative
}
header h1{color:#35d39a;margin:0;font-size:27px}
header p{margin:8px 0 0;color:#c5d2e5}
.menu{position:absolute;right:14px;top:12px}
.menu button{
 font-size:25px;padding:5px 12px;
 background:transparent;color:#35d39a
}
.menu-content{
 display:none;position:absolute;right:0;top:42px;
 background:#18263b;min-width:205px;
 border:1px solid #34445e;border-radius:10px;z-index:10
}
.menu-content a{
 display:block;padding:14px;color:#edf2ff;
 text-decoration:none;border-bottom:1px solid #34445e
}
main{max-width:900px;margin:18px auto;padding:12px}
.card{
 background:#131e30;padding:19px;
 border-radius:15px;margin:13px 0;
 border:1px solid #202f45
}
.card h2{margin-top:0;color:#35d39a}
input,select,textarea{
 width:100%;padding:13px;margin:8px 0 15px;
 background:#091321;color:white;
 border:1px solid #34445e;border-radius:9px;
 font-size:16px
}
textarea{min-height:110px}
button,.btn{
 background:#20b987;color:#06140f;
 padding:12px 17px;border:0;border-radius:8px;
 font-weight:bold;cursor:pointer;
 text-decoration:none;display:inline-block
}
.secondary{background:#1c3045;color:#edf2ff}
.danger{background:#a53d4b;color:white}
.option{
 display:block;background:#10283a;
 border:1px solid #28516a;border-radius:13px;
 padding:20px;margin:13px 0;color:#edf2ff;
 text-decoration:none
}
.option strong{
 display:block;color:#35d39a;
 font-size:18px;margin-bottom:7px
}
table{width:100%;border-collapse:collapse}
td,th{
 padding:11px;border-bottom:1px solid #34445e;
 text-align:left;overflow-wrap:anywhere
}
.output{
 white-space:pre-wrap;overflow-wrap:anywhere;
 background:#091321;border:1px solid #34445e;
 padding:15px;border-radius:10px;margin:12px 0
}
.small{color:#a9b6ca;font-size:13px}
.green{color:#35d39a}
.red{color:#ff6d79}
.setting-row{
 padding:10px 0;border-bottom:1px solid #34445e;
 overflow-wrap:anywhere
}
.setting-row strong{color:#35d39a}
.bottom-nav{
 position:fixed;bottom:0;left:0;right:0;
 z-index:20;background:#101827;
 border-top:1px solid #34445e;
 display:flex;justify-content:space-around;
 padding:9px 4px calc(9px + env(safe-area-inset-bottom))
}
.bottom-nav a{
 flex:1;text-align:center;color:#9eacc1;
 text-decoration:none;font-size:12px;padding:5px 2px
}
.bottom-nav a span{
 display:block;font-size:23px;margin-bottom:4px
}
.bottom-nav a.active{color:#35d39a}
.flash{
 background:#26364b;padding:13px;
 border-radius:9px;margin:10px 0
}
@media(max-width:600px){
 main{padding:9px}
 header h1{font-size:23px}
 table{font-size:13px}
 td,th{padding:8px}
}
</style>
</head>
<body>
<header>
<h1>✞ PRIME NET ✞</h1>
<p>Private VPN Administration</p>
{% if session.get('admin') %}
<div class="menu">
<button type="button" onclick="toggleMenu()">⋮</button>
<div class="menu-content" id="menuContent">
<a href="/kill">Kill Accounts</a>
<a href="/settings">Change Login Method</a>
<a href="/logout">Logout</a>
</div>
</div>
{% endif %}
</header>

<main>
{% for message in get_flashed_messages() %}
<div class="flash">{{ message }}</div>
{% endfor %}
{{ body|safe }}
</main>

{% if session.get('admin') %}
<nav class="bottom-nav">
<a href="/create" class="{{ 'active' if active_tab == 'create' else '' }}">
<span>＋</span>Create
</a>
<a href="/active" class="{{ 'active' if active_tab == 'active' else '' }}">
<span>▣</span>Active
</a>
<a href="/dead" class="{{ 'active' if active_tab == 'dead' else '' }}">
<span>◉</span>Dead
</a>
</nav>
{% endif %}

<script>
function toggleMenu(){
 const menu=document.getElementById("menuContent");
 if(menu){
  menu.style.display=menu.style.display==="block"?"none":"block";
 }
}
function copyText(text, statusId){
 const status=document.getElementById(statusId);
 function fallback(){
  const area=document.createElement("textarea");
  area.value=text;
  document.body.appendChild(area);
  area.select();
  const ok=document.execCommand("copy");
  area.remove();
  if(status) status.innerText=ok?"Copied successfully.":"Copy failed.";
 }
 if(navigator.clipboard && window.isSecureContext){
  navigator.clipboard.writeText(text)
   .then(()=>{if(status)status.innerText="Copied successfully.";})
   .catch(fallback);
 }else{
  fallback();
 }
}
</script>
</body>
</html>
"""


def page(title, body, active_tab="", **data):
    inner = render_template_string(body, **data)

    return render_template_string(
        BASE,
        title=title,
        body=inner,
        active_tab=active_tab
    )


# =========================================================
# LOGIN PROTECTION
# =========================================================

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


# =========================================================
# ADMIN LOGIN
# =========================================================

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
            request.form.get("password", ""),
            admin["password"]
        ):
            session.clear()
            session["admin"] = admin["username"]
            return redirect(url_for("create"))

        flash("Incorrect username or password.")

    return page(
        "Admin Login",
        """
        <div class="card">
        <h2>Admin Login</h2>
        <form method="post">
        <label>Username</label>
        <input name="username" autocomplete="username" required>
        <label>Password</label>
        <input name="password" type="password"
        autocomplete="current-password" required>
        <button>Login</button>
        </form>
        </div>
        """
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================================================
# HOME / CREATE
# =========================================================

@app.route("/")
@login_required
def dashboard():
    return redirect(url_for("create"))


@app.route("/create")
@login_required
def create():
    refresh_expired_accounts()

    return page(
        "Create",
        """
        <div class="card">
        <h2>Create Customer Account</h2>
        <p>Choose how you want to add the VPN configuration.</p>

        <a class="option" href="/clipboard">
        <strong>▣ Paste Clipboard</strong>
        Paste an existing VLESS, VMess, Trojan or Shadowsocks link.
        </a>

        <a class="option" href="/manual">
        <strong>＋ Set Manually</strong>
        Enter the server configuration yourself.
        </a>
        </div>
        """,
        active_tab="create"
    )


# =========================================================
# SAVE ACCOUNT
# =========================================================

def save_account(
    username, password, expires, protocol,
    config, creator_name, ip_limit
):
    with database() as db:
        result = execute(
            db,
            """
            INSERT INTO accounts
            (
                username,password_hash,password_text,
                protocol,expires,status,created,
                config_json,creator_name,ip_limit
            )
            VALUES (?,?,?,?,?,?,?,?,?,?)
            RETURNING id
            """,
            (
                username,
                password_hash(password),
                password,
                protocol,
                expires,
                "Active",
                datetime.now().isoformat(),
                json.dumps(config),
                creator_name,
                ip_limit
            )
        )

        return result.fetchone()["id"]


def account_created(account_id):
    row = get_account(account_id)
    message = account_message(row)

    return page(
        "Account Created",
        """
        <div class="card">
        <h2 class="green">Account Created Successfully</h2>
        <p>Customer account saved.</p>

        <div class="output" id="customerMessage">{{ message }}</div>

        <button onclick="copyText(
            document.getElementById('customerMessage').innerText,
            'copyStatus'
        )">Copy Login Details</button>

        <p id="copyStatus" class="small"></p>

        <a class="btn secondary" href="/account/{{ account_id }}">
        View Account
        </a>
        <a class="btn secondary" href="/create">Create Another</a>
        </div>
        """,
        active_tab="create",
        account_id=account_id,
        message=message
    )


# =========================================================
# COMMON ACCOUNT FORM VALIDATION
# =========================================================

def validate_customer_fields():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    expires = request.form.get("expires", "")
    creator_name = request.form.get("creator_name", "").strip()

    raw_limit = request.form.get("ip_limit", "0").strip()

    if not username:
        return None, "Enter a customer username."

    if len(password) < 8:
        return None, "Customer password must be at least 8 characters."

    if not creator_name:
        return None, "Enter the Creator Name."

    try:
        expiry = date.fromisoformat(expires)
        if expiry < date.today():
            raise ValueError()
    except Exception:
        return None, "Choose a valid expiry date."

    try:
        ip_limit = int(raw_limit or "0")
        if ip_limit < 0:
            raise ValueError()
    except ValueError:
        return None, "Device limit must be zero or a positive number."

    return {
        "username": username,
        "password": password,
        "expires": expires,
        "creator_name": creator_name,
        "ip_limit": ip_limit
    }, None


# =========================================================
# MANUAL ACCOUNT
# =========================================================

@app.route("/manual", methods=["GET", "POST"])
@login_required
def manual():
    if request.method == "POST":
        fields, problem = validate_customer_fields()

        if problem:
            flash(problem)
            return redirect(url_for("manual"))

        protocol = request.form.get("protocol", "").upper()

        if protocol not in (
            "VLESS", "VMESS", "TROJAN", "SHADOWSOCKS"
        ):
            flash("Select a supported protocol.")
            return redirect(url_for("manual"))

        config = {
            key: value.strip()
            for key, value in request.form.items()
            if key not in (
                "username", "password", "expires",
                "creator_name", "ip_limit"
            )
        }

        config["mode"] = "manual"
        config["protocol"] = protocol

        if not config.get("server") or not config.get("port"):
            flash("Server and port are required.")
            return redirect(url_for("manual"))

        try:
            port = int(config["port"])
            if not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            flash("Enter a valid server port.")
            return redirect(url_for("manual"))

        if not config.get("secret"):
            flash("Enter the protocol credential.")
            return redirect(url_for("manual"))

        # Shadowsocks uses its own TCP connection settings.
        if protocol != "SHADOWSOCKS":
            if not config.get("transport"):
                flash("Choose a transport.")
                return redirect(url_for("manual"))

            if not config.get("security"):
                flash("Choose a security setting.")
                return redirect(url_for("manual"))

        try:
            account_id = save_account(
                fields["username"],
                fields["password"],
                fields["expires"],
                protocol,
                config,
                fields["creator_name"],
                fields["ip_limit"]
            )
        except Exception:
            app.logger.exception("Manual account creation failed")
            flash("Could not create account. Check whether username already exists.")
            return redirect(url_for("manual"))

        return account_created(account_id)

    return page(
        "Set Manually",
        """
        <div class="card">
        <h2>Set Manually</h2>

        <form method="post" id="accountform">

        <label>Customer Username</label>
        <input name="username" required>

        <label>Customer Password</label>
        <input name="password" type="password" minlength="8" required>

        <label>Expiry Date</label>
        <input name="expires" type="date"
        min="{{ today }}" required>

        <label>Accounts / Device Limit</label>
        <input name="ip_limit" type="number" min="0" value="0" required>
        <p class="small">Use 0 for unlimited devices.</p>

        <label>Creator Name</label>
        <input name="creator_name" required>

        """ + PROTOCOL_FORM + """

        <button type="submit">Create Account</button>
        </form>
        </div>
        <a class="btn secondary" href="/create">Back</a>
        """,
        active_tab="create",
        today=date.today().isoformat()
    )


# =========================================================
# CLIPBOARD IMPORT
# =========================================================

@app.route("/clipboard", methods=["GET", "POST"])
@login_required
def clipboard():
    if request.method == "POST":
        fields, problem = validate_customer_fields()

        if problem:
            flash(problem)
            return redirect(url_for("clipboard"))

        link = request.form.get("config", "").strip()
        parsed = decode_config(link)

        if not parsed:
            flash("Unsupported configuration link.")
            return redirect(url_for("clipboard"))

        config = {
            "mode": "clipboard",
            "link": link,
            "parsed": parsed
        }

        try:
            account_id = save_account(
                fields["username"],
                fields["password"],
                fields["expires"],
                parsed.get("protocol", "UNKNOWN"),
                config,
                fields["creator_name"],
                fields["ip_limit"]
            )
        except Exception:
            app.logger.exception("Clipboard account creation failed")
            flash("Could not create account. Check whether username already exists.")
            return redirect(url_for("clipboard"))

        return account_created(account_id)

    return page(
        "Paste Clipboard",
        """
        <div class="card">
        <h2>Paste Clipboard</h2>

        <form method="post">

        <label>VPN Configuration Link</label>
        <textarea name="config"
        placeholder="Paste your VPN link here..."
        required></textarea>

        <label>Customer Username</label>
        <input name="username" required>

        <label>Customer Password</label>
        <input name="password" type="password" minlength="8" required>

        <label>Expiry Date</label>
        <input name="expires" type="date"
        min="{{ today }}" required>

        <label>Accounts / Device Limit</label>
        <input name="ip_limit" type="number" min="0" value="0" required>
        <p class="small">Use 0 for unlimited devices.</p>

        <label>Creator Name</label>
        <input name="creator_name" required>

        <button type="submit">Import Account</button>
        </form>
        </div>
        <a class="btn secondary" href="/create">Back</a>
        """,
        active_tab="create",
        today=date.today().isoformat()
    )


# =========================================================
# ACCOUNT DETAILS
# =========================================================

@app.route("/account/<int:account_id>")
@login_required
def account(account_id):
    refresh_expired_accounts()
    row = get_account(account_id)

    if not row:
        flash("Account not found.")
        return redirect(url_for("active_accounts"))

    config = json.loads(row["config_json"] or "{}")
    output = make_config(config)
    settings = get_saved_settings(config)
    message = account_message(row)

    return page(
        "Account Details",
        """
        <div class="card">
        <h2>Account Details</h2>
        <p><b>Username:</b> {{ row.username }}</p>
        <p><b>Password:</b> {{ row.password_text or 'Unavailable' }}</p>
        <p><b>Protocol:</b> {{ row.protocol }}</p>
        <p><b>Created:</b> {{ row.created }}</p>
        <p><b>Expiry:</b> {{ row.expires }}</p>
        <p><b>Creator:</b> {{ row.creator_name or 'Not recorded' }}</p>
        <p><b>Device Limit:</b>
        {{ 'Unlimited' if not row.ip_limit else row.ip_limit }}</p>
        <p><b>Status:</b> {{ row.status }}</p>
        {% if row.dead_reason %}
        <p><b>Reason:</b> {{ row.dead_reason }}</p>
        {% endif %}
        </div>

        <div class="card">
        <h2>Customer Login Message</h2>
        <div class="output" id="loginMessage">{{ message }}</div>
        <button onclick="copyText(
            document.getElementById('loginMessage').innerText,
            'messageStatus'
        )">Copy Login Message</button>
        <p id="messageStatus" class="small"></p>
        </div>

        <div class="card">
        <h2>VPN Configuration</h2>
        <div class="output" id="configOutput">{{ output }}</div>
        <button onclick="copyText(
            document.getElementById('configOutput').innerText,
            'configStatus'
        )">Copy Configuration</button>
        <p id="configStatus" class="small"></p>
        </div>

        <div class="card">
        <h2>Saved Configuration Settings</h2>
        {% if settings %}
        {% for item in settings %}
        <div class="setting-row">
        <strong>{{ item.label }}:</strong> {{ item.value }}
        </div>
        {% endfor %}
        {% else %}
        <p class="small">No additional settings recorded.</p>
        {% endif %}
        </div>

        <a class="btn secondary" href="/active">Active Accounts</a>
        <a class="btn secondary" href="/dead">Dead Accounts</a>
        """,
        row=row,
        output=output,
        settings=settings,
        message=message
    )


# =========================================================
# ACTIVE ACCOUNTS
# =========================================================

@app.route("/active")
@login_required
def active_accounts():
    refresh_expired_accounts()

    with database() as db:
        rows = execute(
            db,
            """
            SELECT * FROM accounts
            WHERE status='Active'
            ORDER BY id DESC
            """
        ).fetchall()

    return page(
        "Active Accounts",
        """
        <div class="card">
        <h2 class="green">Active Accounts</h2>
        <p class="small">Accounts that have not expired or been killed.</p>

        {% if rows %}
        {% for row in rows %}
        <div class="card">
        <h3 class="green">{{ row.username }}</h3>
        <p><b>Password:</b> {{ row.password_text or 'Unavailable' }}</p>
        <p><b>Expiry:</b> {{ row.expires }}</p>
        <p><b>Creator:</b> {{ row.creator_name or 'Not recorded' }}</p>
        <p><b>Device Limit:</b>
        {{ 'Unlimited' if not row.ip_limit else row.ip_limit }}</p>
        <p><b>Protocol:</b> {{ row.protocol }}</p>

        <a class="btn" href="/account/{{ row.id }}">View / Copy</a>
        </div>
        {% endfor %}
        {% else %}
        <p>No active accounts.</p>
        {% endif %}
        </div>
        """,
        active_tab="active",
        rows=rows
    )


# =========================================================
# DEAD ACCOUNTS
# =========================================================

@app.route("/dead")
@login_required
def dead_accounts():
    refresh_expired_accounts()

    with database() as db:
        rows = execute(
            db,
            """
            SELECT * FROM accounts
            WHERE status IN ('Dead','Killed')
            ORDER BY id DESC
            """
        ).fetchall()

    return page(
        "Dead Accounts",
        """
        <div class="card">
        <h2 class="red">Dead Accounts</h2>

        {% if rows %}
        {% for row in rows %}
        <div class="card">
        <h3 class="red">{{ row.username }}</h3>
        <p><b>Password:</b> {{ row.password_text or 'Unavailable' }}</p>
        <p><b>Protocol:</b> {{ row.protocol }}</p>
        <p><b>Expiry:</b> {{ row.expires }}</p>
        <p><b>Creator:</b> {{ row.creator_name or 'Not recorded' }}</p>
        <p><b>Ended:</b> {{ row.ended or 'Not recorded' }}</p>
        <p><b>Reason:</b> {{ row.dead_reason or row.status }}</p>
        <a class="btn secondary" href="/account/{{ row.id }}">View Record</a>
        </div>
        {% endfor %}
        {% else %}
        <p>No dead accounts.</p>
        {% endif %}
        </div>
        """,
        active_tab="dead",
        rows=rows
    )


# Keep the old records URL working.
@app.route("/records")
@login_required
def records():
    return redirect(url_for("active_accounts"))


# =========================================================
# KILL ACCOUNT
# =========================================================

@app.route("/kill", methods=["GET", "POST"])
@login_required
def kill():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

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
            else:
                stamp = datetime.now().isoformat()

                execute(
                    db,
                    """
                    UPDATE accounts
                    SET status='Killed',
                        ended=?,
                        dead_reason='Killed'
                    WHERE id=?
                    """,
                    (stamp, row["id"])
                )

                # Revoke every session belonging to this account.
                try:
                    execute(
                        db,
                        "DELETE FROM client_sessions WHERE account_id=?",
                        (row["id"],)
                    )
                except Exception:
                    app.logger.exception(
                        "Could not revoke client sessions"
                    )

                flash("Account killed. Its record has been preserved.")

        return redirect(url_for("dead_accounts"))

    return page(
        "Kill Account",
        """
        <div class="card">
        <h2 class="red">Kill Customer Account</h2>
        <p>Enter the customer's username and password.</p>

        <form method="post">
        <label>Customer Username</label>
        <input name="username" required>

        <label>Customer Password</label>
        <input name="password" type="password" required>

        <button class="danger">Kill Account</button>
        </form>
        </div>
        """
    )


# =========================================================
# CHANGE ADMIN LOGIN
# =========================================================

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
                        SET username=?,password=?
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
                flash(
                    "Could not update login. "
                    "The username may already exist."
                )

    return page(
        "Change Login Method",
        """
        <div class="card">
        <h2>Change Admin Login</h2>

        <form method="post">
        <label>Existing Five-Digit Security PIN</label>
        <input name="pin" type="password"
        minlength="5" maxlength="5" required>

        <label>New Admin Username</label>
        <input name="username" required>

        <label>New Admin Password</label>
        <input name="password" type="password"
        minlength="8" required>

        <button>Save New Login</button>
        </form>
        </div>
        """
    )


# =========================================================
# ANDROID CLIENT API
# =========================================================

from client_api import register_client_api

register_client_api(
    app,
    database,
    execute,
    verify_password,
    make_config,
    decode_config
)


# =========================================================
# ERROR HANDLING
# =========================================================

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


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("Internal server error")

    if request.path.startswith("/api/"):
        return {
            "error": "Internal server error.",
            "code": "server_error"
        }, 500

    return page(
        "Error",
        "<div class='card'>Something went wrong. Check the Render logs.</div>"
    ), 500


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
