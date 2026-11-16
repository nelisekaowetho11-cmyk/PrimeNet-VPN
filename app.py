import os, sqlite3, secrets, hashlib, hmac, json, base64
from datetime import datetime, date
from functools import wraps
from contextlib import contextmanager
from urllib.parse import urlsplit, parse_qs, unquote
from flask import Flask, request, redirect, url_for, session, flash, render_template_string, jsonify
from protocol_form import PROTOCOL_FORM

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]


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


def password_hash(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(),
        bytes.fromhex(salt), 200000
    ).hex()
    return salt + ":" + hashed


def verify_password(password, stored):
    try:
        salt, expected = stored.split(":")
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(),
            bytes.fromhex(salt), 200000
        ).hex()
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


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

        admin = execute(
            db, "SELECT id FROM admins LIMIT 1"
        ).fetchone()

        if not admin:
            password = os.environ.get("ADMIN_PASS", "")
            if not password:
                raise RuntimeError("ADMIN_PASS is required.")

            execute(
                db,
                "INSERT INTO admins (username,password) VALUES (?,?)",
                (
                    os.environ.get("ADMIN_USER", "hemlock_protocol"),
                    password_hash(password)
                )
            )


init_db()


# CONFIG READER

def decode_config(link):
    link = link.strip()

    try:
        scheme = urlsplit(link).scheme.lower()

        if scheme == "vmess":
            raw = link[8:]
            raw += "=" * (-len(raw) % 4)
            data = json.loads(base64.urlsafe_b64decode(raw))
            return {
                "protocol": "VMESS",
                "server": data.get("add", ""),
                "port": data.get("port", ""),
                "secret": data.get("id", ""),
                "transport": data.get("net", "tcp"),
                "security": data.get("tls", "none"),
                "name": data.get("ps", "")
            }

        if scheme in ("vless", "trojan"):
            parsed = urlsplit(link)
            query = parse_qs(parsed.query)
            return {
                "protocol": scheme.upper(),
                "server": parsed.hostname or "",
                "port": parsed.port or "",
                "secret": unquote(parsed.username or ""),
                "transport": query.get("type", ["tcp"])[0],
                "security": query.get("security", ["none"])[0],
                "sni": query.get("sni", [""])[0],
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


def config_summary(config):
    if config.get("mode") == "clipboard":
        return config.get("link", "")

    lines = [
        "PRIME NET VPN CONFIGURATION",
        "---------------------------",
        "Protocol: " + str(config.get("protocol", "")),
        "Transport: " + str(config.get("transport", "")),
        "Server: " + str(config.get("server", "")),
        "Port: " + str(config.get("port", "")),
    ]

    for key in (
        "secret", "flow", "method", "alterid",
        "encryption", "security", "sni",
        "path", "service_name", "public_key",
        "short_id", "fingerprint", "alpn",
        "proxy_host", "proxy_port", "payload"
    ):
        if config.get(key):
            lines.append(key.replace("_", " ").title() + ": " + str(config[key]))

    return "\n".join(lines)


# HTML DESIGN - NAVY AND GREEN

BASE = """
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - PRIME NET</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#090d16;color:#edf2ff;font-family:Arial,sans-serif}
header{background:#111a2b;padding:20px;text-align:center;position:relative}
header h1{color:#35d39a;margin:0;font-size:30px}
header p{margin:10px 0 0;color:#d5deed}
.menu{position:absolute;right:18px;top:20px}
.menu button{font-size:25px;padding:3px 12px;background:transparent;color:#35d39a}
.menu-content{display:none;position:absolute;right:0;top:42px;background:#18263b;
min-width:205px;border:1px solid #34445e;border-radius:10px;z-index:10}
.menu-content a{display:block;padding:14px;color:#edf2ff;text-decoration:none}
.menu-content a:hover{background:#243650}
nav{background:#101827;padding:14px;text-align:center}
nav a{color:#35d39a;margin:8px;text-decoration:none;display:inline-block}
main{max-width:900px;margin:22px auto;padding:15px}
.card{background:#131e30;padding:20px;border-radius:15px;margin:15px 0}
h2{margin-top:0}
input,select,textarea{width:100%;padding:14px;margin:8px 0 16px;
background:#091321;color:white;border:1px solid #34445e;border-radius:9px;font-size:16px}
textarea{min-height:120px}
button,.btn{background:#20b987;color:#06140f;padding:13px 18px;
border:0;border-radius:8px;font-weight:bold;cursor:pointer;text-decoration:none;
display:inline-block}
.secondary{background:#1c3045;color:#edf2ff;border:1px solid #34445e}
.danger{background:#9d3947;color:white}
.option{display:block;background:#10283a;border:1px solid #28516a;
border-radius:13px;padding:22px;margin:14px 0;color:#edf2ff;text-decoration:none}
.option strong{display:block;color:#35d39a;font-size:20px;margin-bottom:8px}
table{width:100%;border-collapse:collapse}
td,th{padding:10px;border-bottom:1px solid #34445e;text-align:left}
.small{color:#a9b6ca;font-size:14px}
.output{white-space:pre-wrap;overflow-wrap:anywhere;background:#091321;
border:1px solid #34445e;padding:16px;border-radius:10px}
.actions{display:flex;gap:10px;flex-wrap:wrap}
@media(max-width:600px){main{padding:10px}header h1{font-size:25px}td,th{font-size:13px;padding:6px}}
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
 if(m)m.style.display=m.style.display==="block"?"none":"block";
}
</script>
</body>
</html>
"""


def page(title, body, **data):
    return render_template_string(
        BASE, title=title, body=render_template_string(body, **data)
    )


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


# LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        with database() as db:
            admin = execute(
                db, "SELECT * FROM admins WHERE username=?", (username,)
            ).fetchone()

        if admin and verify_password(password, admin["password"]):
            session.clear()
            session["admin"] = admin["username"]
            return redirect(url_for("dashboard"))

        flash("Incorrect username or password.")

    return page("Admin Login", """
    <div class="card">
    <h2>Admin Login</h2>
    <form method="post">
    <label>Username</label><input name="username" required>
    <label>Password</label><input type="password" name="password" required>
    <button>Login</button>
    </form></div>
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

    active = sum(
        1 for r in rows
        if r["status"] == "Active" and r["expires"] >= date.today().isoformat()
    )
    killed = sum(1 for r in rows if r["status"] == "Killed")

    return page("Dashboard", """
    <div class="card">
    <h2>Welcome, {{ admin }}</h2>
    <p>Total accounts: {{ total }}</p>
    <p>Active accounts: {{ active }}</p>
    <p>Killed accounts: {{ killed }}</p>
    </div>

    <a class="option" href="/clipboard">
    <strong>▣ Copy with Clipboard</strong>
    Paste an existing VLESS, VMess, Trojan or Shadowsocks configuration.
    </a>

    <a class="option" href="/manual">
    <strong>＋ Create Manually</strong>
    Configure your Xray account settings yourself.
    </a>
    """, admin=session["admin"], total=len(rows), active=active, killed=killed)


# CHOOSE CREATION METHOD

@app.route("/create")
@login_required
def create():
    return redirect(url_for("dashboard"))


# MANUAL CREATION

@app.route("/manual", methods=["GET", "POST"])
@login_required
def manual():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        expires = request.form.get("expires", "")
        protocol = request.form.get("protocol", "VLESS").upper()

        if not username or not password:
            flash("Enter the customer's username and password.")
            return redirect(url_for("manual"))

        try:
            date.fromisoformat(expires)
        except ValueError:
            flash("Choose a valid expiry date.")
            return redirect(url_for("manual"))

        if protocol not in ("VLESS", "VMESS", "TROJAN", "SHADOWSOCKS"):
            flash("Unsupported protocol.")
            return redirect(url_for("manual"))

        config = {
            k: v for k, v in request.form.items()
            if k not in ("username", "password", "expires")
        }
        config["mode"] = "manual"

        try:
            with database() as db:
                result = execute(db, """
                    INSERT INTO accounts
                    (username,password_hash,protocol,expires,status,created,config_json)
                    VALUES (?,?,?,?,?,?,?)
                    RETURNING id
                """, (
                    username, password_hash(password), protocol,
                    expires, "Active", datetime.now().isoformat(),
                    json.dumps(config)
                ))
                account_id = result.fetchone()["id"]
        except Exception:
            app.logger.exception("Manual account creation failed")
            flash("Account could not be created. Check whether the username already exists.")
            return redirect(url_for("manual"))

        return redirect(url_for("account", account_id=account_id))

    return page("Create Manually", """
    <div class="card">
    <h2>Create Manually</h2>
    <form method="post" id="accountform">
    <label>Customer username</label><input name="username" required>
    <label>Customer password</label><input name="password" type="password" required>
    <label>Expiry date</label><input name="expires" type="date" required>
    """ + PROTOCOL_FORM + """
    <button>Create Account</button>
    </form></div>
    <a class="btn secondary" href="/">Back</a>
    """)


# CLIPBOARD CREATION

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
            flash("That configuration is not a supported V2Ray/Xray link.")
            return redirect(url_for("clipboard"))

        if not username or not password:
            flash("Enter the customer's username and password.")
            return redirect(url_for("clipboard"))

        try:
            date.fromisoformat(expires)
        except ValueError:
            flash("Choose a valid expiry date.")
            return redirect(url_for("clipboard"))

        config = {
            "mode": "clipboard",
            "link": link,
            "parsed": parsed
        }

        try:
            with database() as db:
                result = execute(db, """
                    INSERT INTO accounts
                    (username,password_hash,protocol,expires,status,created,config_json)
                    VALUES (?,?,?,?,?,?,?)
                    RETURNING id
                """, (
                    username, password_hash(password),
                    parsed["protocol"], expires, "Active",
                    datetime.now().isoformat(), json.dumps(config)
                ))
                account_id = result.fetchone()["id"]
        except Exception:
            app.logger.exception("Clipboard account creation failed")
            flash("Account could not be created. Username may already exist.")
            return redirect(url_for("clipboard"))

        return redirect(url_for("account", account_id=account_id))

    return page("Copy with Clipboard", """
    <div class="card">
    <h2>Copy with Clipboard</h2>
    <form method="post">
    <label>Paste VLESS / VMess / Trojan / Shadowsocks link</label>
    <textarea name="config" required placeholder="Paste your configuration link here"></textarea>
    <label>Customer username</label><input name="username" required>
    <label>Customer password</label><input name="password" type="password" required>
    <label>Expiry date</label><input name="expires" type="date" required>
    <button>Import Account</button>
    </form></div>
    <a class="btn secondary" href="/">Back</a>
    """)


# ACCOUNT OUTPUT

@app.route("/account/<int:account_id>")
@login_required
def account(account_id):
    with database() as db:
        row = execute(
            db, "SELECT * FROM accounts WHERE id=?", (account_id,)
        ).fetchone()

    if not row:
        flash("Account not found.")
        return redirect(url_for("records"))

    config = json.loads(row["config_json"] or "{}")
    output = config_summary(config)

    return page("Account Details", """
    <div class="card">
    <h2>Account Created</h2>
    <p><b>Username:</b> {{ username }}</p>
    <p><b>Protocol:</b> {{ protocol }}</p>
    <p><b>Expiry:</b> {{ expires }}</p>
    <p><b>Status:</b> {{ status }}</p>
    </div>
    <div class="card">
    <h2>Configuration</h2>
    <div class="output" id="configOutput">{{ output }}</div>
    <p class="small">Copy this configuration summary.</p>
    <button onclick="copyOutput()">Copy Configuration</button>
    </div>
    <script>
    function copyOutput(){
      navigator.clipboard.writeText(
        document.getElementById("configOutput").innerText
      );
    }
    </script>
    <a class="btn secondary" href="/records">Back to Records</a>
    """, username=row["username"], protocol=row["protocol"],
    expires=row["expires"], status=row["status"], output=output)


# RECORDS

@app.route("/records")
@login_required
def records():
    with database() as db:
        rows = execute(
            db, "SELECT * FROM accounts ORDER BY id DESC"
        ).fetchall()

    return page("Records", """
    <div class="card">
    <h2>Customer Records</h2>
    <table>
    <tr><th>Username</th><th>Protocol</th><th>Expiry</th><th>Status</th><th>Open</th></tr>
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
    """, rows=rows)


# KILL ACCOUNT - CUSTOMER USERNAME AND PASSWORD

@app.route("/kill", methods=["GET", "POST"])
@login_required
def kill():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with database() as db:
            row = execute(
                db, "SELECT * FROM accounts WHERE username=?", (username,)
            ).fetchone()

            if not row or not verify_password(password, row["password_hash"]):
                flash("Username or password is incorrect.")
            else:
                execute(
                    db, "UPDATE accounts SET status='Killed' WHERE id=?",
                    (row["id"],)
                )
                flash("Account disabled. Its record has been preserved.")

        return redirect(url_for("records"))

    return page("Kill Account", """
    <div class="card">
    <h2>Kill Customer Account</h2>
    <form method="post">
    <label>Customer username</label><input name="username" required>
    <label>Customer password</label><input name="password" type="password" required>
    <button class="danger">Kill Account</button>
    </form></div>
    """)


# CHANGE ADMIN LOGIN - PIN REQUIRED

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        pin = request.form.get("pin", "")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        expected_pin = os.environ.get("ADMIN_PIN", "")

        if not expected_pin or not hmac.compare_digest(pin, expected_pin):
            flash("Incorrect security PIN.")
        elif not username or not password:
            flash("Enter the new username and password.")
        else:
            try:
                with database() as db:
                    result = execute(db, """
                        UPDATE admins SET username=?, password=?
                        WHERE username=?
                    """, (username, password_hash(password), session["admin"]))

                    if not result.rowcount:
                        raise RuntimeError("Admin record not found.")

                session.clear()
                flash("Admin login changed. Please sign in again.")
                return redirect(url_for("login"))
            except Exception:
                app.logger.exception("Admin login update failed")
                flash("Could not update login. The username may already exist.")

    return page("Change Login Method", """
    <div class="card">
    <h2>Change Admin Login</h2>
    <form method="post">
    <label>Five-digit security PIN</label>
    <input name="pin" type="password" minlength="5" maxlength="5" required>
    <label>New admin username</label><input name="username" required>
    <label>New admin password</label><input name="password" type="password" required>
    <button>Save Login</button>
    </form></div>
    """)


@app.errorhandler(404)
def not_found(error):
    return page("Not Found", "<div class='card'>Page not found.</div>"), 404


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
)
