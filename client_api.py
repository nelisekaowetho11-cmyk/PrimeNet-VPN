
import hashlib
import hmac
import json
import secrets
from datetime import date, datetime, timezone
from flask import Blueprint, request, jsonify


def register_client_api(app, database, execute, verify_password,
                        make_config, decode_config):

    api = Blueprint("client_api", __name__)

    # API session and device tables
    with database() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS client_sessions (
                token_hash TEXT PRIMARY KEY,
                account_id BIGINT NOT NULL,
                device_id TEXT NOT NULL,
                created TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS client_devices (
                account_id BIGINT NOT NULL,
                device_id TEXT NOT NULL,
                name TEXT NOT NULL,
                platform TEXT NOT NULL,
                ip TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (account_id, device_id)
            )
        """)

    def now():
        return datetime.now(timezone.utc).isoformat()

    def error(message, status=400, code=None, **extra):
        data = {"error": message}
        if code:
            data["code"] = code
        data.update(extra)
        return jsonify(data), status

    def device_headers():
        device_id = request.headers.get("X-Device-Id", "").strip()
        if not device_id or len(device_id) > 128:
            device_id = "unknown-" + secrets.token_hex(8)

        name = request.headers.get("X-Device-Name", "Unknown device")[:120]
        platform = request.headers.get(
            "X-Device-Platform", "unknown"
        )[:30]

        ip = request.remote_addr or ""
        return device_id, name, platform, ip

    def account_by_id(account_id):
        with database() as db:
            return execute(
                db, "SELECT * FROM accounts WHERE id=?", (account_id,)
            ).fetchone()

    def account_status(row):
        if not row:
            return False, "Account not found."
        if str(row["status"]).lower() != "active":
            return False, "This account is not active."
        try:
            expiry = date.fromisoformat(str(row["expires"])[:10])
        except Exception:
            return False, "The account expiry date is invalid."
        if expiry < date.today():
            return False, "This account has expired."
        return True, None

    def save_device(account_id):
        device_id, name, platform, ip = device_headers()
        stamp = now()

        with database() as db:
            execute(
                db,
                """
                INSERT INTO client_devices
                (account_id,device_id,name,platform,ip,last_seen)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(account_id,device_id) DO UPDATE SET
                    name=excluded.name,
                    platform=excluded.platform,
                    ip=excluded.ip,
                    last_seen=excluded.last_seen
                """,
                (account_id, device_id, name, platform, ip, stamp)
            )
        return device_id

    def device_list(account_id):
        with database() as db:
            rows = execute(
                db,
                """
                SELECT device_id,name,platform,ip,last_seen
                FROM client_devices
                WHERE account_id=?
                ORDER BY last_seen DESC
                """,
                (account_id,)
            ).fetchall()

        return [{
            "id": r["device_id"],
            "name": r["name"],
            "platform": r["platform"],
            "ip": r["ip"],
            "last_seen": r["last_seen"]
        } for r in rows]

    def profile_data(row):
        allowed, reason = account_status(row)
        expiry_text = str(row["expires"])[:10]

        try:
            days_left = (date.fromisoformat(expiry_text) - date.today()).days
        except Exception:
            days_left = None

        devices = device_list(row["id"])

        return {
            "id": int(row["id"]),
            "name": row["username"],
            "username": row["username"],
            "email": "",
            "status": str(row["status"]).lower(),
            "can_connect": allowed,
            "unlimited": True,
            "traffic_limit_gb": 0,
            "traffic_used_gb": 0,
            "traffic_left_gb": None,
            "traffic_pct": 0,
            "expires": expiry_text,
            "days_left": days_left,
            "ip_limit": 0,
            "devices_in_use": len(devices),
            "devices": devices,
            "speed_limit_kbps": 0,
            "note": reason or "",
            "sub_url": "",
            "owner": None
        }

    def server_data(row):
        try:
            saved = json.loads(row["config_json"] or "{}")
            link = make_config(saved)
            if not link or not link.startswith(
                ("vless://", "vmess://", "trojan://", "ss://")
            ):
                return []

            parsed = decode_config(link)
            if not parsed:
                return []

            protocol = str(parsed.get("protocol", row["protocol"])).lower()
            address = str(parsed.get("server", ""))
            port = int(parsed.get("port") or 0)

            if not address or not 1 <= port <= 65535:
                return []

            transport = str(parsed.get("transport") or "tcp").lower()
            security = str(parsed.get("security") or "none").lower()
            name = str(parsed.get("name") or "PRIME NET")

            return [{
                "id": int(row["id"]),
                "uid": "primenet#" + str(row["id"]),
                "source_id": "primenet",
                "tag": name,
                "name": name,
                "region": "",
                "country": "",
                "protocol": protocol,
                "transport": transport,
                "network": transport,
                "security": security,
                "address": address,
                "port": port,
                "link": link,
                "outbound": {}
            }]
        except Exception:
            app.logger.exception("Could not build client server configuration")
            return []

    def session_token():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return header[7:].strip()

    def authenticated():
        token = session_token()
        if not token:
            return None, None

        token_hash = hashlib.sha256(token.encode()).hexdigest()

        with database() as db:
            record = execute(
                db,
                "SELECT * FROM client_sessions WHERE token_hash=?",
                (token_hash,)
            ).fetchone()

        if not record:
            return None, None

        row = account_by_id(record["account_id"])
        allowed, _ = account_status(row)
        if not allowed:
            with database() as db:
                execute(
                    db,
                    "DELETE FROM client_sessions WHERE token_hash=?",
                    (token_hash,)
                )
            return None, None

        current_device, _, _, _ = device_headers()
        if current_device != record["device_id"]:
            return None, None

        with database() as db:
            execute(
                db,
                "UPDATE client_sessions SET last_seen=? WHERE token_hash=?",
                (now(), token_hash)
            )

        save_device(row["id"])
        return row, token_hash

    def session_payload(row):
        allowed, reason = account_status(row)
        return {
            "profile": profile_data(row),
            "servers": server_data(row),
            "brand": "PRIME NET VPN",
            "blocked_reason": reason,
            "you": {
                "ip": request.remote_addr or "",
                "country": ""
            }
        }

    @api.get("/api/client/ping")
    def ping():
        return jsonify({"ok": True, "panel": "PRIME NET VPN"})

    @api.post("/api/client/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        if not username or not password:
            return error("Enter your username and password.", 400)

        with database() as db:
            row = execute(
                db,
                "SELECT * FROM accounts WHERE username=?",
                (username,)
            ).fetchone()

        if not row or not verify_password(password, row["password_hash"]):
            return error("Incorrect username or password.", 401)

        allowed, reason = account_status(row)
        if not allowed:
            return error(reason, 403)

        device_id = save_device(row["id"])
        token = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        with database() as db:
            execute(
                db,
                """
                INSERT INTO client_sessions
                (token_hash,account_id,device_id,created,last_seen)
                VALUES (?,?,?,?,?)
                """,
                (token_hash, row["id"], device_id, now(), now())
            )

        result = session_payload(row)
        result["token"] = token
        return jsonify(result)

    @api.get("/api/client/session")
    def get_session():
        row, _ = authenticated()
        if not row:
            return error("Your session has expired. Please log in again.", 401)
        return jsonify(session_payload(row))

    @api.get("/api/client/profile")
    def get_profile():
        row, _ = authenticated()
        if not row:
            return error("Please log in again.", 401)
        return jsonify({"profile": profile_data(row)})

    @api.get("/api/client/update")
    def update():
        return jsonify({
            "available": False,
            "mandatory": False,
            "version": request.args.get("version", ""),
            "url": "",
            "notes": ""
        })

    @api.post("/api/client/logout")
    def client_logout():
        token = session_token()
        if token:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            with database() as db:
                execute(
                    db,
                    "DELETE FROM client_sessions WHERE token_hash=?",
                    (token_hash,)
                )
        return jsonify({"ok": True})

    @api.post("/api/client/devices/release")
    def release_device():
        data = request.get_json(silent=True) or {}
        target_id = str(data.get("id", "")).strip()
        if not target_id:
            return error("Device ID is required.")

        row, _ = authenticated()

        # Allow release when login was refused, but require the account
        # credentials before allowing a device to be removed.
        if not row:
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))
            with database() as db:
                row = execute(
                    db,
                    "SELECT * FROM accounts WHERE username=?",
                    (username,)
                ).fetchone()
            if not row or not verify_password(password, row["password_hash"]):
                return error("Incorrect username or password.", 401)

        own_id, _, _, _ = device_headers()
        if target_id == own_id:
            return error("You cannot release this device.")

        with database() as db:
            execute(
                db,
                """
                DELETE FROM client_devices
                WHERE account_id=? AND device_id=?
                """,
                (row["id"], target_id)
            )
            execute(
                db,
                """
                DELETE FROM client_sessions
                WHERE account_id=? AND device_id=?
                """,
                (row["id"], target_id)
            )

        return jsonify({"devices": device_list(row["id"])})

    @api.post("/api/client/heartbeat")
    def heartbeat():
        row, _ = authenticated()
        if not row:
            return error("Please log in again.", 401)

        allowed, reason = account_status(row)
        return jsonify({
            "profile": profile_data(row),
            "can_connect": allowed,
            "blocked_reason": reason
        })

    app.register_blueprint(api)
