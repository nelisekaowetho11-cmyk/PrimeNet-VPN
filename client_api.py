
import base64
import hashlib
import json
import secrets
from datetime import date, datetime, timezone
from urllib.parse import urlsplit, parse_qs, unquote

from flask import Blueprint, request, jsonify


def register_client_api(app, database, execute, verify_password,
                        make_config, decode_config):

    api = Blueprint("client_api", __name__)

    # Keep the existing database and create only the API tables if missing.
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
        result = {"error": message}
        if code:
            result["code"] = code
        result.update(extra)
        return jsonify(result), status

    def row_value(row, *names, default=None):
        if row is None:
            return default
        try:
            keys = row.keys()
        except Exception:
            keys = ()
        for name in names:
            if name in keys:
                return row[name]
        return default

    def device_headers():
        device_id = request.headers.get("X-Device-Id", "").strip()

        # Stable fallback for older app versions that do not send an ID.
        if not device_id or len(device_id) > 128:
            identity = (
                request.headers.get("User-Agent", "unknown")
                + "|"
                + (request.remote_addr or "")
            )
            device_id = "legacy-" + hashlib.sha256(
                identity.encode()
            ).hexdigest()[:32]

        name = request.headers.get(
            "X-Device-Name", "Unknown device"
        )[:120]
        platform = request.headers.get(
            "X-Device-Platform", "unknown"
        )[:30]
        ip = request.remote_addr or ""

        return device_id, name, platform, ip

    def account_by_id(account_id):
        with database() as db:
            return execute(
                db,
                "SELECT * FROM accounts WHERE id=?",
                (account_id,)
            ).fetchone()

    def account_limit(row):
        value = row_value(
            row, "ip_limit", "device_limit", "accounts_limit",
            "max_devices", default=0
        )
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

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

    def active_device_count(account_id):
        # A device occupies a slot only while it has a live app session.
        with database() as db:
            rows = execute(
                db,
                """
                SELECT DISTINCT device_id
                FROM client_sessions
                WHERE account_id=?
                """,
                (account_id,)
            ).fetchall()
        return len(rows)

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

    def profile_data(row):
        allowed, reason = account_status(row)
        expiry_text = str(row["expires"])[:10]

        try:
            days_left = (
                date.fromisoformat(expiry_text) - date.today()
            ).days
        except Exception:
            days_left = None

        devices = device_list(row["id"])
        limit = account_limit(row)

        return {
            "id": int(row["id"]),
            "name": str(row["username"]),
            "username": str(row["username"]),
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
            "ip_limit": limit,
            "devices_in_use": active_device_count(row["id"]),
            "devices": devices,
            "speed_limit_kbps": 0,
            "note": reason or "",
            "sub_url": "",
            "owner": row_value(row, "creator_name", "owner")
        }

    def decode_vmess(link):
        raw = link.split("://", 1)[1]
        raw += "=" * (-len(raw) % 4)
        data = json.loads(base64.urlsafe_b64decode(raw).decode())

        return {
            "protocol": "vmess",
            "server": data.get("add", ""),
            "port": int(data.get("port") or 0),
            "id": data.get("id", ""),
            "alterId": int(data.get("aid") or 0),
            "cipher": data.get("scy") or "auto",
            "transport": data.get("net") or "tcp",
            "security": "tls" if data.get("tls") else "none",
            "sni": data.get("sni") or data.get("host") or "",
            "path": data.get("path") or "",
            "host": data.get("host") or "",
            "name": data.get("ps") or "PRIME NET"
        }

    def parse_link(link):
        # Prefer the panel's own decoder when it returns useful data.
        try:
            result = decode_config(link)
            if isinstance(result, dict) and result:
                parsed = dict(result)
            else:
                parsed = {}
        except Exception:
            parsed = {}

        if link.startswith("vmess://"):
            try:
                return decode_vmess(link)
            except Exception:
                return parsed

        try:
            uri = urlsplit(link)
            scheme = uri.scheme.lower()
            query = parse_qs(uri.query)

            def q(name, default=""):
                values = query.get(name)
                return values[0] if values else default

            if scheme in ("vless", "trojan"):
                parsed.update({
                    "protocol": scheme,
                    "server": uri.hostname or parsed.get("server", ""),
                    "port": uri.port or parsed.get("port", 0),
                    "name": unquote(uri.fragment) or "PRIME NET",
                    "transport": q("type", parsed.get("transport", "tcp")),
                    "security": q("security", parsed.get("security", "none")),
                    "sni": q("sni", q("serverName", "")),
                    "fp": q("fp", ""),
                    "alpn": q("alpn", ""),
                    "path": q("path", ""),
                    "host": q("host", ""),
                    "serviceName": q("serviceName", ""),
                    "flow": q("flow", ""),
                    "publicKey": q("pbk", ""),
                    "shortId": q("sid", ""),
                    "spiderX": q("spx", "")
                })

                if scheme == "vless":
                    parsed["id"] = unquote(uri.username or "")
                else:
                    parsed["password"] = unquote(uri.username or "")

            elif scheme == "ss":
                # SIP002 format: ss://base64(method:password)@host:port
                user_info = uri.username or ""
                if not user_info and uri.netloc:
                    token = uri.netloc.split("@", 1)[0]
                    token += "=" * (-len(token) % 4)
                    try:
                        user_info = base64.urlsafe_b64decode(
                            token.encode()
                        ).decode()
                    except Exception:
                        pass

                method, separator, password = user_info.partition(":")
                parsed.update({
                    "protocol": "shadowsocks",
                    "server": uri.hostname or "",
                    "port": uri.port or 0,
                    "method": method if separator else "",
                    "password": password if separator else "",
                    "transport": "tcp",
                    "security": "none",
                    "name": unquote(uri.fragment) or "PRIME NET"
                })

        except Exception:
            pass

        return parsed

    def build_outbound(link, parsed):
        protocol = str(parsed.get("protocol", "")).lower()
        address = str(
            parsed.get("server") or parsed.get("address") or ""
        )
        port = int(parsed.get("port") or 0)

        if not address or not 1 <= port <= 65535:
            raise ValueError("The VPN server address or port is missing.")

        transport = str(
            parsed.get("transport") or parsed.get("network") or "tcp"
        ).lower()
        security = str(parsed.get("security") or "none").lower()

        stream = {"network": transport, "security": security}

        if transport == "ws":
            ws = {"path": parsed.get("path") or "/"}
            if parsed.get("host"):
                ws["headers"] = {"Host": parsed["host"]}
            stream["wsSettings"] = ws

        elif transport == "grpc":
            stream["grpcSettings"] = {
                "serviceName": parsed.get("serviceName") or ""
            }

        elif transport == "httpupgrade":
            stream["httpupgradeSettings"] = {
                "path": parsed.get("path") or "/",
                "host": parsed.get("host") or ""
            }

        elif transport not in ("tcp", ""):
            raise ValueError(
                "This transport is not supported by the current app."
            )

        if security == "tls":
            tls = {
                "serverName": parsed.get("sni") or address,
                "allowInsecure": False
            }
            if parsed.get("fp"):
                tls["fingerprint"] = parsed["fp"]
            if parsed.get("alpn"):
                tls["alpn"] = [
                    x.strip() for x in str(parsed["alpn"]).split(",")
                    if x.strip()
                ]
            stream["tlsSettings"] = tls

        elif security == "reality":
            reality = {
                "serverName": parsed.get("sni") or address,
                "publicKey": parsed.get("publicKey") or "",
                "shortId": parsed.get("shortId") or "",
                "spiderX": parsed.get("spiderX") or ""
            }
            if parsed.get("fp"):
                reality["fingerprint"] = parsed["fp"]
            if not reality["publicKey"]:
                raise ValueError("The REALITY public key is missing.")
            stream["realitySettings"] = reality

        elif security not in ("none", ""):
            raise ValueError("Unsupported VPN security setting.")

        if protocol == "vless":
            user_id = str(
                parsed.get("id") or parsed.get("uuid")
                or parsed.get("password") or ""
            )
            if not user_id:
                raise ValueError("The VLESS UUID is missing.")

            user = {
                "id": user_id,
                "encryption": parsed.get("encryption") or "none",
                "level": 0
            }
            if parsed.get("flow"):
                user["flow"] = parsed["flow"]

            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": address,
                        "port": port,
                        "users": [user]
                    }]
                },
                "streamSettings": stream
            }

        elif protocol == "vmess":
            user_id = str(parsed.get("id") or parsed.get("uuid") or "")
            if not user_id:
                raise ValueError("The VMess UUID is missing.")

            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": address,
                        "port": port,
                        "users": [{
                            "id": user_id,
                            "alterId": int(parsed.get("alterId") or 0),
                            "security": parsed.get("cipher") or "auto",
                            "level": 0
                        }]
                    }]
                },
                "streamSettings": stream
            }

        elif protocol == "trojan":
            password = str(parsed.get("password") or "")
            if not password:
                raise ValueError("The Trojan password is missing.")

            outbound = {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": address,
                        "port": port,
                        "password": password,
                        "level": 0
                    }]
                },
                "streamSettings": stream
            }

        elif protocol in ("ss", "shadowsocks"):
            method = str(
                parsed.get("method") or parsed.get("cipher") or ""
            )
            password = str(parsed.get("password") or "")
            if not method or not password:
                raise ValueError(
                    "The Shadowsocks method or password is missing."
                )

            outbound = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": address,
                        "port": port,
                        "method": method,
                        "password": password,
                        "level": 0
                    }]
                },
                "streamSettings": stream
            }

        else:
            raise ValueError("Unsupported VPN protocol: " + protocol)

        return outbound, protocol, address, port, transport, security

    def server_data(row):
        try:
            saved = json.loads(row["config_json"] or "{}")
            link = make_config(saved)

            if not isinstance(link, str) or not link.startswith(
                ("vless://", "vmess://", "trojan://", "ss://")
            ):
                raise ValueError("The saved VPN link is missing or invalid.")

            parsed = parse_link(link)
            outbound, protocol, address, port, transport, security = (
                build_outbound(link, parsed)
            )

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
                "outbound": outbound
            }]

        except Exception:
            app.logger.exception(
                "Could not build client server configuration"
            )
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
                    "DELETE FROM client_sessions WHERE account_id=?",
                    (record["account_id"],)
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
        _, reason = account_status(row)
        servers = server_data(row)

        if not servers and not reason:
            reason = (
                "The VPN configuration is incomplete. "
                "Please contact the administrator."
            )

        return {
            "profile": profile_data(row),
            "servers": servers,
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
            return error("Enter your username and password.")

        with database() as db:
            row = execute(
                db,
                "SELECT * FROM accounts WHERE username=?",
                (username,)
            ).fetchone()

        if not row or not verify_password(
            password, row["password_hash"]
        ):
            return error("Incorrect username or password.", 401)

        allowed, reason = account_status(row)
        if not allowed:
            return error(reason, 403)

        device_id, _, _, _ = device_headers()
        limit = account_limit(row)

        # Existing device sessions do not consume an additional slot.
        with database() as db:
            existing = execute(
                db,
                """
                SELECT token_hash FROM client_sessions
                WHERE account_id=? AND device_id=?
                """,
                (row["id"], device_id)
            ).fetchall()

        if limit > 0 and not existing:
            if active_device_count(row["id"]) >= limit:
                return error(
                    "The device limit has been reached. "
                    "Release another device first.",
                    403,
                    code="DEVICE_LIMIT",
                    devices=device_list(row["id"]),
                    ip_limit=limit
                )

        save_device(row["id"])

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
            return error(
                "Your session has expired. Please log in again.", 401
            )
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

        # Permit account-owner authentication when the device limit
        # prevents a normal app login.
        if not row:
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))

            with database() as db:
                row = execute(
                    db,
                    "SELECT * FROM accounts WHERE username=?",
                    (username,)
                ).fetchone()

            if not row or not verify_password(
                password, row["password_hash"]
            ):
                return error("Incorrect username or password.", 401)

        allowed, reason = account_status(row)
        if not allowed:
            return error(reason, 403)

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
