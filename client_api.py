
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
        device_id = request.headers.get(
            "X-Device-Id", ""
        ).strip()

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
            row,
            "ip_limit",
            "device_limit",
            "accounts_limit",
            "max_devices",
            default=0
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
            expiry = date.fromisoformat(
                str(row["expires"])[:10]
            )
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

    def parse_bool(value, field_name):
        if isinstance(value, bool):
            return value

        text = str(value or "").strip().lower()

        if text in ("true", "1", "yes", "on"):
            return True

        if text in ("false", "0", "no", "off", ""):
            return False

        raise ValueError("Invalid " + field_name + " setting.")

    def get_client_options(saved):
        proxy = str(saved.get("proxy") or "").strip()
        payload = str(saved.get("payload") or "")

        mux = parse_bool(saved.get("mux", False), "Mux")

        proxy_port = None

        if proxy:
            if (
                "://" in proxy
                or any(char.isspace() for char in proxy)
                or "/" in proxy
            ):
                raise ValueError("Invalid proxy address.")

            try:
                proxy_port = int(saved.get("proxy_port") or 8080)
            except (TypeError, ValueError):
                raise ValueError("Invalid proxy port.")

            if not 1 <= proxy_port <= 65535:
                raise ValueError("Proxy port must be between 1 and 65535.")

        return {
            "proxy": proxy,
            "proxy_port": proxy_port,
            "payload": payload,
            "mux": mux
        }

    def decode_base64(value):
        value = str(value or "").strip()
        value += "=" * (-len(value) % 4)

        try:
            return base64.urlsafe_b64decode(
                value.encode()
            ).decode("utf-8")
        except Exception:
            return ""

    def decode_vmess(link):
        raw = link.split("://", 1)[1]
        raw = raw.split("#", 1)[0]
        raw = raw.split("?", 1)[0]

        decoded = decode_base64(raw)

        if not decoded:
            raise ValueError("Invalid VMess configuration.")

        data = json.loads(decoded)

        if not isinstance(data, dict):
            raise ValueError("Invalid VMess configuration.")

        tls_value = str(data.get("tls") or "").lower()
        security = "tls" if tls_value in (
            "tls", "true", "1", "yes"
        ) else "none"

        return {
            "protocol": "vmess",
            "server": data.get("add", ""),
            "port": int(data.get("port") or 0),
            "id": data.get("id", ""),
            "alterId": int(data.get("aid") or 0),
            "cipher": data.get("scy") or "auto",
            "transport": data.get("net") or "tcp",
            "security": security,
            "sni": (
                data.get("sni")
                or data.get("servername")
                or data.get("host")
                or ""
            ),
            "fp": data.get("fp") or "",
            "alpn": data.get("alpn") or "",
            "path": data.get("path") or "",
            "host": data.get("host") or "",
            "name": data.get("ps") or "PRIME NET"
        }

    def parse_link(link):
        if not isinstance(link, str):
            raise ValueError("VPN link must be text.")

        link = link.strip()

        if not link:
            raise ValueError("VPN configuration link is empty.")

        parsed = {}

        try:
            result = decode_config(link)

            if isinstance(result, dict):
                parsed.update(result)
        except Exception:
            pass

        if link.lower().startswith("vmess://"):
            parsed.update(decode_vmess(link))
            return parsed

        uri = urlsplit(link)
        scheme = uri.scheme.lower()
        query = parse_qs(uri.query, keep_blank_values=True)

        def q(name, default=""):
            values = query.get(name)
            return values[0] if values else default

        if scheme in ("vless", "trojan"):
            parsed.update({
                "protocol": scheme,
                "server": uri.hostname or parsed.get("server", ""),
                "port": uri.port or parsed.get("port", 0),
                "name": unquote(uri.fragment) or "PRIME NET",
                "transport": q(
                    "type",
                    parsed.get("transport", "tcp")
                ),
                "security": q(
                    "security",
                    parsed.get("security", "none")
                ),
                "sni": q(
                    "sni",
                    q("serverName", parsed.get("sni", ""))
                ),
                "fp": q("fp", parsed.get("fp", "")),
                "alpn": q("alpn", parsed.get("alpn", "")),
                "path": q("path", parsed.get("path", "")),
                "host": q("host", parsed.get("host", "")),
                "serviceName": q(
                    "serviceName",
                    parsed.get("serviceName", "")
                ),
                "mode": q("mode", parsed.get("mode", "")),
                "flow": q("flow", parsed.get("flow", "")),
                "encryption": q(
                    "encryption",
                    parsed.get("encryption", "none")
                ),
                "publicKey": q(
                    "pbk",
                    parsed.get("publicKey", "")
                ),
                "shortId": q(
                    "sid",
                    parsed.get("shortId", "")
                ),
                "spiderX": q(
                    "spx",
                    parsed.get("spiderX", "")
                )
            })

            if scheme == "vless":
                parsed["id"] = unquote(uri.username or "")
            else:
                parsed["password"] = unquote(uri.username or "")

            return parsed

        if scheme == "ss":
            user_info = unquote(uri.username or "")

            if ":" not in user_info:
                decoded_user = decode_base64(user_info)

                if decoded_user and ":" in decoded_user:
                    user_info = decoded_user

            method, separator, password = user_info.partition(":")

            if not separator and uri.netloc:
                raw_user = uri.netloc.split("@", 1)[0]
                decoded_user = decode_base64(raw_user)

                if ":" in decoded_user:
                    method, password = decoded_user.split(":", 1)
                    separator = True

            parsed.update({
                "protocol": "shadowsocks",
                "server": uri.hostname or parsed.get("server", ""),
                "port": uri.port or parsed.get("port", 0),
                "method": method if separator else "",
                "password": password if separator else "",
                "transport": "tcp",
                "security": "none",
                "name": unquote(uri.fragment) or "PRIME NET",
                "plugin": q("plugin", "")
            })

            return parsed

        raise ValueError("Unsupported VPN link format.")

    def normalise_transport(value):
        transport = str(value or "tcp").strip().lower()

        aliases = {
            "websocket": "ws",
            "web-socket": "ws",
            "http-upgrade": "httpupgrade",
            "http_upgrade": "httpupgrade",
            "tcp": "tcp",
            "ws": "ws",
            "grpc": "grpc",
            "httpupgrade": "httpupgrade"
        }

        return aliases.get(transport, transport)

    def build_outbound(link, parsed):
        protocol = str(
            parsed.get("protocol") or ""
        ).strip().lower()

        if protocol == "ss":
            protocol = "shadowsocks"

        address = str(
            parsed.get("server")
            or parsed.get("address")
            or ""
        ).strip()

        try:
            port = int(parsed.get("port") or 0)
        except (TypeError, ValueError):
            raise ValueError("Invalid VPN server port.")

        if not address or not 1 <= port <= 65535:
            raise ValueError(
                "The VPN server address or port is missing or invalid."
            )

        transport = normalise_transport(
            parsed.get("transport") or parsed.get("network") or "tcp"
        )

        security = str(
            parsed.get("security") or "none"
        ).strip().lower()

        supported_transports = (
            "tcp",
            "ws",
            "grpc",
            "httpupgrade"
        )

        if transport not in supported_transports:
            raise ValueError(
                "Unsupported transport: "
                + transport
                + ". Supported transports are TCP, WebSocket, "
                  "gRPC and HTTPUpgrade."
            )

        if protocol not in (
            "vless",
            "vmess",
            "trojan",
            "shadowsocks"
        ):
            raise ValueError(
                "Unsupported VPN protocol: " + protocol
            )

        stream = {
            "network": transport,
            "security": security
        }

        if protocol == "shadowsocks":
            if transport != "tcp" or security not in ("none", ""):
                raise ValueError(
                    "This app configuration supports plain TCP "
                    "Shadowsocks only."
                )

            if parsed.get("plugin"):
                raise ValueError(
                    "Shadowsocks plugins are not supported by this app configuration."
                )

        if transport == "ws":
            ws_settings = {
                "path": parsed.get("path") or "/"
            }

            host = str(parsed.get("host") or "").strip()

            if host:
                ws_settings["headers"] = {"Host": host}

            stream["wsSettings"] = ws_settings

        elif transport == "grpc":
            grpc_settings = {
                "serviceName": (
                    parsed.get("serviceName")
                    or parsed.get("service_name")
                    or ""
                )
            }

            mode = str(
                parsed.get("mode")
                or parsed.get("grpcMode")
                or ""
            ).strip().lower()

            if mode in ("multi", "multi-mode", "multimode"):
                grpc_settings["multiMode"] = True

            host = str(parsed.get("host") or "").strip()

            if host:
                grpc_settings["authority"] = host

            stream["grpcSettings"] = grpc_settings

        elif transport == "httpupgrade":
            stream["httpupgradeSettings"] = {
                "path": parsed.get("path") or "/",
                "host": parsed.get("host") or ""
            }

        if security == "tls":
            tls_settings = {
                "serverName": (
                    parsed.get("sni")
                    or parsed.get("serverName")
                    or address
                ),
                "allowInsecure": False
            }

            fingerprint = str(parsed.get("fp") or "").strip()

            if fingerprint:
                tls_settings["fingerprint"] = fingerprint

            alpn = parsed.get("alpn") or ""

            if isinstance(alpn, list):
                alpn_values = [
                    str(item).strip()
                    for item in alpn
                    if str(item).strip()
                ]
            else:
                alpn_values = [
                    item.strip()
                    for item in str(alpn).split(",")
                    if item.strip()
                ]

            if alpn_values:
                tls_settings["alpn"] = alpn_values

            stream["tlsSettings"] = tls_settings

        elif security == "reality":
            if protocol != "vless":
                raise ValueError(
                    "REALITY is only enabled for VLESS in this panel."
                )

            public_key = str(
                parsed.get("publicKey")
                or parsed.get("pbk")
                or ""
            ).strip()

            if not public_key:
                raise ValueError("The REALITY public key is missing.")

            reality_settings = {
                "serverName": (
                    parsed.get("sni")
                    or parsed.get("serverName")
                    or address
                ),
                "fingerprint": parsed.get("fp") or "chrome",
                "publicKey": public_key,
                "shortId": (
                    parsed.get("shortId")
                    or parsed.get("sid")
                    or ""
                ),
                "spiderX": (
                    parsed.get("spiderX")
                    or parsed.get("spx")
                    or ""
                )
            }

            stream["realitySettings"] = reality_settings

        elif security not in ("none", ""):
            raise ValueError(
                "Unsupported VPN security setting: " + security
            )

        if protocol == "vless":
            user_id = str(
                parsed.get("id")
                or parsed.get("uuid")
                or ""
            ).strip()

            if not user_id:
                raise ValueError("The VLESS UUID is missing.")

            user = {
                "id": user_id,
                "encryption": (
                    parsed.get("encryption") or "none"
                ),
                "level": 0
            }

            flow = str(parsed.get("flow") or "").strip()

            if flow:
                user["flow"] = flow

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
            user_id = str(
                parsed.get("id")
                or parsed.get("uuid")
                or ""
            ).strip()

            if not user_id:
                raise ValueError("The VMess UUID is missing.")

            try:
                alter_id = int(parsed.get("alterId") or 0)
            except (TypeError, ValueError):
                raise ValueError("Invalid VMess alter ID.")

            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": address,
                        "port": port,
                        "users": [{
                            "id": user_id,
                            "alterId": alter_id,
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

        else:
            method = str(
                parsed.get("method")
                or parsed.get("cipher")
                or ""
            ).strip()

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

        return outbound, protocol, address, port, transport, security

    def server_data(row):
        try:
            saved = json.loads(row["config_json"] or "{}")

            if not isinstance(saved, dict):
                raise ValueError("Saved configuration is invalid.")

            options = get_client_options(saved)

            link = make_config(saved)

            if not isinstance(link, str) or not link.startswith(
                ("vless://", "vmess://", "trojan://", "ss://")
            ):
                raise ValueError(
                    "The saved VPN link is missing or invalid."
                )

            parsed = parse_link(link)

            (
                outbound,
                protocol,
                address,
                port,
                transport,
                security
            ) = build_outbound(link, parsed)

            # Mux belongs inside the outbound object.
            # XrayConfigBuilder passes server.outbound directly
            # into the final Xray outbounds array.
            if options["mux"]:
                outbound["mux"] = {
                    "enabled": True,
                    "concurrency": 8
                }

            name = str(
                parsed.get("name") or "PRIME NET"
            )

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
                "outbound": outbound,
                "client_options": options
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

        token_hash = hashlib.sha256(
            token.encode()
        ).hexdigest()

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
                """
                UPDATE client_sessions
                SET last_seen=?
                WHERE token_hash=?
                """,
                (now(), token_hash)
            )

        save_device(row["id"])

        return row, token_hash

    def session_payload(row):
        _, reason = account_status(row)
        servers = server_data(row)

        if not servers and not reason:
            reason = (
                "The VPN configuration is incomplete or uses "
                "a setting that the app does not support. "
                "Please check the panel configuration."
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
        return jsonify({
            "ok": True,
            "panel": "PRIME NET VPN"
        })

    @api.post("/api/client/login")
    def login():
        data = request.get_json(silent=True) or {}

        username = str(
            data.get("username", "")
        ).strip()

        password = str(
            data.get("password", "")
        )

        if not username or not password:
            return error(
                "Enter your username and password."
            )

        with database() as db:
            row = execute(
                db,
                "SELECT * FROM accounts WHERE username=?",
                (username,)
            ).fetchone()

        if not row or not verify_password(
            password,
            row["password_hash"]
        ):
            return error(
                "Incorrect username or password.",
                401
            )

        allowed, reason = account_status(row)

        if not allowed:
            return error(reason, 403)

        device_id, _, _, _ = device_headers()
        limit = account_limit(row)

        with database() as db:
            existing = execute(
                db,
                """
                SELECT token_hash
                FROM client_sessions
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

        token_hash = hashlib.sha256(
            token.encode()
        ).hexdigest()

        with database() as db:
            execute(
                db,
                """
                INSERT INTO client_sessions
                (token_hash,account_id,device_id,created,last_seen)
                VALUES (?,?,?,?,?)
                """,
                (
                    token_hash,
                    row["id"],
                    device_id,
                    now(),
                    now()
                )
            )

        result = session_payload(row)
        result["token"] = token

        return jsonify(result)

    @api.get("/api/client/session")
    def get_session():
        row, _ = authenticated()

        if not row:
            return error(
                "Your session has expired. Please log in again.",
                401
            )

        return jsonify(session_payload(row))

    @api.get("/api/client/profile")
    def get_profile():
        row, _ = authenticated()

        if not row:
            return error(
                "Please log in again.",
                401
            )

        return jsonify({
            "profile": profile_data(row)
        })

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
            token_hash = hashlib.sha256(
                token.encode()
            ).hexdigest()

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

        target_id = str(
            data.get("id", "")
        ).strip()

        if not target_id:
            return error("Device ID is required.")

        row, _ = authenticated()

        if not row:
            username = str(
                data.get("username", "")
            ).strip()

            password = str(
                data.get("password", "")
            )

            with database() as db:
                row = execute(
                    db,
                    "SELECT * FROM accounts WHERE username=?",
                    (username,)
                ).fetchone()

            if not row or not verify_password(
                password,
                row["password_hash"]
            ):
                return error(
                    "Incorrect username or password.",
                    401
                )

        allowed, reason = account_status(row)

        if not allowed:
            return error(reason, 403)

        own_id, _, _, _ = device_headers()

        if target_id == own_id:
            return error(
                "You cannot release this device."
            )

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

        return jsonify({
            "devices": device_list(row["id"])
        })

    @api.post("/api/client/heartbeat")
    def heartbeat():
        row, _ = authenticated()

        if not row:
            return error(
                "Please log in again.",
                401
            )

        allowed, reason = account_status(row)

        return jsonify({
            "profile": profile_data(row),
            "can_connect": allowed,
            "blocked_reason": reason
        })

    app.register_blueprint(api)
