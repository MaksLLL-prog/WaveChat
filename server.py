"""
WaveChat Server — full-featured edition
Features: registration/login, JWT tokens, SQLite storage, WebSocket real-time,
          message delivery status, push notifications (Web Push / VAPID)

Requirements:
    pip install aiohttp aiosqlite pywebpush

Run:
    python server.py

ENV vars:
    PORT          (default 8080)
    DB_PATH       (default wavechat.db)
    SECRET_KEY    (auto-generated if not set — set it to keep sessions across restarts)
    MAX_FILE_MB   (default 25)
    HISTORY_LIMIT (default 200)
    VAPID_EMAIL   (e.g. mailto:admin@example.com)
"""

import asyncio, json, base64, os, secrets, hashlib, time, sqlite3, threading, uuid
from datetime import datetime
from pathlib import Path
from collections import deque
from aiohttp import web, WSMsgType

# ── CONFIG ─────────────────────────────────────────────────────────────────
PORT          = int(os.environ.get("PORT", 8080))
DB_PATH       = os.environ.get("DB_PATH", "wavechat.db")
SECRET_KEY    = os.environ.get("SECRET_KEY", secrets.token_hex(32))
MAX_FILE_MB   = int(os.environ.get("MAX_FILE_MB", 25))
HISTORY_LIMIT = int(os.environ.get("HISTORY_LIMIT", 200))
VAPID_EMAIL   = os.environ.get("VAPID_EMAIL", "mailto:admin@wavechat.app")

# Runtime state (cleared on restart; persistent data lives in SQLite)
clients: dict = {}          # ws -> {id, name, avatar}
global_history = deque(maxlen=HISTORY_LIMIT)
dm_history: dict = {}       # "dm:a-b" -> deque
db_lock = threading.Lock()

# ── PUSH (pywebpush optional) ───────────────────────────────────────────────
try:
    from pywebpush import webpush, WebPushException
    from py_vapid import Vapid
    PUSH_AVAILABLE = True
except ImportError:
    PUSH_AVAILABLE = False


# ── HELPERS ────────────────────────────────────────────────────────────────
def ts():   return datetime.now().strftime("%H:%M")
def iso():  return datetime.now().isoformat(timespec="seconds")
def log(m): print(f"[{datetime.now().strftime('%H:%M:%S')}] {m}", flush=True)

def dm_key(a, b): return f"dm:{min(a,b)}-{max(a,b)}"

def get_dm(a, b):
    k = dm_key(a, b)
    if k not in dm_history:
        dm_history[k] = deque(maxlen=HISTORY_LIMIT)
    return dm_history[k]

def ws_by_id(uid):
    for w, v in clients.items():
        if v["id"] == uid:
            return w

def all_users():
    return [{"id": v["id"], "name": v["name"], "avatar": v.get("avatar")} for v in clients.values()]


# ── PASSWORD & TOKEN ────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"pbkdf2:{salt}:{h.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split(":")
        expected = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
        return secrets.compare_digest(expected.hex(), h)
    except Exception:
        return False

def make_token(user_id: int) -> str:
    payload = f"{user_id}:{int(time.time())}"
    sig = hashlib.sha256(f"{payload}:{SECRET_KEY}".encode()).hexdigest()[:24]
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

def verify_token(token: str):
    """Returns user_id int if valid, else None."""
    try:
        raw = base64.urlsafe_b64decode(token.encode() + b"==").decode()
        parts = raw.rsplit(":", 1)
        payload, sig = ":".join(parts[:-1]), parts[-1]
        uid_ts = payload.split(":")
        uid, ts_val = int(uid_ts[0]), int(uid_ts[1])
        expected = hashlib.sha256(f"{payload}:{SECRET_KEY}".encode()).hexdigest()[:24]
        if not secrets.compare_digest(expected, sig):
            return None
        if time.time() - ts_val > 30 * 86400:  # 30 days
            return None
        return uid
    except Exception:
        return None

def auth_required(handler):
    """Decorator that validates Bearer token and injects user_id."""
    async def wrapper(req):
        auth = req.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="Missing token")
        uid = verify_token(auth[7:])
        if uid is None:
            raise web.HTTPUnauthorized(text="Invalid or expired token")
        req["user_id"] = uid
        return await handler(req)
    return wrapper


# ── DATABASE ────────────────────────────────────────────────────────────────
def db_connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def db_init():
    conn = db_connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT    UNIQUE NOT NULL,   -- email or phone
            name       TEXT    NOT NULL,
            password   TEXT    NOT NULL,
            avatar     TEXT,                       -- base64 data URI
            bio        TEXT    DEFAULT '',
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS messages (
            id         TEXT    PRIMARY KEY,        -- uuid4
            from_id    INTEGER NOT NULL REFERENCES users(id),
            to_id      INTEGER REFERENCES users(id),  -- NULL = global
            type       TEXT    NOT NULL DEFAULT 'text',
            body       TEXT    NOT NULL,           -- JSON payload
            status     TEXT    NOT NULL DEFAULT 'sent',  -- sent | delivered | read
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            endpoint    TEXT    NOT NULL,
            p256dh      TEXT    NOT NULL,
            auth        TEXT    NOT NULL,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(user_id, endpoint)
        );

        CREATE TABLE IF NOT EXISTS vapid_keys (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            private_key TEXT NOT NULL,
            public_key  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_id);
        CREATE INDEX IF NOT EXISTS idx_messages_to   ON messages(to_id);
    """)
    conn.commit()
    return conn

DB = db_init()

def db_exec(sql, params=(), fetchone=False, fetchall=False, commit=False):
    with db_lock:
        try:
            cur = DB.execute(sql, params)
            if commit:
                DB.commit()
            if fetchone:
                return cur.fetchone()
            if fetchall:
                return cur.fetchall()
            if commit:
                return cur.lastrowid
        except Exception as e:
            log(f"DB error: {e}")
            raise


# ── VAPID KEY MANAGEMENT ────────────────────────────────────────────────────
VAPID_PRIVATE_KEY = None
VAPID_PUBLIC_KEY  = None

def init_vapid():
    global VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY
    if not PUSH_AVAILABLE:
        return

    row = db_exec("SELECT private_key, public_key FROM vapid_keys WHERE id=1", fetchone=True)
    if row:
        VAPID_PRIVATE_KEY = row["private_key"]
        VAPID_PUBLIC_KEY  = row["public_key"]
    else:
        try:
            vapid = Vapid()
            vapid.generate_keys()
            priv = vapid.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            pub = vapid.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            pub_b64 = base64.urlsafe_b64encode(pub).rstrip(b"=").decode()
            db_exec("INSERT INTO vapid_keys(id, private_key, public_key) VALUES(1,?,?)",
                    (priv, pub_b64), commit=True)
            VAPID_PRIVATE_KEY = priv
            VAPID_PUBLIC_KEY  = pub_b64
            log(f"VAPID keys generated. Public key: {pub_b64}")
        except Exception as e:
            log(f"VAPID init failed: {e}")


# ── WS HELPERS ──────────────────────────────────────────────────────────────
async def snd(ws, p):
    try:
        await ws.send_str(json.dumps(p, ensure_ascii=False))
    except Exception:
        pass

async def bcast(p, ex=None):
    d = json.dumps(p, ensure_ascii=False)
    for w in list(clients):
        if w != ex:
            try:
                await w.send_str(d)
            except Exception:
                pass

async def push_users():
    await bcast({"type": "users", "users": all_users()})

async def send_push_to_user(user_id: int, payload: dict):
    """Send a Web Push notification to all subscriptions of a user."""
    if not PUSH_AVAILABLE or not VAPID_PRIVATE_KEY:
        return
    subs = db_exec(
        "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id=?",
        (user_id,), fetchall=True
    )
    if not subs:
        return
    msg = json.dumps(payload, ensure_ascii=False)
    for sub in subs:
        try:
            webpush(
                subscription_info={
                    "endpoint": sub["endpoint"],
                    "keys": {"p256dh": sub["p256dh"], "auth": sub["auth"]}
                },
                data=msg,
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims={"sub": VAPID_EMAIL}
            )
        except WebPushException as e:
            if "410" in str(e) or "404" in str(e):
                # Subscription expired — remove it
                db_exec(
                    "DELETE FROM push_subscriptions WHERE endpoint=?",
                    (sub["endpoint"],), commit=True
                )
            else:
                log(f"Push error for user {user_id}: {e}")
        except Exception as e:
            log(f"Push error: {e}")


# ── REST: REGISTRATION & LOGIN ──────────────────────────────────────────────
async def api_register(req: web.Request):
    try:
        body = await req.json()
    except Exception:
        raise web.HTTPBadRequest(text="Invalid JSON")

    identifier = (body.get("identifier") or "").strip().lower()
    name       = (body.get("name") or "").strip()[:64]
    password   = body.get("password") or ""

    if not identifier:
        raise web.HTTPBadRequest(text="Email or phone is required")
    if not name:
        raise web.HTTPBadRequest(text="Name is required")
    if len(password) < 6:
        raise web.HTTPBadRequest(text="Password must be at least 6 characters")

    # Check duplicate
    existing = db_exec("SELECT id FROM users WHERE identifier=?", (identifier,), fetchone=True)
    if existing:
        raise web.HTTPConflict(text="This email/phone is already registered")

    pwd_hash = hash_password(password)
    try:
        with db_lock:
            cur = DB.execute(
                "INSERT INTO users(identifier, name, password) VALUES(?,?,?)",
                (identifier, name, pwd_hash)
            )
            user_id = cur.lastrowid
            DB.commit()
    except sqlite3.IntegrityError:
        raise web.HTTPConflict(text="This email/phone is already registered")

    token = make_token(user_id)
    log(f"Register: [{user_id}] {name} ({identifier})")
    return web.json_response({
        "token": token,
        "user": {"id": user_id, "name": name, "avatar": None, "bio": ""}
    })


async def api_login(req: web.Request):
    try:
        body = await req.json()
    except Exception:
        raise web.HTTPBadRequest(text="Invalid JSON")

    identifier = (body.get("identifier") or "").strip().lower()
    password   = body.get("password") or ""

    row = db_exec(
        "SELECT id, name, password, avatar, bio FROM users WHERE identifier=?",
        (identifier,), fetchone=True
    )
    if not row or not verify_password(password, row["password"]):
        raise web.HTTPUnauthorized(text="Invalid credentials")

    token = make_token(row["id"])
    log(f"Login: [{row['id']}] {row['name']}")
    return web.json_response({
        "token": token,
        "user": {
            "id": row["id"],
            "name": row["name"],
            "avatar": row["avatar"],
            "bio": row["bio"] or ""
        }
    })


@auth_required
async def api_profile_get(req: web.Request):
    row = db_exec(
        "SELECT id, name, avatar, bio, identifier, created_at FROM users WHERE id=?",
        (req["user_id"],), fetchone=True
    )
    if not row:
        raise web.HTTPNotFound()
    return web.json_response({
        "id": row["id"],
        "name": row["name"],
        "avatar": row["avatar"],
        "bio": row["bio"] or "",
        "identifier": row["identifier"],
        "created_at": row["created_at"]
    })


@auth_required
async def api_profile_put(req: web.Request):
    try:
        body = await req.json()
    except Exception:
        raise web.HTTPBadRequest(text="Invalid JSON")

    uid  = req["user_id"]
    name = (body.get("name") or "").strip()[:64]
    bio  = (body.get("bio") or "")[:200]
    avatar = body.get("avatar")  # base64 data URI or null

    # Validate avatar size (~1MB base64)
    if avatar and len(avatar) > 1_400_000:
        raise web.HTTPBadRequest(text="Avatar image too large (max 1MB)")

    if not name:
        raise web.HTTPBadRequest(text="Name is required")

    db_exec(
        "UPDATE users SET name=?, bio=?, avatar=? WHERE id=?",
        (name, bio, avatar, uid), commit=True
    )

    # Update live WS session if connected
    for ws, v in clients.items():
        if v["id"] == uid:
            v["name"]   = name
            v["avatar"] = avatar
            break

    await push_users()
    return web.json_response({"ok": True, "name": name, "avatar": avatar, "bio": bio})


async def api_push_key(req: web.Request):
    return web.json_response({
        "available": PUSH_AVAILABLE and bool(VAPID_PUBLIC_KEY),
        "publicKey": VAPID_PUBLIC_KEY or ""
    })


@auth_required
async def api_push_subscribe(req: web.Request):
    try:
        body = await req.json()
    except Exception:
        raise web.HTTPBadRequest(text="Invalid JSON")

    uid      = req["user_id"]
    endpoint = body.get("endpoint", "")
    p256dh   = body.get("p256dh", "")
    auth_key = body.get("auth", "")

    if not endpoint or not p256dh or not auth_key:
        raise web.HTTPBadRequest(text="Missing subscription fields")

    db_exec(
        """INSERT INTO push_subscriptions(user_id, endpoint, p256dh, auth)
           VALUES(?,?,?,?)
           ON CONFLICT(user_id, endpoint) DO UPDATE SET p256dh=excluded.p256dh, auth=excluded.auth""",
        (uid, endpoint, p256dh, auth_key), commit=True
    )
    return web.json_response({"ok": True})


async def api_dm_history(req: web.Request):
    """REST endpoint for persisted DM history from DB."""
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise web.HTTPUnauthorized()
    uid = verify_token(auth[7:])
    if uid is None:
        raise web.HTTPUnauthorized()

    peer_id = int(req.match_info["peer_id"])
    rows = db_exec(
        """SELECT m.id, m.from_id, m.to_id, m.body, m.status, m.created_at,
                  u.name as from_name, u.avatar as from_avatar
           FROM messages m JOIN users u ON u.id = m.from_id
           WHERE m.type='text'
             AND ((m.from_id=? AND m.to_id=?) OR (m.from_id=? AND m.to_id=?))
           ORDER BY m.created_at ASC LIMIT 200""",
        (uid, peer_id, peer_id, uid), fetchall=True
    )
    messages = []
    for r in rows:
        body = json.loads(r["body"])
        messages.append({
            "id": r["id"],
            "from_id": r["from_id"],
            "from_name": r["from_name"],
            "to_id": r["to_id"],
            "text": body.get("text", ""),
            "ts": r["created_at"][11:16],
            "iso": r["created_at"],
            "status": r["status"],
            "self": r["from_id"] == uid,
            "dm": True
        })
    return web.json_response({"messages": messages})


# ── WEBSOCKET HANDLER ────────────────────────────────────────────────────────
async def ws_handler(req: web.Request):
    ws = web.WebSocketResponse(heartbeat=30, max_msg_size=(MAX_FILE_MB + 2) * 1024 * 1024)
    await ws.prepare(req)

    cid  = None
    name = None

    try:
        # ── Await join message ──────────────────────────────────────────────
        try:
            first = await asyncio.wait_for(ws.__anext__(), timeout=20)
        except (asyncio.TimeoutError, StopAsyncIteration):
            return ws

        if first.type != WSMsgType.TEXT:
            return ws

        msg = json.loads(first.data)
        if msg.get("type") != "join":
            return ws

        token = msg.get("token", "")
        uid   = verify_token(token) if token else None

        if uid is None:
            await snd(ws, {"type": "error", "text": "Invalid or expired token. Please log in again."})
            return ws

        # Load user from DB
        row = db_exec("SELECT id, name, avatar FROM users WHERE id=?", (uid,), fetchone=True)
        if not row:
            await snd(ws, {"type": "error", "text": "User not found"})
            return ws

        cid  = row["id"]
        name = row["name"]

        clients[ws] = {"id": cid, "name": name, "avatar": row["avatar"]}
        log(f"+ [{cid}] {name} (online: {len(clients)})")

        # Send init packet with history
        await snd(ws, {
            "type":    "init",
            "my_id":   cid,
            "my_name": name,
            "avatar":  row["avatar"],
            "history": list(global_history),
            "users":   all_users()
        })
        await bcast({"type": "system", "text": f"{name} joined 👋", "ts": ts()}, ex=ws)
        await push_users()

        # ── Message loop ────────────────────────────────────────────────────
        async for m in ws:
            if m.type == WSMsgType.ERROR:
                break
            if m.type != WSMsgType.TEXT:
                continue

            msg   = json.loads(m.data)
            mtype = msg.get("type")
            t     = ts()
            i     = iso()

            # ── TEXT ──────────────────────────────────────────────────────
            if mtype == "text":
                text = msg.get("text", "").strip()
                if not text or len(text) > 4000:
                    continue

                to_id = msg.get("to_id")

                if to_id:
                    to_id   = int(to_id)
                    to_name = next((v["name"] for v in clients.values() if v["id"] == to_id), "?")

                    # Persist to DB
                    msg_id = str(uuid.uuid4())
                    db_exec(
                        "INSERT INTO messages(id, from_id, to_id, type, body, status) VALUES(?,?,?,?,?,?)",
                        (msg_id, cid, to_id, "text", json.dumps({"text": text}), "sent"),
                        commit=True
                    )

                    p = {
                        "type": "text", "dm": True,
                        "id": msg_id,
                        "from_id": cid, "from_name": name,
                        "to_id": to_id, "to_name": to_name,
                        "text": text, "ts": t, "iso": i,
                        "status": "sent"
                    }
                    get_dm(cid, to_id).append(p)

                    to_ws = ws_by_id(to_id)
                    if to_ws:
                        await snd(to_ws, p)
                        # Auto-mark as delivered when recipient is online
                        db_exec(
                            "UPDATE messages SET status='delivered' WHERE id=?",
                            (msg_id,), commit=True
                        )
                        await snd(ws, {**p, "self": True, "status": "delivered"})
                        await snd(to_ws, {"type": "delivered", "msg_id": msg_id, "from_id": cid})
                    else:
                        await snd(ws, {**p, "self": True, "status": "sent"})
                        # Send push notification to offline user
                        asyncio.create_task(send_push_to_user(to_id, {
                            "title": f"New message from {name}",
                            "body": text[:100],
                            "from_id": cid,
                            "from_name": name
                        }))
                else:
                    p = {"type": "text", "dm": False, "from_id": cid, "from_name": name,
                         "text": text, "ts": t, "iso": i}
                    global_history.append(p)
                    await bcast(p, ex=ws)
                    await snd(ws, {**p, "self": True})

            # ── DELIVERED ACK ─────────────────────────────────────────────
            elif mtype == "delivered":
                msg_id = msg.get("msg_id")
                if msg_id:
                    db_exec(
                        "UPDATE messages SET status='delivered' WHERE id=? AND to_id=?",
                        (msg_id, cid), commit=True
                    )
                    row2 = db_exec("SELECT from_id FROM messages WHERE id=?", (msg_id,), fetchone=True)
                    if row2:
                        sender_ws = ws_by_id(row2["from_id"])
                        if sender_ws:
                            await snd(sender_ws, {"type": "delivered", "msg_id": msg_id})

            # ── FILE ──────────────────────────────────────────────────────
            elif mtype == "file":
                fname = (msg.get("filename") or "file").strip()[:200]
                mime  = msg.get("mime") or "application/octet-stream"
                data  = msg.get("data", "")
                to_id = msg.get("to_id")
                try:
                    size = len(base64.b64decode(data + "=="))
                except Exception:
                    continue
                if size > MAX_FILE_MB * 1024 * 1024:
                    await snd(ws, {"type": "error", "text": f"Max {MAX_FILE_MB}MB"})
                    continue

                if to_id:
                    to_id   = int(to_id)
                    to_name = next((v["name"] for v in clients.values() if v["id"] == to_id), "?")
                    p = {"type": "file", "dm": True,
                         "from_id": cid, "from_name": name,
                         "to_id": to_id, "to_name": to_name,
                         "filename": fname, "mime": mime, "data": data, "size": size,
                         "ts": t, "iso": i}
                    to_ws = ws_by_id(to_id)
                    if to_ws:
                        await snd(to_ws, p)
                    await snd(ws, {**p, "self": True})
                else:
                    p = {"type": "file", "dm": False,
                         "from_id": cid, "from_name": name,
                         "filename": fname, "mime": mime, "data": data, "size": size,
                         "ts": t, "iso": i}
                    global_history.append({**p, "data": None})
                    await bcast(p, ex=ws)
                    await snd(ws, {**p, "self": True})

            # ── VOICE ─────────────────────────────────────────────────────
            elif mtype == "voice":
                data  = msg.get("data", "")
                to_id = msg.get("to_id")
                dur   = msg.get("duration", 0)
                try:
                    size = len(base64.b64decode(data + "=="))
                except Exception:
                    continue
                if size > 10 * 1024 * 1024:
                    await snd(ws, {"type": "error", "text": "Voice max 10MB"})
                    continue

                if to_id:
                    to_id   = int(to_id)
                    to_name = next((v["name"] for v in clients.values() if v["id"] == to_id), "?")
                    p = {"type": "voice", "dm": True,
                         "from_id": cid, "from_name": name,
                         "to_id": to_id, "to_name": to_name,
                         "data": data, "duration": dur, "ts": t, "iso": i}
                    to_ws = ws_by_id(to_id)
                    if to_ws:
                        await snd(to_ws, p)
                    await snd(ws, {**p, "self": True})
                else:
                    p = {"type": "voice", "dm": False,
                         "from_id": cid, "from_name": name,
                         "data": data, "duration": dur, "ts": t, "iso": i}
                    await bcast(p, ex=ws)
                    await snd(ws, {**p, "self": True})

            # ── DM HISTORY ────────────────────────────────────────────────
            elif mtype == "dm_history":
                peer_id = int(msg.get("peer_id", 0))
                await snd(ws, {
                    "type":     "dm_history",
                    "messages": list(get_dm(cid, peer_id)),
                    "peer_id":  peer_id
                })

            # ── TYPING ────────────────────────────────────────────────────
            elif mtype == "typing":
                to_id = msg.get("to_id")
                if to_id:
                    to_ws = ws_by_id(int(to_id))
                    if to_ws:
                        await snd(to_ws, {"type": "typing", "from_id": cid, "from_name": name, "dm": True})
                else:
                    await bcast({"type": "typing", "from_id": cid, "from_name": name}, ex=ws)

            # ── WebRTC SIGNALING ──────────────────────────────────────────
            elif mtype == "call-offer":
                to_id = int(msg.get("to_id", 0))
                to_ws = ws_by_id(to_id)
                if to_ws:
                    await snd(to_ws, {"type": "call-offer", "from_id": cid, "from_name": name, "sdp": msg.get("sdp")})
                    log(f"  call {cid}→{to_id}")
                else:
                    await snd(ws, {"type": "call-error", "text": "User is offline"})

            elif mtype == "call-answer":
                to_id = int(msg.get("to_id", 0))
                to_ws = ws_by_id(to_id)
                if to_ws:
                    await snd(to_ws, {"type": "call-answer", "from_id": cid, "sdp": msg.get("sdp")})

            elif mtype == "ice-candidate":
                to_id = int(msg.get("to_id", 0))
                to_ws = ws_by_id(to_id)
                if to_ws:
                    await snd(to_ws, {"type": "ice-candidate", "from_id": cid, "candidate": msg.get("candidate")})

            elif mtype in ("call-reject", "call-end"):
                to_id = int(msg.get("to_id", 0))
                to_ws = ws_by_id(to_id)
                if to_ws:
                    await snd(to_ws, {"type": mtype, "from_id": cid, "from_name": name})

    except Exception as e:
        log(f"! [{cid}] {e}")
    finally:
        clients.pop(ws, None)
        log(f"- [{cid}] {name} left (online: {len(clients)})")
        if name:
            await bcast({"type": "system", "text": f"{name} left the chat", "ts": ts()})
            await push_users()
    return ws


# ── STATIC ───────────────────────────────────────────────────────────────────
async def index(req: web.Request):
    p = Path(__file__).parent / "client.html"
    html = p.read_text("utf-8") if p.exists() else "<h1>client.html not found</h1>"
    return web.Response(text=html, content_type="text/html")

async def serve_sw(req: web.Request):
    p = Path(__file__).parent / "sw.js"
    if p.exists():
        return web.Response(text=p.read_text("utf-8"), content_type="application/javascript",
                            headers={"Service-Worker-Allowed": "/"})
    return web.Response(status=404)

async def health(req: web.Request):
    return web.Response(text="ok")


# ── APP ──────────────────────────────────────────────────────────────────────
@web.middleware
async def cors_middleware(req, handler):
    try:
        resp = await handler(req)
    except web.HTTPException as ex:
        resp = ex
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
    return resp

async def options_handler(req):
    return web.Response(status=204)

app = web.Application(middlewares=[cors_middleware])
app.router.add_get("/",                           index)
app.router.add_get("/sw.js",                      serve_sw)
app.router.add_get("/health",                     health)
app.router.add_get("/ws",                         ws_handler)
app.router.add_post("/api/register",              api_register)
app.router.add_post("/api/login",                 api_login)
app.router.add_get("/api/profile",                api_profile_get)
app.router.add_put("/api/profile",                api_profile_put)
app.router.add_get("/api/push/key",               api_push_key)
app.router.add_post("/api/push/subscribe",        api_push_subscribe)
app.router.add_get("/api/dm-history/{peer_id}",   api_dm_history)
app.router.add_route("OPTIONS", "/{path_info:.*}", options_handler)


if __name__ == "__main__":
    init_vapid()
    push_status = "with push notifications" if (PUSH_AVAILABLE and VAPID_PUBLIC_KEY) else "without push (install pywebpush)"
    log(f"WaveChat v2.0 | port={PORT} | db={DB_PATH} | {push_status}")
    log(f"Secret key (save this!): {SECRET_KEY[:8]}…")
    web.run_app(app, host="0.0.0.0", port=PORT, access_log=None)