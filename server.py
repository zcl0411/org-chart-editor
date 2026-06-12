#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "org_chart.sqlite3"
SECRET_PATH = ROOT / "org_chart_secret.key"
MAX_HISTORY = 30
TOKEN_TTL = 60 * 60 * 24 * 14


def get_secret() -> bytes:
    if not SECRET_PATH.exists():
      SECRET_PATH.write_bytes(os.urandom(32))
    return SECRET_PATH.read_bytes()


SECRET = get_secret()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              salt TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS histories (
              id TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL,
              name TEXT NOT NULL,
              time TEXT NOT NULL,
              data TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_histories_user_created
            ON histories(user_id, created_at DESC);
            """
        )


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return base64.b64encode(digest).decode("ascii"), base64.b64encode(salt).decode("ascii")


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    digest, _ = hash_password(password, base64.b64decode(salt))
    return hmac.compare_digest(digest, password_hash)


def sign(payload: bytes) -> str:
    return base64.urlsafe_b64encode(hmac.new(SECRET, payload, hashlib.sha256).digest()).decode("ascii").rstrip("=")


def make_token(user: sqlite3.Row) -> str:
    payload = json.dumps({
        "uid": user["id"],
        "username": user["username"],
        "exp": int(time.time()) + TOKEN_TTL,
    }, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return payload_b64 + "." + sign(payload)


def parse_token(token: str) -> dict | None:
    try:
        payload_b64, sig = token.split(".", 1)
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = base64.urlsafe_b64decode(padded.encode("ascii"))
        if not hmac.compare_digest(sig, sign(payload)):
            return None
        data = json.loads(payload.decode("utf-8"))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


class Handler(SimpleHTTPRequestHandler):
    server_version = "OrgChartEditor/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/me":
            user = self.require_user()
            if user:
                self.json_response({"user": user})
            return
        if parsed.path == "/api/history":
            user = self.require_user()
            if not user:
                return
            with db() as conn:
                rows = conn.execute(
                    "SELECT id, name, time, data FROM histories WHERE user_id = ? ORDER BY created_at DESC",
                    (user["id"],),
                ).fetchall()
            self.json_response({
                "history": [
                    {"id": r["id"], "name": r["name"], "time": r["time"], "data": json.loads(r["data"])}
                    for r in rows
                ]
            })
            return
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/register":
            self.register()
            return
        if parsed.path == "/api/login":
            self.login()
            return
        if parsed.path == "/api/history":
            self.save_history()
            return
        self.error(HTTPStatus.NOT_FOUND, "接口不存在")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        prefix = "/api/history/"
        if parsed.path.startswith(prefix):
            user = self.require_user()
            if not user:
                return
            item_id = unquote(parsed.path[len(prefix):])
            with db() as conn:
                conn.execute("DELETE FROM histories WHERE id = ? AND user_id = ?", (item_id, user["id"]))
            self.json_response({"ok": True})
            return
        self.error(HTTPStatus.NOT_FOUND, "接口不存在")

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8") or "{}")

    def json_response(self, payload: dict, status=HTTPStatus.OK):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def error(self, status, message):
        self.json_response({"error": message}, status)

    def require_user(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self.error(HTTPStatus.UNAUTHORIZED, "请先登录")
            return None
        data = parse_token(auth.removeprefix("Bearer ").strip())
        if not data:
            self.error(HTTPStatus.UNAUTHORIZED, "登录已过期，请重新登录")
            return None
        return {"id": data["uid"], "username": data["username"]}

    def register(self):
        try:
            body = self.read_json()
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            if len(username) < 2 or len(username) > 40:
                self.error(HTTPStatus.BAD_REQUEST, "账号长度需为 2-40 个字符")
                return
            if len(password) < 6:
                self.error(HTTPStatus.BAD_REQUEST, "密码至少 6 位")
                return
            password_hash, salt = hash_password(password)
            with db() as conn:
                cur = conn.execute(
                    "INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                    (username, password_hash, salt),
                )
                user = {"id": cur.lastrowid, "username": username}
            self.json_response({"user": user, "token": make_token(user)}, HTTPStatus.CREATED)
        except sqlite3.IntegrityError:
            self.error(HTTPStatus.CONFLICT, "账号已存在")
        except Exception as exc:
            self.error(HTTPStatus.BAD_REQUEST, f"注册失败：{exc}")

    def login(self):
        try:
            body = self.read_json()
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            with db() as conn:
                user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not user or not verify_password(password, user["password_hash"], user["salt"]):
                self.error(HTTPStatus.UNAUTHORIZED, "账号或密码错误")
                return
            public_user = {"id": user["id"], "username": user["username"]}
            self.json_response({"user": public_user, "token": make_token(user)})
        except Exception as exc:
            self.error(HTTPStatus.BAD_REQUEST, f"登录失败：{exc}")

    def save_history(self):
        user = self.require_user()
        if not user:
            return
        try:
            body = self.read_json()
            name = str(body.get("name") or "未命名").strip()[:120]
            data = body.get("data")
            if not isinstance(data, dict):
                self.error(HTTPStatus.BAD_REQUEST, "历史数据格式无效")
                return
            item_id = uuid.uuid4().hex
            now = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())
            created_at = int(time.time() * 1000)
            with db() as conn:
                conn.execute(
                    "INSERT INTO histories(id, user_id, name, time, data, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (item_id, user["id"], name, now, json.dumps(data, ensure_ascii=False), created_at),
                )
                rows = conn.execute(
                    "SELECT id FROM histories WHERE user_id = ? ORDER BY created_at DESC LIMIT -1 OFFSET ?",
                    (user["id"], MAX_HISTORY),
                ).fetchall()
                if rows:
                    conn.executemany("DELETE FROM histories WHERE id = ?", [(r["id"],) for r in rows])
            self.json_response({"item": {"id": item_id, "name": name, "time": now, "data": data}}, HTTPStatus.CREATED)
        except Exception as exc:
            self.error(HTTPStatus.BAD_REQUEST, f"保存失败：{exc}")


def main():
    init_db()
    host = "127.0.0.1"
    port = int(os.environ.get("ORG_CHART_PORT", "8765"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Org chart editor running at http://{host}:{port}")
    print(f"SQLite database: {DB_PATH}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
