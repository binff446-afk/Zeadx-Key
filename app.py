"""
Quản Lí Key & Quản Lí Get Key
------------------------------
Backend Flask cho hệ thống quản lý key (license key server).

Chức năng:
- Trang admin (/admin): đăng nhập bằng mật khẩu, tạo / xem / xoá key,
  khoá IP, xem cấu hình (config) của từng key.
- Trang lấy key (/): người dùng chọn thời hạn và nhận 1 key mới.
- API để app/phần mềm khác gọi vào để xác minh key (POST /api/verify-key).

Lưu trữ: SQLite (file keys.db). Trên Render (gói Free) ổ đĩa là ephemeral
-> dữ liệu có thể mất khi service bị restart/deploy lại. Nếu cần lưu lâu dài,
gắn Render Persistent Disk và trỏ DB_PATH vào đó, hoặc dùng Postgres.

Deploy lên Render:
1. Push app.py + requirements.txt lên 1 repo Git (GitHub/GitLab).
2. Render -> New -> Web Service -> chọn repo.
3. Build Command:  pip install -r requirements.txt
   Start Command:  gunicorn app:app
4. Thêm Environment Variable:
     ADMIN_PASSWORD = <mật khẩu admin của bạn>
     SECRET_KEY     = <chuỗi ngẫu nhiên bất kỳ>
5. Deploy. Trang admin: https://<ten-service>.onrender.com/admin
   Trang lấy key:      https://<ten-service>.onrender.com/
"""

import os
import sqlite3
import secrets
import string
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, g, jsonify, redirect, request, session, url_for

# --------------------------------------------------------------------------
# Cấu hình
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "keys.db"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(16))
ALLOWED_DURATIONS = [12, 24]  # giờ - khớp với 2 lựa chọn trên trang lấy key

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            note TEXT DEFAULT '',
            duration_hours REAL NOT NULL,
            lock_ip INTEGER NOT NULL DEFAULT 0,
            ip TEXT,
            created_at TEXT NOT NULL,
            activated_at TEXT,
            expires_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat() if dt else None


def parse_iso(s):
    return datetime.fromisoformat(s) if s else None


def gen_key():
    seg = lambda: "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    return f"AT-{seg()}-{seg()}-{seg()}"


def row_to_dict(row):
    created_at = parse_iso(row["created_at"])
    activated_at = parse_iso(row["activated_at"])
    expires_at = parse_iso(row["expires_at"])
    n = now_utc()
    if not activated_at:
        status = "unused"
    elif expires_at and n > expires_at:
        status = "expired"
    else:
        status = "active"
    return {
        "id": row["id"],
        "key": row["key"],
        "note": row["note"],
        "duration_hours": row["duration_hours"],
        "lock_ip": bool(row["lock_ip"]),
        "ip": row["ip"],
        "created_at": row["created_at"],
        "activated_at": row["activated_at"],
        "expires_at": row["expires_at"],
        "status": status,
    }


# --------------------------------------------------------------------------
# Auth admin
# --------------------------------------------------------------------------
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"ok": False, "error": "Chưa đăng nhập admin"}), 401
        return fn(*args, **kwargs)

    return wrapper


@app.post("/api/admin/login")
def admin_login():
    data = request.get_json(silent=True) or {}
    if data.get("password") == ADMIN_PASSWORD:
        session["is_admin"] = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Sai mật khẩu"}), 401


@app.post("/api/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return jsonify({"ok": True})


@app.get("/api/admin/session")
def admin_session():
    return jsonify({"ok": True, "is_admin": bool(session.get("is_admin"))})


# --------------------------------------------------------------------------
# API quản lý key (admin) - Quản Lí Key
# --------------------------------------------------------------------------
@app.get("/api/admin/keys")
@admin_required
def list_keys():
    db = get_db()
    rows = db.execute("SELECT * FROM keys ORDER BY id DESC").fetchall()
    return jsonify({"ok": True, "keys": [row_to_dict(r) for r in rows]})


@app.post("/api/admin/keys")
@admin_required
def create_key():
    data = request.get_json(silent=True) or {}
    duration_hours = float(data.get("duration_hours", 24))
    note = (data.get("note") or "").strip()[:200]
    lock_ip = bool(data.get("lock_ip", False))

    db = get_db()
    key = gen_key()
    db.execute(
        "INSERT INTO keys (key, note, duration_hours, lock_ip, created_at) VALUES (?,?,?,?,?)",
        (key, note, duration_hours, int(lock_ip), iso(now_utc())),
    )
    db.commit()
    row = db.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    return jsonify({"ok": True, "key": row_to_dict(row)}), 201


@app.delete("/api/admin/keys/<int:key_id>")
@admin_required
def delete_key(key_id):
    db = get_db()
    db.execute("DELETE FROM keys WHERE id=?", (key_id,))
    db.commit()
    return jsonify({"ok": True})


@app.get("/api/admin/keys/<int:key_id>/config")
@admin_required
def get_config(key_id):
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "Không tìm thấy key"}), 404
    k = row_to_dict(row)
    config = {
        "key": k["key"],
        "status": k["status"],
        "note": k["note"],
        "created_at": k["created_at"],
        "expires_at": k["expires_at"],
        "duration_hours": k["duration_hours"],
        "ip_lock": k["lock_ip"],
        "bound_ip": k["ip"],
    }
    return jsonify({"ok": True, "config": config})


@app.post("/api/admin/keys/<int:key_id>/check-ip")
@admin_required
def admin_check_ip(key_id):
    data = request.get_json(silent=True) or {}
    ip_val = (data.get("ip") or "").strip()
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "Không tìm thấy key"}), 404
    if not ip_val:
        return jsonify({"ok": False, "error": "Thiếu địa chỉ IP"}), 400

    if not row["lock_ip"]:
        db.execute("UPDATE keys SET ip=? WHERE id=?", (ip_val, key_id))
        db.commit()
        result = "unlocked"
    elif not row["ip"]:
        db.execute("UPDATE keys SET ip=? WHERE id=?", (ip_val, key_id))
        db.commit()
        result = "assigned"
    elif row["ip"] == ip_val:
        result = "match"
    else:
        result = "mismatch"

    return jsonify({"ok": True, "result": result})


# --------------------------------------------------------------------------
# API lấy key công khai - Quản Lí Get Key
# --------------------------------------------------------------------------
@app.post("/api/get-key")
def get_key():
    data = request.get_json(silent=True) or {}
    duration_hours = data.get("duration_hours", 12)
    try:
        duration_hours = float(duration_hours)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Thời hạn không hợp lệ"}), 400
    if duration_hours not in ALLOWED_DURATIONS:
        return jsonify({"ok": False, "error": "Thời hạn không được hỗ trợ"}), 400

    n = now_utc()
    expires = n + timedelta(hours=duration_hours)
    key = gen_key()
    db = get_db()
    db.execute(
        "INSERT INTO keys (key, note, duration_hours, lock_ip, created_at, activated_at, expires_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (key, "Tự lấy (get-key)", duration_hours, 0, iso(n), iso(n), iso(expires)),
    )
    db.commit()
    row = db.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    return jsonify({"ok": True, "key": row_to_dict(row)}), 201


@app.post("/api/verify-key")
def verify_key():
    """Dùng cho phần mềm/app phía client gọi vào để kiểm tra key hợp lệ.
    Nếu key chưa kích hoạt, kích hoạt luôn lúc gọi lần đầu."""
    data = request.get_json(silent=True) or {}
    key_val = (data.get("key") or "").strip()
    ip_val = (data.get("ip") or request.remote_addr or "").strip()
    if not key_val:
        return jsonify({"ok": False, "error": "Thiếu key"}), 400

    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE key=?", (key_val,)).fetchone()
    if not row:
        return jsonify({"ok": False, "valid": False, "error": "Key không tồn tại"}), 404

    n = now_utc()
    if not row["activated_at"]:
        expires = n + timedelta(hours=row["duration_hours"])
        db.execute(
            "UPDATE keys SET activated_at=?, expires_at=? WHERE id=?",
            (iso(n), iso(expires), row["id"]),
        )
        db.commit()
        row = db.execute("SELECT * FROM keys WHERE id=?", (row["id"],)).fetchone()

    k = row_to_dict(row)

    if row["lock_ip"]:
        if not row["ip"]:
            db.execute("UPDATE keys SET ip=? WHERE id=?", (ip_val, row["id"]))
            db.commit()
        elif row["ip"] != ip_val:
            return jsonify({"ok": True, "valid": False, "error": "IP không khớp", "key": k}), 403

    if k["status"] == "expired":
        return jsonify({"ok": True, "valid": False, "error": "Key đã hết hạn", "key": k}), 403

    return jsonify({"ok": True, "valid": True, "key": k})


# --------------------------------------------------------------------------
# Trang giao diện (HTML tối giản, gọi vào API ở trên)
# --------------------------------------------------------------------------
GET_KEY_PAGE = """
<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Quản Lí Get Key</title>
<style>
 body{background:#080b12;color:#eef1f8;font-family:Inter,sans-serif;display:flex;
      align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
 .card{background:#111726;border:1px solid rgba(255,255,255,.08);border-radius:16px;
       padding:28px;max-width:420px;width:100%}
 h1{font-size:20px;margin:0 0 14px}
 select,button{width:100%;padding:12px;border-radius:10px;border:1px solid rgba(255,255,255,.1);
       background:#0c111c;color:#eef1f8;font-size:14px;margin-bottom:12px}
 button{background:linear-gradient(135deg,#6366f1,#2dd4e8);color:#080b12;font-weight:700;
        border:none;cursor:pointer}
 .key-box{background:#0c111c;border:1px solid rgba(255,255,255,.08);border-radius:10px;
          padding:14px;font-family:monospace;word-break:break-all;display:none}
 .muted{color:#8d96ab;font-size:12.5px}
 .err{color:#fb7185;font-size:13px;min-height:18px}
</style></head><body>
<div class="card">
  <h1>Quản Lí Get Key</h1>
  <p class="muted">Chọn thời hạn key rồi bấm lấy key.</p>
  <select id="dur">
    <option value="12">12 giờ</option>
    <option value="24">24 giờ</option>
  </select>
  <button onclick="doGetKey()">Lấy key</button>
  <div class="err" id="err"></div>
  <div class="key-box" id="keyBox">
    <div class="muted">Access key</div>
    <div id="keyVal" style="font-size:16px;font-weight:700;margin:6px 0"></div>
    <div class="muted">Hết hạn lúc: <span id="expVal"></span></div>
  </div>
</div>
<script>
async function doGetKey(){
  const dur = document.getElementById('dur').value;
  const err = document.getElementById('err'); err.textContent='';
  const res = await fetch('/api/get-key', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({duration_hours: Number(dur)})
  });
  const data = await res.json();
  if(!data.ok){ err.textContent = data.error || 'Có lỗi xảy ra'; return; }
  document.getElementById('keyVal').textContent = data.key.key;
  document.getElementById('expVal').textContent = data.key.expires_at;
  document.getElementById('keyBox').style.display = 'block';
}
</script>
</body></html>
"""

ADMIN_PAGE = """
<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Quản Lí Key</title>
<style>
 body{background:#0a0d14;color:#e8ecf5;font-family:Inter,sans-serif;margin:0;padding:24px}
 .wrap{max-width:900px;margin:0 auto}
 h1{font-size:22px}
 input,select,button{padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,.1);
     background:#121826;color:#e8ecf5;font-size:13px}
 button{cursor:pointer;background:linear-gradient(135deg,#818cf8,#22d3ee);color:#0a0d14;
        font-weight:700;border:none}
 table{width:100%;border-collapse:collapse;margin-top:18px;font-size:13px}
 th,td{border-bottom:1px solid rgba(255,255,255,.08);padding:8px;text-align:left}
 .row{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
 #loginBox{max-width:340px;margin:60px auto;text-align:center}
 #loginBox input{width:100%;margin-bottom:10px}
 #loginBox button{width:100%}
 .err{color:#fb7185;font-size:13px}
 .status-active{color:#34d399} .status-expired{color:#fb7185} .status-unused{color:#fbbf24}
</style></head><body>
<div class="wrap" id="app" style="display:none">
  <h1>Quản Lí Key</h1>
  <div class="row">
    <input id="note" placeholder="Ghi chú">
    <select id="hours">
      <option value="12">12 giờ</option>
      <option value="24" selected>24 giờ</option>
      <option value="168">7 ngày</option>
      <option value="720">30 ngày</option>
    </select>
    <label style="display:flex;align-items:center;gap:6px">
      <input type="checkbox" id="lockIp" style="width:auto"> Khoá IP
    </label>
    <button onclick="createKey()">+ Tạo key</button>
  </div>
  <table>
    <thead><tr><th>Key</th><th>Ghi chú</th><th>Trạng thái</th><th>Hết hạn</th><th>IP</th><th></th></tr></thead>
    <tbody id="tbody"></tbody>
  </table>
</div>

<div id="loginBox">
  <h1>Quản Lí Key</h1>
  <input type="password" id="pass" placeholder="Mật khẩu admin">
  <button onclick="doLogin()">Đăng nhập</button>
  <div class="err" id="loginErr"></div>
</div>

<script>
async function checkSession(){
  const r = await fetch('/api/admin/session'); const d = await r.json();
  if(d.is_admin){ show(); loadKeys(); }
}
function show(){
  document.getElementById('loginBox').style.display='none';
  document.getElementById('app').style.display='block';
}
async function doLogin(){
  const password = document.getElementById('pass').value;
  const r = await fetch('/api/admin/login', {method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({password})});
  const d = await r.json();
  if(d.ok){ show(); loadKeys(); } else { document.getElementById('loginErr').textContent = d.error; }
}
async function loadKeys(){
  const r = await fetch('/api/admin/keys'); const d = await r.json();
  const body = document.getElementById('tbody');
  body.innerHTML = d.keys.map(k => `
    <tr>
      <td>${k.key}</td>
      <td>${k.note||''}</td>
      <td class="status-${k.status}">${k.status}</td>
      <td>${k.expires_at ? new Date(k.expires_at).toLocaleString('vi-VN') : '—'}</td>
      <td>${k.ip || '—'}</td>
      <td><button onclick="delKey(${k.id})">Xoá</button></td>
    </tr>`).join('');
}
async function createKey(){
  const note = document.getElementById('note').value;
  const duration_hours = Number(document.getElementById('hours').value);
  const lock_ip = document.getElementById('lockIp').checked;
  await fetch('/api/admin/keys', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({note, duration_hours, lock_ip})});
  document.getElementById('note').value='';
  loadKeys();
}
async function delKey(id){
  if(!confirm('Xoá key này?')) return;
  await fetch('/api/admin/keys/'+id, {method:'DELETE'});
  loadKeys();
}
checkSession();
</script>
</body></html>
"""


@app.get("/")
def home():
    return GET_KEY_PAGE


@app.get("/admin")
def admin_page():
    return ADMIN_PAGE


# --------------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
