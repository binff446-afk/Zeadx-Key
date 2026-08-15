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
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nhận Key</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#080b12;
    --surface:#111726;
    --surface-2:#0c111c;
    --border: rgba(255,255,255,0.07);
    --text:#eef1f8;
    --text-dim:#8d96ab;
    --text-faint:#565f76;

    --indigo:#6366f1;
    --cyan:#2dd4e8;
    --emerald:#34d399;
    --amber:#fbbf24;
    --rose:#fb7185;

    --shadow-black: 0 24px 48px -12px rgba(0,0,0,0.85), 0 4px 12px rgba(0,0,0,0.6);
    --radius: 16px;
  }
  *{box-sizing:border-box;}
  html,body{margin:0;padding:0;}
  body{
    background:
      radial-gradient(circle at 15% 0%, rgba(99,102,241,0.16), transparent 45%),
      radial-gradient(circle at 90% 10%, rgba(45,212,232,0.12), transparent 42%),
      radial-gradient(circle at 50% 100%, rgba(52,211,153,0.06), transparent 50%),
      var(--bg);
    background-attachment:fixed;
    color:var(--text);
    font-family:'Inter',sans-serif;
    min-height:100vh;
    -webkit-font-smoothing:antialiased;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:28px 16px;
    overflow-x:hidden;
  }
  .display{ font-family:'Space Grotesk', sans-serif; }
  .mono{ font-family:'JetBrains Mono', monospace; }
  ::selection{ background: rgba(99,102,241,0.35); }
  :focus-visible{ outline:2px solid var(--cyan); outline-offset:2px; border-radius:6px; }

  /* ---------- background ping sweep ---------- */
  .radar-field{
    position:fixed; inset:0; z-index:0; pointer-events:none;
    background-image:
      linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px);
    background-size:38px 38px;
    mask-image: radial-gradient(circle at 50% 30%, black, transparent 70%);
  }

  .shell{ position:relative; z-index:1; width:100%; max-width:440px; }

  /* ---------- header / brand ---------- */
  .brand-row{ display:flex; align-items:center; justify-content:center; gap:11px; margin-bottom:22px; }
  .ping-badge{ position:relative; width:38px; height:38px; flex-shrink:0; }
  .ping-badge svg{ position:relative; z-index:2; }
  .ping-ring{
    position:absolute; inset:0; border-radius:50%;
    border:1.5px solid var(--cyan); opacity:0;
    animation: pingOut 2.4s cubic-bezier(.2,.7,.3,1) infinite;
  }
  .ping-ring.r2{ animation-delay:.8s; }
  .ping-ring.r3{ animation-delay:1.6s; }
  @keyframes pingOut{
    0%{ transform:scale(1); opacity:.65; }
    100%{ transform:scale(2.6); opacity:0; }
  }
  .brand-name{ font-size:19px; font-weight:700; letter-spacing:.2px; }
  .brand-name b{ color:var(--cyan); font-weight:700; }

  /* ---------- main card ---------- */
  .card{
    position:relative;
    background: linear-gradient(165deg, var(--surface), var(--surface-2));
    border:1px solid var(--border);
    border-radius: var(--radius);
    padding:32px 28px 28px;
    box-shadow: var(--shadow-black);
    overflow:hidden;
    animation: cardIn .55s cubic-bezier(.16,1,.3,1);
  }
  @keyframes cardIn{ from{opacity:0; transform:translateY(12px);} to{opacity:1; transform:translateY(0);} }
  .card::before{
    content:''; position:absolute; inset:0; border-radius:inherit; padding:1px;
    background: linear-gradient(135deg, rgba(99,102,241,0.55), rgba(45,212,232,0.05) 35%, rgba(255,255,255,0.03) 65%, rgba(52,211,153,0.3));
    -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
    -webkit-mask-composite: xor; mask-composite: exclude;
    pointer-events:none;
  }

  .steps{ display:flex; align-items:center; gap:6px; margin-bottom:24px; }
  .step-dot{
    flex:1; height:3px; border-radius:3px; background:var(--surface-2);
    border:1px solid var(--border); position:relative; overflow:hidden;
  }
  .step-dot i{ display:block; height:100%; width:0%; background:linear-gradient(90deg,var(--indigo),var(--cyan)); transition:width .4s ease; }
  .step-dot.done i{ width:100%; }
  .step-dot.active i{ width:50%; }

  .stage{ display:none; }
  .stage.active{ display:block; animation: fadeUp .4s ease; }
  @keyframes fadeUp{ from{opacity:0; transform:translateY(6px);} to{opacity:1; transform:translateY(0);} }

  .eyebrow{ font-size:11px; letter-spacing:1.2px; text-transform:uppercase; color:var(--text-faint); font-weight:600; margin-bottom:8px; }
  h1{ font-size:22px; margin:0 0 8px; line-height:1.25; }
  .lede{ color:var(--text-dim); font-size:13.5px; line-height:1.6; margin:0 0 22px; }

  .radar-visual{
    width:120px; height:120px; margin:6px auto 22px; position:relative;
    display:flex; align-items:center; justify-content:center;
  }
  .radar-visual .sweep-ring{
    position:absolute; border-radius:50%; border:1px solid rgba(45,212,232,0.28);
  }
  .radar-visual .sweep-ring:nth-child(1){ inset:0; }
  .radar-visual .sweep-ring:nth-child(2){ inset:16px; }
  .radar-visual .sweep-ring:nth-child(3){ inset:32px; }
  .radar-visual .core{
    position:relative; z-index:3; width:14px; height:14px; border-radius:50%;
    background:linear-gradient(135deg,var(--indigo),var(--cyan));
    box-shadow:0 0 22px 4px rgba(45,212,232,0.55);
  }
  .radar-visual .sweep{
    position:absolute; inset:0; border-radius:50%;
    background: conic-gradient(from 0deg, rgba(45,212,232,0.35), transparent 35%);
    animation: sweepSpin 2.6s linear infinite;
  }
  @keyframes sweepSpin{ to{ transform:rotate(360deg);} }

  .btn{
    width:100%; border:none; cursor:pointer; border-radius:11px;
    font-family:'Inter',sans-serif; font-weight:600; font-size:14px;
    padding:13px 18px; display:flex; align-items:center; justify-content:center; gap:8px;
    transition: transform .15s ease, filter .15s ease, box-shadow .15s ease;
  }
  .btn:active{ transform:scale(0.98); }
  .btn:disabled{ opacity:.55; cursor:not-allowed; }
  .btn-primary{
    background:linear-gradient(135deg,var(--indigo),var(--cyan));
    color:#080b12; box-shadow:0 14px 26px -10px rgba(99,102,241,0.6);
  }
  .btn-primary:hover:not(:disabled){ filter:brightness(1.08); }
  .btn-ghost{ background:var(--surface-2); color:var(--text); border:1px solid var(--border); }
  .btn-ghost:hover{ border-color: rgba(255,255,255,0.18); }

  .task-list{ display:flex; flex-direction:column; gap:9px; margin-bottom:20px; }
  .task-row{
    display:flex; align-items:center; gap:11px; padding:12px 13px;
    background:var(--surface-2); border:1px solid var(--border); border-radius:11px;
    font-size:13px; color:var(--text-dim);
  }
  .task-row .num{
    width:22px; height:22px; border-radius:50%; flex-shrink:0;
    display:flex; align-items:center; justify-content:center;
    background:var(--surface); border:1px solid var(--border); font-size:11px; font-weight:700; color:var(--text-faint);
  }
  .task-row.done{ color:var(--text); border-color:rgba(52,211,153,0.3); }
  .task-row.done .num{ background:rgba(52,211,153,0.15); border-color:rgba(52,211,153,0.4); color:var(--emerald); }

  .timer-ring{ position:relative; width:64px; height:64px; margin:0 auto 18px; }
  .timer-ring svg{ transform:rotate(-90deg); }
  .timer-ring circle{ fill:none; stroke-width:5; }
  .timer-ring .track{ stroke:var(--border); }
  .timer-ring .prog{ stroke:url(#ringGrad); stroke-linecap:round; transition:stroke-dashoffset .3s linear; }
  .timer-num{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; font-family:'JetBrains Mono',monospace; font-size:15px; font-weight:700; }

  /* ---------- key stage ---------- */
  .status-pill{
    display:inline-flex; align-items:center; gap:6px; font-size:11.5px; font-weight:600;
    padding:5px 11px; border-radius:20px; background:rgba(52,211,153,0.12); color:var(--emerald);
    border:1px solid rgba(52,211,153,0.3); margin-bottom:16px;
  }
  .status-pill .dot{ width:6px; height:6px; border-radius:50%; background:var(--emerald); box-shadow:0 0 8px var(--emerald); }

  .key-box{
    background:var(--surface-2); border:1px solid var(--border); border-radius:12px;
    padding:16px; margin-bottom:14px;
  }
  .key-box .lbl{ font-size:10.5px; letter-spacing:1px; text-transform:uppercase; color:var(--text-faint); margin-bottom:8px; }
  .key-row{ display:flex; align-items:center; gap:10px; }
  .key-val{ flex:1; font-size:15px; font-weight:700; letter-spacing:.4px; word-break:break-all; }
  .copy-btn{
    flex-shrink:0; width:36px; height:36px; border-radius:9px; border:1px solid var(--border);
    background:var(--surface); color:var(--text-dim); display:flex; align-items:center; justify-content:center;
    cursor:pointer; transition:.15s ease;
  }
  .copy-btn:hover{ color:var(--text); border-color:rgba(255,255,255,0.18); }
  .copy-btn.copied{ color:var(--emerald); border-color:rgba(52,211,153,0.4); }

  .meta-grid{ display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:20px; }
  .meta-cell{ background:var(--surface-2); border:1px solid var(--border); border-radius:10px; padding:11px 12px; }
  .meta-cell .lbl{ font-size:10px; letter-spacing:.6px; text-transform:uppercase; color:var(--text-faint); margin-bottom:4px; }
  .meta-cell .val{ font-size:13px; font-weight:600; font-family:'JetBrains Mono',monospace; }

  .note{
    display:flex; align-items:flex-start; gap:9px; font-size:11.5px; color:var(--text-faint);
    line-height:1.55; background:var(--surface-2); border:1px solid var(--border); border-radius:12px; padding:12px 13px;
  }
  .note svg{ flex-shrink:0; margin-top:1px; color:var(--amber); }
  .note b{ color:var(--text-dim); }

  .duration-grid{ display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:22px; }
  .duration-opt{
    position:relative; cursor:pointer; text-align:left;
    background:var(--surface-2); border:1px solid var(--border); border-radius:12px;
    padding:14px 14px 13px; transition: border-color .15s ease, background .15s ease, transform .15s ease;
  }
  .duration-opt:hover{ border-color:rgba(255,255,255,0.18); }
  .duration-opt:active{ transform:scale(0.98); }
  .duration-opt input{ position:absolute; opacity:0; pointer-events:none; }
  .duration-opt .len{ font-family:'Space Grotesk',sans-serif; font-size:20px; font-weight:700; line-height:1; margin-bottom:5px; }
  .duration-opt .desc{ font-size:11.5px; color:var(--text-faint); }
  .duration-opt .badge{
    position:absolute; top:10px; right:10px; font-size:9.5px; font-weight:700; letter-spacing:.4px;
    text-transform:uppercase; padding:3px 7px; border-radius:20px;
    background:rgba(52,211,153,0.15); color:var(--emerald); border:1px solid rgba(52,211,153,0.35);
  }
  .duration-opt.selected{
    border-color:var(--indigo); background:rgba(99,102,241,0.09);
    box-shadow:0 0 0 3px rgba(99,102,241,0.14);
  }
  .duration-opt.selected .len{ color:var(--cyan); }

  .foot-link{ text-align:center; margin-top:18px; font-size:12px; color:var(--text-faint); }
  .foot-link a{ color:var(--cyan); text-decoration:none; }
  .foot-link a:hover{ text-decoration:underline; }

  @media (max-width:420px){
    .card{ padding:26px 18px 22px; }
  }
</style>
</head>
<body>

<div class="radar-field"></div>

<div class="shell">


  <div class="card">
    <div class="steps">
      <div class="step-dot" id="dot1"><i></i></div>
      <div class="step-dot" id="dot2"><i></i></div>
      <div class="step-dot" id="dot3"><i></i></div>
    </div>

    <!-- STAGE 1: intro -->
    <div class="stage active" id="stage1">
      <div class="eyebrow">Hệ thống key</div>
      <h1 class="display">Nhận key truy cập</h1>
      <p class="lede">Chọn thời hạn key phù hợp với nhu cầu sử dụng, key sẽ có hiệu lực ngay khi kích hoạt.</p>

      <div class="radar-visual">
        <div class="sweep"></div>
        <div class="sweep-ring"></div>
        <div class="sweep-ring"></div>
        <div class="sweep-ring"></div>
        <div class="core"></div>
      </div>

      <div class="duration-grid" id="durationGrid">
        <label class="duration-opt selected" data-hours="12">
          <input type="radio" name="duration" value="12" checked>
          <div class="len display">12 giờ</div>
          <div class="desc">Dùng nhanh, gọn</div>
        </label>
        <label class="duration-opt" data-hours="24">
          <input type="radio" name="duration" value="24">
          <span class="badge">Phổ biến</span>
          <div class="len display">24 giờ</div>
          <div class="desc">Trọn một ngày</div>
        </label>
      </div>

      <button class="btn btn-primary" onclick="startVerify()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg>
        Bắt đầu lấy key
      </button>
      <div class="foot-link">Đã có key? <a href="#" onclick="return false;">Kiểm tra trạng thái key</a></div>
    </div>

    <!-- STAGE 2: verifying -->
    <div class="stage" id="stage2">
      <div class="eyebrow">Bước 2 / 3</div>
      <h1 class="display">Đang xác minh</h1>
      <p class="lede">Vui lòng đợi hệ thống hoàn tất xác minh trước khi cấp key.</p>

      <div class="timer-ring">
        <svg width="64" height="64">
          <defs>
            <linearGradient id="ringGrad" x1="0" y1="0" x2="1" y2="1">
              <stop stop-color="#6366f1"/><stop offset="1" stop-color="#2dd4e8"/>
            </linearGradient>
          </defs>
          <circle class="track" cx="32" cy="32" r="27"/>
          <circle class="prog" id="ringProg" cx="32" cy="32" r="27" stroke-dasharray="169.6" stroke-dashoffset="169.6"/>
        </svg>
        <div class="timer-num mono" id="ringNum">5s</div>
      </div>

      <div class="task-list" id="taskList">
        <div class="task-row" data-i="0"><div class="num">1</div><div>Xác minh trình duyệt</div></div>
        <div class="task-row" data-i="1"><div class="num">2</div><div>Kiểm tra kết nối</div></div>
        <div class="task-row" data-i="2"><div class="num">3</div><div>Khởi tạo key mới</div></div>
      </div>

      <button class="btn btn-ghost" disabled id="waitBtn">Đang xử lý…</button>
    </div>

    <!-- STAGE 3: key result -->
    <div class="stage" id="stage3">
      <div class="status-pill"><span class="dot"></span> Key đã kích hoạt</div>
      <h1 class="display">Key của bạn đã sẵn sàng</h1>
      <p class="lede">Sao chép key bên dưới và dán vào ứng dụng để đăng nhập.</p>

      <div class="key-box">
        <div class="lbl">Access key</div>
        <div class="key-row">
          <div class="key-val mono" id="keyVal">AT-••••-••••-••••</div>
          <button class="copy-btn" id="copyBtn" onclick="copyKey()" aria-label="Copy key">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
          </button>
        </div>
      </div>

      <div class="meta-grid">
        <div class="meta-cell"><div class="lbl">Hết hạn sau</div><div class="val" id="expiresIn">24:00:00</div></div>
        <div class="meta-cell"><div class="lbl">Thời hạn key</div><div class="val" id="durationLabel" style="color:var(--cyan)">24 giờ</div></div>
      </div>

      <div class="note">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
        <span><b>Lưu ý:</b> mỗi key gắn với một phiên làm việc. Lấy key mới sẽ vô hiệu hoá key đang dùng trên thiết bị này.</span>
      </div>
    </div>
  </div>
</div>

<script>
let selectedHours = 12;
document.querySelectorAll('.duration-opt').forEach(opt=>{
  opt.addEventListener('click', ()=>{
    document.querySelectorAll('.duration-opt').forEach(o=>o.classList.remove('selected'));
    opt.classList.add('selected');
    opt.querySelector('input').checked = true;
    selectedHours = parseInt(opt.dataset.hours, 10);
  });
});

function setStep(n){
  for(let i=1;i<=3;i++){
    const d=document.getElementById('dot'+i);
    d.classList.remove('done','active');
    if(i<n) d.classList.add('done');
    if(i===n) d.classList.add('active');
  }
}
setStep(1);

let fetchedKeyData = null;
let fetchError = null;

function startVerify(){
  document.getElementById('stage1').classList.remove('active');
  document.getElementById('stage2').classList.add('active');
  setStep(2);

  // Gọi API lấy key thật ngay khi bắt đầu xác minh, song song với animation
  fetchedKeyData = null;
  fetchError = null;
  fetch('/api/get-key', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({duration_hours: selectedHours})
  })
  .then(r=>r.json())
  .then(data=>{
    if(data.ok){ fetchedKeyData = data.key; }
    else { fetchError = data.error || 'Không lấy được key'; }
  })
  .catch(()=>{ fetchError = 'Không kết nối được máy chủ'; });

  const total=5, circumference=169.6;
  let remaining=total;
  const ring=document.getElementById('ringProg');
  const num=document.getElementById('ringNum');
  const rows=document.querySelectorAll('.task-row');

  const tick=()=>{
    num.textContent=remaining+'s';
    const offset=circumference*(remaining/total);
    ring.style.strokeDashoffset=offset;
    const doneCount=Math.min(rows.length, Math.floor((total-remaining)/(total/rows.length)));
    rows.forEach((r,i)=>r.classList.toggle('done', i<doneCount));
    if(remaining<=0){
      clearInterval(iv);
      rows.forEach(r=>r.classList.add('done'));
      setTimeout(showKey, 350);
      return;
    }
    remaining--;
  };
  tick();
  const iv=setInterval(tick,1000);
}

let expirySeconds = 24*3600;
function showKey(){
  // Nếu API vẫn chưa xong (mạng chậm), đợi thêm tối đa vài giây
  if(!fetchedKeyData && !fetchError){
    setTimeout(showKey, 300);
    return;
  }
  document.getElementById('stage2').classList.remove('active');
  document.getElementById('stage3').classList.add('active');
  setStep(3);

  if(fetchError){
    document.getElementById('keyVal').textContent = 'Lỗi: ' + fetchError;
    document.getElementById('durationLabel').textContent = '—';
    document.getElementById('expiresIn').textContent = '—';
    return;
  }

  document.getElementById('keyVal').textContent = fetchedKeyData.key;
  document.getElementById('durationLabel').textContent = selectedHours + ' giờ';

  const expiresAt = new Date(fetchedKeyData.expires_at).getTime();
  updateExpiry(expiresAt);
  clearInterval(window._expIv);
  window._expIv = setInterval(()=>updateExpiry(expiresAt), 1000);
}

function updateExpiry(expiresAtMs){
  let remainingSec = Math.max(0, Math.floor((expiresAtMs - Date.now())/1000));
  if(remainingSec<=0){ clearInterval(window._expIv); }
  const h=String(Math.floor(remainingSec/3600)).padStart(2,'0');
  const m=String(Math.floor((remainingSec%3600)/60)).padStart(2,'0');
  const s=String(remainingSec%60).padStart(2,'0');
  document.getElementById('expiresIn').textContent = `${h}:${m}:${s}`;
}

function copyKey(){
  const key=document.getElementById('keyVal').textContent;
  const btn=document.getElementById('copyBtn');
  navigator.clipboard.writeText(key).then(()=>{
    btn.classList.add('copied');
    setTimeout(()=>btn.classList.remove('copied'), 1600);
  }).catch(()=>{});
}
</script>
</body>
</html>

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
