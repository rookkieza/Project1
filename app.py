"""ยืมกันนะ — ระบบยืม-คืนของระหว่างเพื่อนในหอพัก (Flask + SQLite)"""
import os
import secrets
import sqlite3
import time
from datetime import date
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DATABASE", os.path.join(BASE_DIR, "data.db"))
IS_PROD = os.environ.get("FLASK_ENV", "").lower() == "production" or bool(os.environ.get("RENDER"))

CATEGORIES = ["การ์ตูน/หนังสือ", "บอร์ดเกม", "ชีท/หนังสือเรียน", "อุปกรณ์ไฟฟ้า", "อื่น ๆ"]
STATUS_TH = {
    "pending": "รออนุมัติ", "approved": "อนุมัติแล้ว", "rejected": "ปฏิเสธ",
    "returned": "คืนแล้ว", "cancelled": "ยกเลิก",
}


def load_secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(BASE_DIR, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(path, 0o600)
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    MAX_CONTENT_LENGTH=64 * 1024,
)
csrf = CSRFProtect(app)

# ---------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
    is_banned INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available','borrowed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    borrower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    borrow_date TEXT NOT NULL,
    return_date TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected','returned','cancelled')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    admin_user = os.environ.get("ADMIN_USER", "admin")
    admin_pass = os.environ.get("ADMIN_PASSWORD", "Admin@12345")
    if not db.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        db.execute(
            "INSERT INTO users (username, display_name, password_hash, role) VALUES (?,?,?,'admin')",
            (admin_user, "ผู้ดูแลระบบ", generate_password_hash(admin_pass)),
        )
        print(f"[init] สร้างบัญชี admin: {admin_user} (กรุณาเปลี่ยนรหัสผ่านผ่านตัวแปร ADMIN_PASSWORD)")
    db.commit()
    db.close()


init_db()

# ---------------------------------------------------------------- auth helpers
DUMMY_HASH = generate_password_hash("dummy-password")
FAILED = {}  # (ip, username) -> (count, first_time)
MAX_FAILS, WINDOW = 5, 600


def is_locked(key):
    rec = FAILED.get(key)
    if not rec:
        return False
    count, first = rec
    if time.time() - first > WINDOW:
        FAILED.pop(key, None)
        return False
    return count >= MAX_FAILS


def record_fail(key):
    count, first = FAILED.get(key, (0, time.time()))
    FAILED[key] = (count + 1, first)


@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        user = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if user is None or user["is_banned"]:
            session.clear()
        else:
            g.user = user


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            flash("กรุณาเข้าสู่ระบบก่อน", "warn")
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*a, **kw):
        if g.user["role"] != "admin":
            abort(403)
        return view(*a, **kw)
    return wrapped


def safe_next(target):
    """กัน open redirect: อนุญาตเฉพาะ path ภายในเว็บ"""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("index")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def inject():
    return {"STATUS_TH": STATUS_TH, "CATEGORIES": CATEGORIES}

# ---------------------------------------------------------------- auth routes
@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        display = request.form.get("display_name", "").strip()
        pw = request.form.get("password", "")
        pw2 = request.form.get("password2", "")
        errors = []
        if not (3 <= len(username) <= 20) or not username.replace("_", "").isalnum() or not username.isascii():
            errors.append("ชื่อผู้ใช้ต้องเป็นตัวอักษรอังกฤษ/ตัวเลข/_ ยาว 3-20 ตัว")
        if not (1 <= len(display) <= 40):
            errors.append("ชื่อที่แสดงต้องยาว 1-40 ตัวอักษร")
        if len(pw) < 8 or len(pw) > 128:
            errors.append("รหัสผ่านต้องยาว 8-128 ตัวอักษร")
        if pw != pw2:
            errors.append("รหัสผ่านสองช่องไม่ตรงกัน")
        db = get_db()
        if not errors and db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            errors.append("ชื่อผู้ใช้นี้ถูกใช้แล้ว")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, display_name=display), 400
        db.execute(
            "INSERT INTO users (username, display_name, password_hash) VALUES (?,?,?)",
            (username, display, generate_password_hash(pw)),
        )
        db.commit()
        flash("สมัครสมาชิกสำเร็จ เข้าสู่ระบบได้เลย", "ok")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        key = (request.remote_addr, username.lower())
        if is_locked(key):
            flash("ลองผิดหลายครั้งเกินไป กรุณารอ 10 นาทีแล้วลองใหม่", "error")
            return render_template("login.html", username=username), 429
        user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        # ตรวจ hash เสมอแม้ไม่พบผู้ใช้ เพื่อลดการเดาชื่อผู้ใช้จากเวลาตอบสนอง
        ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, pw)
        if not user or not ok:
            record_fail(key)
            flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", "error")
            return render_template("login.html", username=username), 401
        if user["is_banned"]:
            flash("บัญชีนี้ถูกระงับการใช้งาน", "error")
            return render_template("login.html", username=username), 403
        FAILED.pop(key, None)
        session.clear()  # กัน session fixation
        session["uid"] = user["id"]
        session.permanent = True
        return redirect(safe_next(request.args.get("next")))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("ออกจากระบบแล้ว", "ok")
    return redirect(url_for("index"))

# ---------------------------------------------------------------- items
def validate_item(form):
    title = form.get("title", "").strip()
    category = form.get("category", "")
    desc = form.get("description", "").strip()
    errors = []
    if not (1 <= len(title) <= 80):
        errors.append("ชื่อของต้องยาว 1-80 ตัวอักษร")
    if category not in CATEGORIES:
        errors.append("หมวดหมู่ไม่ถูกต้อง")
    if len(desc) > 500:
        errors.append("รายละเอียดต้องไม่เกิน 500 ตัวอักษร")
    return {"title": title, "category": category, "description": desc}, errors


@app.route("/")
def index():
    q = request.args.get("q", "").strip()[:50]
    cat = request.args.get("cat", "")
    sql = ("SELECT items.*, users.display_name AS owner_name FROM items "
           "JOIN users ON users.id = items.owner_id WHERE users.is_banned = 0")
    params = []
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        sql += " AND (items.title LIKE ? ESCAPE '\\' OR items.description LIKE ? ESCAPE '\\')"
        params += [like, like]
    if cat in CATEGORIES:
        sql += " AND items.category = ?"
        params.append(cat)
    sql += " ORDER BY items.status = 'borrowed', items.id DESC"
    items = get_db().execute(sql, params).fetchall()
    return render_template("index.html", items=items, q=q, cat=cat)


@app.route("/items/new", methods=["GET", "POST"])
@login_required
def item_new():
    if request.method == "POST":
        data, errors = validate_item(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("item_form.html", item=data, mode="new"), 400
        db = get_db()
        db.execute("INSERT INTO items (owner_id, title, category, description) VALUES (?,?,?,?)",
                   (g.user["id"], data["title"], data["category"], data["description"]))
        db.commit()
        flash("เพิ่มของเรียบร้อย", "ok")
        return redirect(url_for("my_items"))
    return render_template("item_form.html", item={"category": CATEGORIES[0]}, mode="new")


def get_item_or_404(item_id):
    item = get_db().execute(
        "SELECT items.*, users.display_name AS owner_name FROM items "
        "JOIN users ON users.id = items.owner_id WHERE items.id=?", (item_id,)).fetchone()
    if item is None:
        abort(404)
    return item


def require_owner(item):
    """สิทธิ์เจ้าของ: ตรวจฝั่งเซิร์ฟเวอร์ทุกครั้ง (กัน IDOR)"""
    if item["owner_id"] != g.user["id"]:
        abort(403)


@app.route("/items/<int:item_id>")
def item_detail(item_id):
    item = get_item_or_404(item_id)
    return render_template("item_detail.html", item=item, today=date.today().isoformat(), form={})


@app.route("/items/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
def item_edit(item_id):
    item = get_item_or_404(item_id)
    require_owner(item)
    if request.method == "POST":
        data, errors = validate_item(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
            data["id"] = item_id
            return render_template("item_form.html", item=data, mode="edit"), 400
        db = get_db()
        db.execute("UPDATE items SET title=?, category=?, description=? WHERE id=? AND owner_id=?",
                   (data["title"], data["category"], data["description"], item_id, g.user["id"]))
        db.commit()
        flash("บันทึกการแก้ไขแล้ว", "ok")
        return redirect(url_for("my_items"))
    return render_template("item_form.html", item=item, mode="edit")


@app.route("/items/<int:item_id>/delete", methods=["POST"])
@login_required
def item_delete(item_id):
    item = get_item_or_404(item_id)
    is_admin = g.user["role"] == "admin"
    if not is_admin:
        require_owner(item)
    db = get_db()
    db.execute("DELETE FROM items WHERE id=?", (item_id,))
    db.commit()
    flash("ลบรายการแล้ว", "ok")
    return redirect(url_for("admin") if is_admin and item["owner_id"] != g.user["id"] else url_for("my_items"))

# ---------------------------------------------------------------- borrow requests
@app.route("/items/<int:item_id>/borrow", methods=["POST"])
@login_required
def borrow(item_id):
    item = get_item_or_404(item_id)
    if item["owner_id"] == g.user["id"]:
        flash("ยืมของตัวเองไม่ได้", "error")
        return redirect(url_for("item_detail", item_id=item_id))
    if item["status"] != "available":
        flash("ของชิ้นนี้ถูกยืมอยู่ ลองใหม่ภายหลัง", "error")
        return redirect(url_for("item_detail", item_id=item_id))
    bd = request.form.get("borrow_date", "")
    rd = request.form.get("return_date", "")
    msg = request.form.get("message", "").strip()
    errors = []
    try:
        bdate, rdate = date.fromisoformat(bd), date.fromisoformat(rd)
        if bdate < date.today():
            errors.append("วันที่ยืมต้องไม่ใช่วันที่ผ่านมาแล้ว")
        if rdate < bdate:
            errors.append("วันที่คืนต้องไม่ก่อนวันที่ยืม")
        if (rdate - bdate).days > 60:
            errors.append("ยืมได้ไม่เกิน 60 วัน")
    except ValueError:
        errors.append("รูปแบบวันที่ไม่ถูกต้อง")
    if len(msg) > 300:
        errors.append("ข้อความต้องไม่เกิน 300 ตัวอักษร")
    db = get_db()
    if db.execute("SELECT 1 FROM requests WHERE item_id=? AND borrower_id=? AND status='pending'",
                  (item_id, g.user["id"])).fetchone():
        errors.append("คุณส่งคำขอยืมของชิ้นนี้ไปแล้ว รอเจ้าของตอบกลับ")
    if errors:
        for e in errors:
            flash(e, "error")
        return render_template("item_detail.html", item=item, today=date.today().isoformat(),
                               form=request.form), 400
    db.execute("INSERT INTO requests (item_id, borrower_id, borrow_date, return_date, message) VALUES (?,?,?,?,?)",
               (item_id, g.user["id"], bd, rd, msg))
    db.commit()
    flash("ส่งคำขอยืมแล้ว รอเจ้าของอนุมัติ", "ok")
    return redirect(url_for("my_requests"))


@app.route("/my/items")
@login_required
def my_items():
    db = get_db()
    items = db.execute("SELECT * FROM items WHERE owner_id=? ORDER BY id DESC", (g.user["id"],)).fetchall()
    incoming = db.execute(
        "SELECT requests.*, items.title, items.status AS item_status, users.display_name AS borrower_name "
        "FROM requests JOIN items ON items.id = requests.item_id "
        "JOIN users ON users.id = requests.borrower_id "
        "WHERE items.owner_id=? AND requests.status IN ('pending','approved') "
        "ORDER BY requests.status='pending' DESC, requests.id DESC", (g.user["id"],)).fetchall()
    return render_template("my_items.html", items=items, incoming=incoming)


@app.route("/my/requests")
@login_required
def my_requests():
    rows = get_db().execute(
        "SELECT requests.*, items.title, users.display_name AS owner_name "
        "FROM requests JOIN items ON items.id = requests.item_id "
        "JOIN users ON users.id = items.owner_id "
        "WHERE requests.borrower_id=? ORDER BY requests.id DESC", (g.user["id"],)).fetchall()
    return render_template("my_requests.html", requests=rows)


@app.route("/requests/<int:req_id>/<action>", methods=["POST"])
@login_required
def request_action(req_id, action):
    if action not in ("approve", "reject", "returned", "cancel"):
        abort(404)
    db = get_db()
    r = db.execute(
        "SELECT requests.*, items.owner_id, items.status AS item_status "
        "FROM requests JOIN items ON items.id = requests.item_id WHERE requests.id=?", (req_id,)).fetchone()
    if r is None:
        abort(404)
    if action == "cancel":
        if r["borrower_id"] != g.user["id"]:
            abort(403)
        if r["status"] != "pending":
            flash("ยกเลิกได้เฉพาะคำขอที่ยังรออนุมัติ", "error")
        else:
            db.execute("UPDATE requests SET status='cancelled' WHERE id=?", (req_id,))
            flash("ยกเลิกคำขอแล้ว", "ok")
        db.commit()
        return redirect(url_for("my_requests"))
    if r["owner_id"] != g.user["id"]:
        abort(403)
    if action == "approve":
        if r["status"] != "pending" or r["item_status"] != "available":
            flash("อนุมัติไม่ได้: คำขอนี้ไม่อยู่ในสถานะรออนุมัติ หรือของถูกยืมอยู่", "error")
        else:
            db.execute("UPDATE requests SET status='approved' WHERE id=?", (req_id,))
            db.execute("UPDATE items SET status='borrowed' WHERE id=?", (r["item_id"],))
            flash("อนุมัติแล้ว", "ok")
    elif action == "reject":
        if r["status"] != "pending":
            flash("ปฏิเสธได้เฉพาะคำขอที่รออนุมัติ", "error")
        else:
            db.execute("UPDATE requests SET status='rejected' WHERE id=?", (req_id,))
            flash("ปฏิเสธคำขอแล้ว", "ok")
    elif action == "returned":
        if r["status"] != "approved":
            flash("ทำเครื่องหมายคืนได้เฉพาะคำขอที่อนุมัติแล้ว", "error")
        else:
            db.execute("UPDATE requests SET status='returned' WHERE id=?", (req_id,))
            db.execute("UPDATE items SET status='available' WHERE id=?", (r["item_id"],))
            flash("บันทึกว่าคืนของแล้ว", "ok")
    db.commit()
    return redirect(url_for("my_items"))

# ---------------------------------------------------------------- admin
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute(
        "SELECT users.*, (SELECT COUNT(*) FROM items WHERE owner_id = users.id) AS item_count "
        "FROM users ORDER BY id").fetchall()
    items = db.execute(
        "SELECT items.*, users.display_name AS owner_name FROM items "
        "JOIN users ON users.id = items.owner_id ORDER BY items.id DESC").fetchall()
    return render_template("admin.html", users=users, items=items)


@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@admin_required
def admin_ban(user_id):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    if target["role"] == "admin":
        flash("ระงับบัญชี admin ไม่ได้", "error")
    else:
        new = 0 if target["is_banned"] else 1
        db.execute("UPDATE users SET is_banned=? WHERE id=?", (new, user_id))
        db.commit()
        flash(("ระงับบัญชี " if new else "ปลดระงับบัญชี ") + target["username"] + " แล้ว", "ok")
    return redirect(url_for("admin"))

# ---------------------------------------------------------------- errors
def error_page(code, title, text):
    return render_template("error.html", code=code, title=title, text=text), code


@app.errorhandler(403)
def e403(_):
    return error_page(403, "ไม่มีสิทธิ์เข้าถึง", "คุณไม่ใช่เจ้าของข้อมูลนี้ หรือไม่มีสิทธิ์ทำรายการนี้")


@app.errorhandler(404)
def e404(_):
    return error_page(404, "ไม่พบหน้านี้", "ลิงก์อาจผิด หรือรายการถูกลบไปแล้ว")


@app.errorhandler(413)
def e413(_):
    return error_page(413, "ข้อมูลใหญ่เกินไป", "ลองลดความยาวข้อมูลที่ส่ง")


@app.errorhandler(CSRFError)
def ecsrf(_):
    return error_page(400, "เซสชันหมดอายุ", "กรุณากลับไปโหลดหน้าใหม่แล้วลองอีกครั้ง")


@app.errorhandler(500)
def e500(_):
    return error_page(500, "เกิดข้อผิดพลาดในระบบ", "ลองใหม่อีกครั้งภายหลัง")


if __name__ == "__main__":
    app.run(debug=False, port=int(os.environ.get("PORT", 5000)))
