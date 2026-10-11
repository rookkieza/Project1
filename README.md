# ยืมกันนะ — ระบบยืม-คืนของระหว่างเพื่อนในหอพัก

เว็บแอปด้วย **Python Flask + SQLite** นักศึกษาลงของที่ให้ยืม เพื่อนกดขอยืม เจ้าของอนุมัติ/ปฏิเสธ/บันทึกว่าคืนแล้ว

## รันในเครื่อง

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                    # เปิด http://localhost:5000
```

ครั้งแรกระบบสร้างฐานข้อมูล `data.db` และบัญชี admin ให้อัตโนมัติ
- ค่าเริ่มต้น: `admin` / `Admin@12345`
- **ควรเปลี่ยนก่อนใช้จริง** โดยตั้งตัวแปร `ADMIN_USER` และ `ADMIN_PASSWORD` *ก่อนรันครั้งแรก*

## ตรงกับเกณฑ์โจทย์

| เกณฑ์ | อยู่ที่ไหน |
|---|---|
| 1. สมัคร/ล็อกอิน + hashing | `/register`, `/login` ใช้ `generate_password_hash` (scrypt) ของ Werkzeug |
| 2. สองบทบาท | `user` และ `admin` (คอลัมน์ `users.role`, ตัวตกแต่ง `admin_required`) |
| 3. CRUD มีเจ้าของ | ตาราง `items`: เพิ่ม/แก้/ลบได้เฉพาะเจ้าของ (`require_owner`) |
| 4. ฟอร์มอย่างน้อย 2 ฟอร์ม | ฟอร์มเพิ่ม/แก้ของ และฟอร์มขอยืม (`requests`) บันทึกลง DB แล้วแสดงผล |
| 5. หน้า admin | `/admin` ดูผู้ใช้ ระงับ/ปลดระงับ ลบรายการ |

## การป้องกันการโจมตี (ใช้ตอบคำถามได้)

| การโจมตี | วิธีป้องกันในโค้ด |
|---|---|
| SQL Injection | ทุกคำสั่ง SQL ใช้ parameter `?` ไม่ต่อสตริง และ escape `% _` ในช่องค้นหา |
| XSS | Jinja2 escape อัตโนมัติ + CSP ห้าม inline script |
| CSRF | Flask-WTF `CSRFProtect` ทุกฟอร์ม POST (รวมปุ่มออกจากระบบ/ลบ) |
| IDOR | ตรวจเจ้าของฝั่งเซิร์ฟเวอร์ทุก route (คนอื่นแก้/ลบ/อนุมัติจะได้ 403) |
| Brute force | ล็อกชั่วคราว 10 นาทีหากรหัสผิด 5 ครั้ง (ต่อ IP+ชื่อผู้ใช้) |
| Session | HttpOnly, SameSite=Lax, Secure (บนโฮส), `session.clear()` ตอนล็อกอิน (กัน fixation), ผู้ใช้ที่ถูกแบนหลุดทันที |
| Open redirect | `safe_next()` รับเฉพาะ path ภายในเว็บ |
| Clickjacking / อื่น ๆ | `X-Frame-Options: DENY`, `X-Content-Type-Options`, จำกัดขนาด request |
| Validation | ตรวจความยาว ชนิด วันที่ หมวดหมู่ ฝั่งเซิร์ฟเวอร์ |

## เอาขึ้นโฮส (Render.com ตัวอย่าง)

1. อัปโหลดโฟลเดอร์นี้ขึ้น GitHub
2. Render → New → **Web Service** → เลือก repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Environment variables:
   - `SECRET_KEY` = สตริงสุ่มยาว ๆ (เช่นผลจาก `python -c "import secrets;print(secrets.token_hex(32))"`)
   - `ADMIN_USER`, `ADMIN_PASSWORD` = บัญชี admin ของคุณ
   - `FLASK_ENV` = `production`
6. กด Deploy แล้วส่งลิงก์ใน classroom

**ข้อควรรู้:** แพ็กเกจฟรีของ Render ไม่เก็บไฟล์ถาวร ฐานข้อมูล SQLite จะรีเซ็ตเมื่อเซิร์ฟเวอร์รีสตาร์ท ถ้าต้องการข้อมูลถาวรให้เพิ่ม Disk แล้วตั้ง `DATABASE=/path/to/data.db` หรือย้ายไปใช้ PostgreSQL

## โครงสร้างไฟล์

```
app.py            โค้ดหลักทั้งหมด (routes, DB, ความปลอดภัย)
templates/        หน้าเว็บ (Jinja2)
static/           style.css, confirm.js
requirements.txt  Procfile  .gitignore
```
