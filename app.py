from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import or_, text, inspect
from sqlalchemy.exc import IntegrityError, DataError
from functools import wraps
from io import BytesIO
from math import ceil
from datetime import datetime, timezone
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import secrets
import os
import re
from xhtml2pdf import pisa

# -------------------------------------------------
# Flask & App config
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "gizli_anahtar")

# Şablonlar ve statikler
app.config["TEMPLATES_AUTO_RELOAD"] = True
# Build/versiyon bilgisi (Render, Railway, Heroku vb. için)
APP_VERSION = (os.getenv("RENDER_GIT_COMMIT")
               or os.getenv("HEROKU_SLUG_COMMIT")
               or os.getenv("GIT_COMMIT")
               or "dev")[:7]
app.jinja_env.globals["APP_VERSION"] = APP_VERSION
# Statik cache’i azalt (canlıda yeni UI’nin gelmesini kolaylaştırır)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 300  # 5 dk (istediğinde yükselt)

# -------------------------------------------------
# DB config
# -------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'gorev_takip.db')}"

_db_url_final = DATABASE_URL
if _db_url_final.startswith("postgresql://"):
    _db_url_final = _db_url_final.replace("postgresql://", "postgresql+psycopg://", 1)
if _db_url_final.startswith("postgresql+psycopg://") and "sslmode=" not in _db_url_final:
    sep = "&" if "?" in _db_url_final else "?"
    _db_url_final = f"{_db_url_final}{sep}sslmode=require"

app.config["SQLALCHEMY_DATABASE_URI"] = _db_url_final
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
engine_opts = {"pool_pre_ping": True, "pool_recycle": 300}
if _db_url_final.startswith("postgresql+psycopg://"):
    engine_opts["connect_args"] = {"sslmode": "require"}
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_opts

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# -------------------------------------------------
# Mail (Gmail uygulama şifresi önerilir)
# -------------------------------------------------
MAIL_USER = os.getenv("MAIL_USER")
MAIL_PASS = os.getenv("MAIL_PASS")

def send_mail_plain(to_email: str, subject: str, body: str) -> bool:
    if not MAIL_USER or not MAIL_PASS:
        app.logger.error("MAIL_USER / MAIL_PASS tanımlı değil.")
        return False
    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = MAIL_USER
    msg["To"] = to_email
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(MAIL_USER, MAIL_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        app.logger.error(f"Mail gönderilemedi: {e}")
        return False

# -------------------------------------------------
# Token yardımcıları
# -------------------------------------------------
def _signer():
    return URLSafeTimedSerializer(app.secret_key, salt="pw-reset")

def make_reset_token(user_id: int) -> str:
    raw = f"{user_id}:{secrets.token_urlsafe(16)}"
    return _signer().dumps(raw)

def parse_reset_token(token: str, max_age_seconds: int = 1800) -> int | None:
    try:
        payload = _signer().loads(token, max_age=max_age_seconds)
        return int(payload.split(":", 1)[0])
    except (BadSignature, SignatureExpired, ValueError):
        return None

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# -------------------------------------------------
# Modeller
# -------------------------------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")  # user / admin

    tasks_created = db.relationship("Task", foreign_keys="Task.user_id", backref="assigner", lazy=True)
    tasks_assigned = db.relationship("Task", foreign_keys="Task.assigned_to", backref="assignee", lazy=True)

class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(200))
    location = db.Column(db.String(200))
    materials = db.Column(db.Text)
    date = db.Column(db.String(50))
    needs_support = db.Column(db.String(50))
    status = db.Column(db.String(50))
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))
    accepted = db.Column(db.String(20), default="Bekliyor")
    completed = db.Column(db.String(20), default="Hayir")
    completion_note = db.Column(db.Text, default="")

    @property
    def assigner_name(self):
        return self.assigner.username if self.assigner else ""

    @property
    def assignee_name(self):
        return self.assignee.username if self.assignee else ""

# -------------------------------------------------
# Yardımcılar
# -------------------------------------------------
@app.before_request
def refresh_role():
    uid = session.get("user_id")
    if uid:
        u = db.session.get(User, uid)
        if u:
            session["role"] = u.role
            session["username"] = u.username

def apply_filters(query, user_id):
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    mine = request.args.get("mine") == "1"
    assigned = (request.args.get("assigned") or "").strip()

    if q:
        like = f"%{q}%"
        query = query.filter(or_(Task.title.ilike(like), Task.location.ilike(like), Task.materials.ilike(like)))
    if status:
        query = query.filter(Task.status == status)
    if mine:
        query = query.filter(or_(Task.user_id == user_id, Task.assigned_to == user_id))
    if assigned.isdigit():
        query = query.filter(Task.assigned_to == int(assigned))
    return query

def paginate(query, page, per_page=10):
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    pages = ceil(total / per_page) if per_page else 1
    return items, total, pages

def require_admin():
    if "user_id" not in session or session.get("role") != "admin":
        abort(403)

def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard")) if "user_id" in session else redirect(url_for("login"))

# --- Register ---
@app.route("/register", methods=["GET", "POST"])
def register():
    has_email_col = any(c.name == "email" for c in User.__table__.columns)

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password_raw = request.form.get("password") or ""
        email = (request.form.get("email") or "").strip().lower()

        if has_email_col:
            if not username or not password_raw or not email:
                return render_template("register.html", error="Kullanıcı adı, e-posta ve şifre zorunludur.",
                                       has_email_col=has_email_col)
            if not EMAIL_RE.match(email):
                return render_template("register.html", error="Geçerli bir e-posta giriniz.",
                                       has_email_col=has_email_col)
        else:
            if not username or not password_raw:
                return render_template("register.html", error="Kullanıcı adı ve şifre zorunludur.",
                                       has_email_col=has_email_col)

        try:
            user = User(
                username=username,
                password=generate_password_hash(password_raw, method="pbkdf2:sha256", salt_length=16),
                **({"email": email} if has_email_col else {})
            )
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("login"))
        except IntegrityError:
            db.session.rollback()
            msg = "Kullanıcı adı"
            if has_email_col:
                msg += " veya e-posta"
            msg += " zaten kayıtlı."
            return render_template("register.html", error=msg, has_email_col=has_email_col)
        except DataError as e:
            db.session.rollback()
            return render_template("register.html", error=f"Veri formatı hatası: {e.orig}",
                                   has_email_col=has_email_col)
        except Exception as e:
            db.session.rollback()
            return render_template("register.html", error=f"Kayıt sırasında hata: {e}",
                                   has_email_col=has_email_col)

    return render_template("register.html", has_email_col=has_email_col)

# --- Login/Logout ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["role"] = user.role
            session["username"] = user.username
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Kullanıcı adı veya şifre hatalı.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- Şifre sıfırlama ---
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    has_email_col = any(c.name == "email" for c in User.__table__.columns)

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        common_msg = "Eğer e-posta kayıtlıysa, sıfırlama linki gönderildi. Gelen kutunu kontrol et."

        if not has_email_col:
            return render_template("forgot_password.html",
                                   error="Bu sistemde e-posta alanı devre dışı. Lütfen yönetici ile iletişime geçin.",
                                   has_email_col=has_email_col), 400

        user = User.query.filter(db.func.lower(User.email) == email).first() if email else None
        if user:
            token = make_reset_token(user.id)
            link = url_for("reset_password", token=token, _external=True)
            body = (
                "Merhaba,\n\n"
                "Şifreni sıfırlamak için aşağıdaki linke tıkla (30 dakika geçerli):\n"
                f"{link}\n\n"
                "Eğer bu isteği sen yapmadıysan bu e-postayı yok sayabilirsin."
            )
            send_mail_plain(user.email, "Görev Takip – Şifre Sıfırlama", body)

        return render_template("forgot_password.html", message=common_msg, has_email_col=has_email_col)

    return render_template("forgot_password.html", has_email_col=has_email_col)

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user_id = parse_reset_token(token)
    if not user_id:
        return render_template("reset_password.html", error="Token geçersiz veya süresi dolmuş."), 400

    user = db.session.get(User, user_id)
    if not user:
        return render_template("reset_password.html", error="Kullanıcı bulunamadı."), 404

    if request.method == "POST":
        pw1 = (request.form.get("password") or "").strip()
        pw2 = (request.form.get("confirm") or "").strip()
        errs = []
        if len(pw1) < 8:
            errs.append("Şifre en az 8 karakter olmalı.")
        if pw1 != pw2:
            errs.append("Şifreler uyuşmuyor.")
        if not any(c.isalpha() for c in pw1) or not any(c.isdigit() for c in pw1):
            errs.append("Şifre harf ve rakam içermeli.")
        if errs:
            return render_template("reset_password.html", error="<br>".join(errs))

        user.password = generate_password_hash(pw1, method="pbkdf2:sha256", salt_length=16)
        db.session.commit()
        return render_template("reset_password.html", message="Şifren güncellendi. Giriş yapabilirsin.")

    return render_template("reset_password.html")

# --- Dashboard / Görevler ---
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    all_users = User.query.order_by(User.username.asc()).all()

    if request.method == "POST":
        t = Task(
            user_id=user_id,
            title=(request.form.get("title") or "").strip(),
            location=(request.form.get("location") or "").strip(),
            materials=(request.form.get("materials") or "").strip(),
            date=(request.form.get("date") or "").strip(),
            needs_support=(request.form.get("needs_support") or "").strip(),
            status=(request.form.get("status") or "Planlandi").strip(),
            assigned_to=int(request.form.get("assigned_to") or user_id),
        )
        db.session.add(t)
        db.session.commit()
        return redirect(url_for("dashboard", **request.args))

    base = Task.query.order_by(Task.id.desc())
    filtered = apply_filters(base, user_id)
    page = max(int(request.args.get("page", 1)), 1)
    tasks, total, pages = paginate(filtered, page, per_page=10)

    return render_template(
        "dashboard.html",
        tasks=tasks,
        all_users=all_users,
        current_user=user_id,
        total=total,
        pages=pages,
        page=page,
        q=request.args.get("q", ""),
        f_status=request.args.get("status", ""),
        mine=request.args.get("mine") == "1",
        f_assigned=request.args.get("assigned", ""),
    )

@app.route("/assigned_tasks")
def assigned_tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_id = session["user_id"]
    tasks = Task.query.filter_by(assigned_to=user_id, completed="Hayir").order_by(Task.id.desc()).all()
    return render_template("assigned_tasks.html", tasks=tasks, current_user=user_id)

@app.route("/completed_tasks")
def completed_tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_id = session["user_id"]
    tasks = Task.query.filter_by(assigned_to=user_id, completed="Evet").order_by(Task.id.desc()).all()
    return render_template("completed_tasks.html", tasks=tasks)

# --- Basit rapor sayfası ---
@app.route("/report")
def report():
    if "user_id" not in session:
        return redirect(url_for("login"))
    tasks = Task.query.order_by(Task.id.desc()).all()
    return render_template("report.html", tasks=tasks)

# --- Excel Export ---
@app.route("/export/excel")
def export_excel():
    if "user_id" not in session:
        return redirect(url_for("login"))
    tasks = Task.query.filter_by(completed="Evet").order_by(Task.id.desc()).all()

    rows = [[
        t.title or "", t.location or "", t.date or "", t.materials or "", t.needs_support or "",
        t.status or "", t.assigner_name or "", t.assignee_name or "", t.completion_note or ""
    ] for t in tasks]

    df = pd.DataFrame(rows, columns=[
        "Görev", "Yer", "Tarih", "Malzemeler", "Destek", "Durum",
        "Görevi Giren", "Atanan", "Açıklama"
    ])

    out = BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Tamamlanan Görevler")
    out.seek(0)

    resp = make_response(out.read())
    resp.headers["Content-Disposition"] = "attachment; filename=rapor.xlsx"
    resp.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return resp

# --- PDF Export (xhtml2pdf) ---
@app.route("/export/pdf")
def export_pdf():
    if "user_id" not in session:
        return redirect(url_for("login"))
    tasks = Task.query.filter_by(completed="Evet").order_by(Task.id.desc()).all()

    html = render_template("report_pdf.html", tasks=tasks)
    pdf_io = BytesIO()
    pisa.CreatePDF(html, dest=pdf_io, encoding="utf-8")
    pdf_io.seek(0)

    resp = make_response(pdf_io.read())
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = "attachment; filename=rapor.pdf"
    return resp

# --- Görev kabul/tamamla/sil ---
@app.route("/accept_task/<int:task_id>", methods=["POST"])
def accept_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_id = session["user_id"]
    task = Task.query.filter_by(id=task_id, assigned_to=user_id).first()
    if task:
        task.accepted = "Evet"
        db.session.commit()
    return redirect(url_for("assigned_tasks"))

@app.route("/complete_task/<int:task_id>", methods=["GET", "POST"])
def complete_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_id = session["user_id"]
    task = Task.query.filter_by(id=task_id, assigned_to=user_id).first()
    if not task:
        return redirect(url_for("assigned_tasks"))
    if request.method == "POST":
        task.completed = "Evet"
        task.completion_note = (request.form.get("note") or "").strip()
        task.status = "Tamamlandi"
        db.session.commit()
        return redirect(url_for("assigned_tasks"))
    return render_template("complete_task.html", task_id=task_id)

@app.route("/delete_task/<int:task_id>", methods=["POST"])
def delete_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_id = session["user_id"]
    role = session.get("role", "user")
    task = Task.query.filter_by(id=task_id).first()
    if task and (task.user_id == user_id or role == "admin"):
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for("dashboard"))

# -------------------------
# Admin: Kullanıcı yönetimi
# -------------------------
@app.route("/admin/users")
def admin_users():
    require_admin()
    users = User.query.order_by(User.id.asc()).all()
    return render_template("users.html", users=users)

@app.route("/admin/users/<int:user_id>/make_admin", methods=["POST"])
def admin_make_admin(user_id):
    require_admin()
    u = User.query.get_or_404(user_id)
    u.role = "admin"
    db.session.commit()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/make_user", methods=["POST"])
def admin_make_user(user_id):
    require_admin()
    if user_id == session.get("user_id"):
        return "Kendi rolünüzü düşüremezsiniz.", 400
    u = User.query.get_or_404(user_id)
    u.role = "user"
    db.session.commit()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id):
    require_admin()
    if user_id == session.get("user_id"):
        return "Kendi hesabınızı silemezsiniz.", 400
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    return redirect(url_for("admin_users"))

# -------------------------
# Tek seferlik admin terfisi (İş bitince SİL!)
# -------------------------
@app.route("/_once/make_me_admin", methods=["POST"])
@require_login
def make_me_admin_once():
    token = request.headers.get("X-PROMOTE-TOKEN") or request.args.get("token")
    expected = os.getenv("PROMOTE_TOKEN")
    if not expected or token != expected:
        abort(403)

    user = db.session.get(User, session["user_id"])
    if not user:
        abort(404)

    already = User.query.filter_by(role="admin").first()
    if already:
        return "Admin zaten var. Bu uç nokta kilitlendi.", 409

    user.role = "admin"
    db.session.commit()
    return "Artık adminsiniz. Bu rotayı ve PROMOTE_TOKEN'ı KALDIRIN!", 200

# -------------------------
# Sağlık ve Teşhis
# -------------------------
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.config import Config

@app.route("/health/alembic")
def health_alembic():
    out = {}
    # DB üzerindeki mevcut rev
    try:
        with db.engine.connect() as conn:
            context = MigrationContext.configure(conn)
            out["db_current_rev"] = context.get_current_revision()
    except Exception as e:
        out["db_current_rev_error"] = str(e)

    # Kod tarafının head rev'i (alembic.ini olmayabilir)
    try:
        ini_path = os.path.join(app.root_path, "alembic.ini")
        if os.path.exists(ini_path):
            cfg = Config(ini_path)
            script = ScriptDirectory.from_config(cfg)
            out["code_head_rev"] = script.get_current_head()
        else:
            out["alembic_ini"] = "missing"
    except Exception as e:
        out["code_head_rev_error"] = str(e)

    try:
        insp = inspect(db.engine)
        out["tables"] = sorted(insp.get_table_names())
    except Exception as e:
        out["tables_error"] = str(e)

    out["app_version"] = APP_VERSION
    return jsonify(out), 200

@app.route("/health/app")
def health_app():
    return jsonify({
        "version": APP_VERSION,
        "branch": os.getenv("RENDER_GIT_BRANCH"),
        "commit": os.getenv("RENDER_GIT_COMMIT"),
        "time": datetime.now(timezone.utc).isoformat()
    }), 200

@app.route("/health/db")
def health_db():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500

@app.route("/health/db_url")
def health_db_url():
    url = app.config.get("SQLALCHEMY_DATABASE_URI", "not-set")
    safe = url
    if "://" in url and "@" in url:
        prefix, rest = url.split("://", 1)
        safe = f"{prefix}://****:****@" + rest.split("@", 1)[1]
    return jsonify({"db": safe}), 200

# Opsiyonel bootstrap (geliştirme için)
with app.app_context():
    if os.getenv("AUTO_BOOTSTRAP") == "1":
        insp = inspect(db.engine)
        if not insp.has_table("users") or not insp.has_table("tasks"):
            db.create_all()

# 403
@app.errorhandler(403)
def forbidden(_):
    return render_template("403.html"), 403

if __name__ == "__main__":
    app.run(debug=True)
