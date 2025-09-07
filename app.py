from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import or_, text, inspect
from sqlalchemy.exc import IntegrityError, DataError
from functools import wraps
import os, re, secrets, base64
from urllib.parse import urlparse, unquote
import pandas as pd
from io import BytesIO
from xhtml2pdf import pisa
from math import ceil
from datetime import datetime

# --- PDF font kayıtları için ---
from pathlib import Path
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.pdfmetrics import registerFontFamily

# --- Mail & Token yardımcıları ---
import smtplib
from email.mime.text import MIMEText  # <-- DOĞRU İTHALAT
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# -------------------------------------------------
# Flask & DB config
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "gizli_anahtar")

app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True

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

# --- Mail ENV (Gmail uygulama şifresi) ---
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


# --- Token yardımcıları ---
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


# Basit e-posta regex
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# -------------------------------------------------
# MODELLER
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
    location = db.Column(db.String(200))   # düzeltildi
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
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    mine = request.args.get("mine") == "1"
    assigned = request.args.get("assigned", "").strip()

    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(Task.title.ilike(like), Task.location.ilike(like), Task.materials.ilike(like))
        )
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
# Durum kanonikleştirme
# -------------------------------------------------
def canonical_status(value: str) -> str | None:
    s = (value or "").strip().lower()
    s_norm = (
        s.replace("ı", "i").replace("ş", "s").replace("ğ", "g")
         .replace("ü", "u").replace("ö", "o").replace("ç", "c")
    )
    tamam = {"tamamlandi", "tamamlandı", "completed", "complete", "done", "bitti", "evet"}
    devam  = {"devamediyor", "devam ediyor", "in-progress", "progress", "doing", "calisiliyor", "calisiyor"}
    plan   = {"planlandi", "planlandı", "planned", "planli", "planlı", "todo", "pending", "beklemede", "bekliyor", "hayir"}

    if s in tamam or s_norm in tamam:
        return "Tamamlandi"
    if s in devam or s_norm in devam:
        return "DevamEdiyor"
    if s in plan or s_norm in plan:
        return "Planlandi"
    if s in {"planlandi", "devamediyor", "tamamlandi"}:
        return s[0].upper() + s[1:]
    return None


# -------------------------------------------------
# ROUTES
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
                return render_template(
                    "register.html",
                    error="Kullanıcı adı, e-posta ve şifre zorunludur.",
                    has_email_col=has_email_col,
                )
            if not EMAIL_RE.match(email):
                return render_template(
                    "register.html", error="Geçerli bir e-posta giriniz.", has_email_col=has_email_col
                )
        else:
            if not username or not password_raw:
                return render_template(
                    "register.html",
                    error="Kullanıcı adı ve şifre zorunludur.",
                    has_email_col=has_email_col,
                )

        try:
            user = User(
                username=username,
                password=generate_password_hash(password_raw, method="pbkdf2:sha256", salt_length=16),
                **({"email": email} if has_email_col else {}),
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
        except Exception as e:
            db.session.rollback()
            return render_template(
                "register.html", error=f"Kayıt sırasında hata: {e}", has_email_col=has_email_col
            )

    return render_template("register.html", has_email_col=has_email_col)


# --- Login ---
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


# --- Logout ---
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
            return (
                render_template(
                    "forgot_password.html",
                    error="Bu sistemde e-posta alanı devre dışı. Yönetici ile iletişime geçin.",
                    has_email_col=has_email_col,
                ),
                400,
            )

        user = User.query.filter(db.func.lower(User.email) == email).first() if email else None
        if user:
            token = make_reset_token(user.id)
            link = url_for("reset_password", token=token, _external=True)
            body = (
                "Merhaba,\n\n"
                "Şifreni sıfırlamak için aşağıdaki linke tıkla (30 dk geçerli):\n"
                f"{link}\n\n"
                "Bu isteği sen yapmadıysan yok sayabilirsin."
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
            errs.append("Şifre hem harf hem rakam içermeli.")
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

    total_tasks = db.session.query(Task).count()
    planned_tasks = db.session.query(Task).filter_by(status="Planlandi").count()
    ongoing_tasks = db.session.query(Task).filter_by(status="DevamEdiyor").count()
    completed_tasks = db.session.query(Task).filter(or_(Task.status == "Tamamlandi", Task.completed == "Evet")).count()

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
        total_tasks=total_tasks,
        ongoing_tasks=ongoing_tasks,
        completed_tasks=completed_tasks,
        planned_tasks=planned_tasks,
    )


# --- JSON API: durum güncelle ---
@app.route("/api/tasks/<int:task_id>/status", methods=["POST"])
@require_login
def api_update_task_status(task_id: int):
    data = request.get_json(silent=True) or request.form
    new_status_raw = (data.get("status") or "").strip()
    new_status = canonical_status(new_status_raw)

    if not new_status:
        return jsonify(ok=False, error="Geçersiz durum değeri."), 400

    task = Task.query.get_or_404(task_id)
    uid = session["user_id"]
    role = session.get("role", "user")

    if not (task.user_id == uid or task.assigned_to == uid or role == "admin"):
        return jsonify(ok=False, error="Bu görevi güncelleme yetkiniz yok."), 403

    task.status = new_status
    if new_status == "Tamamlandi":
        task.completed = "Evet"
    db.session.commit()

    counts = {
        "total": db.session.query(Task).count(),
        "planned": db.session.query(Task).filter_by(status="Planlandi").count(),
        "ongoing": db.session.query(Task).filter_by(status="DevamEdiyor").count(),
        "completed": db.session.query(Task).filter(
            or_(Task.status == "Tamamlandi", Task.completed == "Evet")
        ).count(),
    }
    return jsonify(ok=True, status=new_status, counts=counts), 200


# --- Atanan görevler ---
@app.route("/assigned_tasks")
def assigned_tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_id = session["user_id"]
    tasks = Task.query.filter_by(assigned_to=user_id, completed="Hayir").order_by(Task.id.desc()).all()
    return render_template("assigned_tasks.html", tasks=tasks, current_user=user_id)


# --- Tamamlanan görevler ---
@app.route("/completed_tasks")
def completed_tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_id = session["user_id"]
    tasks = Task.query.filter_by(assigned_to=user_id, completed="Evet").order_by(Task.id.desc()).all()
    return render_template("completed_tasks.html", tasks=tasks)


# --- Rapor (filtreli + KPI sayıları) ---
@app.route("/report")
def report():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    all_users = User.query.order_by(User.username.asc()).all()

    q          = (request.args.get("q") or "").strip()
    f_status   = (request.args.get("status") or "").strip()
    f_assigned = (request.args.get("assigned") or "").strip()
    date_from  = (request.args.get("from") or "").strip()
    date_to    = (request.args.get("to") or "").strip()
    mine       = request.args.get("mine") == "1"

    query = Task.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            Task.title.ilike(like),
            Task.location.ilike(like),
            Task.materials.ilike(like),
        ))
    if f_status:
        query = query.filter(Task.status == f_status)
    if f_assigned.isdigit():
        query = query.filter(Task.assigned_to == int(f_assigned))
    if mine:
        query = query.filter(or_(Task.user_id == user_id, Task.assigned_to == user_id))
    if date_from:
        query = query.filter(Task.date >= date_from)
    if date_to:
        query = query.filter(Task.date <= date_to)

    tasks = query.order_by(Task.id.desc()).all()

    total_tasks     = db.session.query(Task).count()
    planned_tasks   = db.session.query(Task).filter_by(status="Planlandi").count()
    ongoing_tasks   = db.session.query(Task).filter_by(status="DevamEdiyor").count()
    completed_tasks = db.session.query(Task).filter(
        or_(Task.status == "Tamamlandi", Task.completed == "Evet")
    ).count()

    return render_template(
        "report.html",
        tasks=tasks,
        all_users=all_users,
        q=q, f_status=f_status, f_assigned=f_assigned,
        date_from=date_from, date_to=date_to, mine=mine,
        total_tasks=total_tasks,
        planned_tasks=planned_tasks,
        ongoing_tasks=ongoing_tasks,
        completed_tasks=completed_tasks,
    )


# --- Excel Export (rapor filtreleri ile) ---
@app.route("/export/excel", endpoint="export_excel")
def export_excel():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    q          = (request.args.get("q") or "").strip()
    f_status   = (request.args.get("status") or "").strip()
    f_assigned = (request.args.get("assigned") or "").strip()
    date_from  = (request.args.get("from") or "").strip()
    date_to    = (request.args.get("to") or "").strip()
    mine       = request.args.get("mine") == "1"

    query = Task.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            Task.title.ilike(like),
            Task.location.ilike(like),
            Task.materials.ilike(like),
        ))
    if f_status:
        query = query.filter(Task.status == f_status)
    if f_assigned.isdigit():
        query = query.filter(Task.assigned_to == int(f_assigned))
    if mine:
        query = query.filter(or_(Task.user_id == user_id, Task.assigned_to == user_id))
    if date_from:
        query = query.filter(Task.date >= date_from)
    if date_to:
        query = query.filter(Task.date <= date_to)

    tasks = query.order_by(Task.id.desc()).all()

    rows = []
    for t in tasks:
        rows.append([
            t.title or "", t.location or "", t.date or "", t.status or "",
            t.materials or "", t.needs_support or "",
            t.assignee_name or "", t.assigner_name or "", t.completion_note or "",
        ])

    df = pd.DataFrame(
        rows,
        columns=[
            "Görev", "Yer", "Tarih", "Durum",
            "Malzemeler", "Destek Birimi",
            "Atanan", "Görevi Giren", "Açıklama"
        ],
    )

    out = BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Rapor")
    out.seek(0)

    resp = make_response(out.read())
    resp.headers["Content-Disposition"] = "attachment; filename=rapor.xlsx"
    resp.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return resp


# --- xhtml2pdf: link çözümleyici ---
def _pisa_link_callback(uri, rel):
    if uri.startswith(("http://", "https://", "data:")):
        return uri

    if uri.startswith("file://"):
        p = urlparse(uri)
        path = unquote(p.path)
        if os.name == "nt" and path.startswith("/"):
            path = path[1:]
        return path

    if uri.startswith("/static/"):
        return os.path.join(app.root_path, uri.lstrip("/"))
    if uri.startswith("static/"):
        return os.path.join(app.root_path, uri)
    return os.path.join(app.root_path, uri.lstrip("/"))


# --- ReportLab için font register (mevcut /export/pdf kullanıyor) ---
def _register_pdf_fonts_once():
    if app.config.get("PDF_FONTS_READY"):
        return
    font_dir = Path(app.root_path) / "static" / "fonts"
    regular = font_dir / "DejaVuSans.ttf"
    bold    = font_dir / "DejaVuSans-Bold.ttf"
    italic  = font_dir / "DejaVuSans-Oblique.ttf"
    boldit  = font_dir / "DejaVuSans-BoldOblique.ttf"

    if regular.exists():
        pdfmetrics.registerFont(TTFont("TRSans", str(regular)))
        pdfmetrics.registerFont(TTFont("DejaVuSans", str(regular)))
    if bold.exists():
        pdfmetrics.registerFont(TTFont("TRSans-Bold", str(bold)))
        pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", str(bold)))
    if italic.exists():
        pdfmetrics.registerFont(TTFont("TRSans-Italic", str(italic)))
        pdfmetrics.registerFont(TTFont("DejaVuSans-Italic", str(italic)))
    if boldit.exists():
        pdfmetrics.registerFont(TTFont("TRSans-BoldItalic", str(boldit)))
        pdfmetrics.registerFont(TTFont("DejaVuSans-BoldItalic", str(boldit)))

    registerFontFamily(
        "TRSans",
        normal="TRSans",
        bold="TRSans-Bold" if bold.exists() else "TRSans",
        italic="TRSans-Italic" if italic.exists() else "TRSans",
        boldItalic="TRSans-BoldItalic" if boldit.exists() else ("TRSans-Bold" if bold.exists() else "TRSans"),
    )
    registerFontFamily(
        "DejaVuSans",
        normal="DejaVuSans",
        bold="DejaVuSans-Bold" if bold.exists() else "DejaVuSans",
        italic="DejaVuSans-Italic" if italic.exists() else "DejaVuSans",
        boldItalic="DejaVuSans-BoldItalic" if boldit.exists() else ("DejaVuSans-Bold" if bold.exists() else "DejaVuSans"),
    )
    app.config["PDF_FONTS_READY"] = True


# --- Export PDF (xhtml2pdf) ---
@app.route("/export/pdf")
def export_pdf():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    q          = (request.args.get("q") or "").strip()
    f_status   = (request.args.get("status") or "").strip()
    f_assigned = (request.args.get("assigned") or "").strip()
    date_from  = (request.args.get("from") or "").strip()
    date_to    = (request.args.get("to") or "").strip()
    mine       = request.args.get("mine") == "1"

    query = Task.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Task.title.ilike(like),
                                 Task.location.ilike(like),
                                 Task.materials.ilike(like)))
    if f_status:
        query = query.filter(Task.status == f_status)
    if f_assigned.isdigit():
        query = query.filter(Task.assigned_to == int(f_assigned))
    if mine:
        query = query.filter(or_(Task.user_id == user_id, Task.assigned_to == user_id))
    if date_from:
        query = query.filter(Task.date >= date_from)
    if date_to:
        query = query.filter(Task.date <= date_to)

    tasks = query.order_by(Task.id.desc()).all()

    kpi = {
        "total":     len(tasks),
        "planned":   sum(1 for t in tasks if t.status == "Planlandi"),
        "ongoing":   sum(1 for t in tasks if t.status == "DevamEdiyor"),
        "completed": sum(1 for t in tasks if t.status == "Tamamlandi" or t.completed == "Evet"),
    }

    root = Path(app.root_path)
    logo_file = None
    for ext in ("png", "jpg", "jpeg", "webp"):
        p = root / "static" / "images" / f"karacabey-logo.{ext}"
        if p.exists():
            logo_file = p
            break
    logo_url = logo_file.resolve().as_uri() if logo_file else ""

    _register_pdf_fonts_once()

    context = {
        "tasks": tasks,
        "kpi": kpi,
        "generated_at": datetime.now(),
        "org_title": os.getenv("ORG_TITLE", "BIM Görev Takip"),
        "logo_url": logo_url,
        "font_regular_url": "",
        "font_bold_url": "",
        "q": q, "f_status": f_status, "f_assigned": f_assigned,
        "date_from": date_from, "date_to": date_to, "mine": mine,
    }

    html = render_template("report_pdf.html", **context)
    pdf_io = BytesIO()
    pisa.CreatePDF(src=html, dest=pdf_io, link_callback=_pisa_link_callback, encoding="utf-8")
    pdf_io.seek(0)

    resp = make_response(pdf_io.read())
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = "attachment; filename=rapor.pdf"
    return resp


# ---------- YENİ: wkhtmltopdf + pdfkit ile TÜRKÇE %100 (base64 font gömme) ----------
def _wkhtmltopdf_config():
    """
    wkhtmltopdf yolunu bulur:
    - WKHTMLTOPDF_BIN ortam değişkeni
    - Windows varsayılan kurulum yolu
    - Linux/Mac için 'wkhtmltopdf' (PATH)
    """
    try:
        import pdfkit  # iç import
    except Exception:
        return None, "pdfkit yüklü değil (pip install pdfkit)."

    custom = os.getenv("WKHTMLTOPDF_BIN")
    candidates = []
    if custom:
        candidates.append(custom)
    if os.name == "nt":
        candidates += [
            r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe",
            r"C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe",
        ]
    else:
        candidates += ["wkhtmltopdf"]  # PATH’teyse

    exe_path = None
    for c in candidates:
        if os.path.isfile(c) or c == "wkhtmltopdf":
            exe_path = c
            break

    try:
        cfg = pdfkit.configuration(wkhtmltopdf=exe_path) if exe_path != "wkhtmltopdf" else pdfkit.configuration()
        return cfg, None
    except Exception as e:
        return None, f"wkhtmltopdf bulunamadı: {e}"


@app.route("/export/pdf2")
def export_pdf2():
    """wkhtmltopdf ile PDF (Türkçe karakter sorunsuz, base64 gömülü font)"""
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    q          = (request.args.get("q") or "").strip()
    f_status   = (request.args.get("status") or "").strip()
    f_assigned = (request.args.get("assigned") or "").strip()
    date_from  = (request.args.get("from") or "").strip()
    date_to    = (request.args.get("to") or "").strip()
    mine       = request.args.get("mine") == "1"

    query = Task.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Task.title.ilike(like),
                                 Task.location.ilike(like),
                                 Task.materials.ilike(like)))
    if f_status:
        query = query.filter(Task.status == f_status)
    if f_assigned.isdigit():
        query = query.filter(Task.assigned_to == int(f_assigned))
    if mine:
        query = query.filter(or_(Task.user_id == user_id, Task.assigned_to == user_id))
    if date_from:
        query = query.filter(Task.date >= date_from)
    if date_to:
        query = query.filter(Task.date <= date_to)

    tasks = query.order_by(Task.id.desc()).all()

    kpi = {
        "total":     len(tasks),
        "planned":   sum(1 for t in tasks if t.status == "Planlandi"),
        "ongoing":   sum(1 for t in tasks if t.status == "DevamEdiyor"),
        "completed": sum(1 for t in tasks if t.status == "Tamamlandi" or t.completed == "Evet"),
    }

    root = Path(app.root_path)
    # Logo (varsa)
    logo_file = None
    for ext in ("png", "jpg", "jpeg", "webp"):
        p = root / "static" / "images" / f"karacabey-logo.{ext}"
        if p.exists():
            logo_file = p
            break
    logo_url = logo_file.resolve().as_uri() if logo_file else ""

    # --- FONTLARI BASE64 GÖM ---
    font_dir = root / "static" / "fonts"

    def _b64(p: Path) -> str:
        try:
            return base64.b64encode(p.read_bytes()).decode("ascii")
        except Exception:
            return ""

    font_regular_b64 = _b64(font_dir / "DejaVuSans.ttf")
    font_bold_b64    = _b64(font_dir / "DejaVuSans-Bold.ttf")
    font_italic_b64  = _b64(font_dir / "DejaVuSans-Oblique.ttf")
    font_boldit_b64  = _b64(font_dir / "DejaVuSans-BoldOblique.ttf")

    context = {
        "tasks": tasks,
        "kpi": kpi,
        "generated_at": datetime.now(),
        "org_title": os.getenv("ORG_TITLE", "BIM Görev Takip"),
        "logo_url": logo_url,
        # BASE64 değişkenleri (şablon bunları kullanacak)
        "font_regular_b64": font_regular_b64,
        "font_bold_b64":    font_bold_b64,
        "font_italic_b64":  font_italic_b64,
        "font_boldit_b64":  font_boldit_b64,
    }

    html = render_template("report_pdf_wk.html", **context)

    try:
        import pdfkit
    except Exception:
        return "pdfkit kurulu değil. Lütfen 'pip install pdfkit' yükleyin.", 500

    cfg, err = _wkhtmltopdf_config()
    if err:
        return err, 500

    options = {
        "encoding": "UTF-8",
        "page-size": "A4",
        "margin-top": "12mm",
        "margin-right": "10mm",
        "margin-bottom": "14mm",
        "margin-left": "10mm",
        "enable-local-file-access": None,  # base64 için şart değil ama dursun
        "viewport-size": "1280x1024",
        "dpi": 300,
    }

    pdf_bytes = pdfkit.from_string(html, False, options=options, configuration=cfg)
    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = "attachment; filename=rapor.pdf"
    return resp
# ----------------------------------------------------------------------


# --- Görev silme ---
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


# --- Admin: Kullanıcı Yönetimi ---
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


# --- Tek seferlik admin terfisi ---
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


# --- Alembic & DB Health ---
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.config import Config


@app.route("/health/alembic")
def health_alembic():
    out = {}
    with db.engine.connect() as conn:
        context = MigrationContext.configure(conn)
        out["db_current_rev"] = context.get_current_revision()
    cfg = Config("alembic.ini")
    script = ScriptDirectory.from_config(cfg)
    out["code_head_rev"] = script.get_current_head()
    insp = inspect(db.engine)
    out["tables"] = sorted(insp.get_table_names())
    return jsonify(out), 200


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


# --- AUTO BOOTSTRAP ---
with app.app_context():
    if os.getenv("AUTO_BOOTSTRAP") == "1":
        insp = inspect(db.engine)
        if not insp.has_table("users") or not insp.has_table("tasks"):
            db.create_all()


# --- 403 Template ---
@app.errorhandler(403)
def forbidden(_):
    return render_template("403.html"), 403


# --- Main ---
if __name__ == "__main__":
    app.run(debug=True)
