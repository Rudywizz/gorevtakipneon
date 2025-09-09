from flask import (
    Flask, render_template, request, redirect, url_for, session,
    make_response, jsonify, abort, flash, current_app, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import or_, text, inspect
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, ProgrammingError
from functools import wraps
from datetime import datetime, date
import os
import re
import pandas as pd
from io import BytesIO
from xhtml2pdf import pisa
from math import ceil
from types import SimpleNamespace

# ReportLab – font kaydı
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.rl_config import TTFSearchPath

# --- Mail & Token yardımcıları ---
import smtplib
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import secrets

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "gizli_anahtar")

# -------------------------------------------------
# DB config (Postgres/SQLite)
# -------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'gorev_takip.db')}"

_db_url_final = DATABASE_URL or ""
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
app.config.setdefault("APP_VERSION", "local-dev")

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- DB HOTFIX: users tablosuna eksik kolonları ekle + NULL'ları doldur ---
with app.app_context():
    try:
        eng = db.engine
        insp = inspect(eng)
        if insp.has_table("users"):
            existing_cols = {c["name"] for c in insp.get_columns("users")}
            dialect = eng.dialect.name  # "sqlite", "postgresql", ...
            is_sqlite = dialect == "sqlite"
            is_pg = dialect == "postgresql"

            add_is_active = "is_active" not in existing_cols
            add_mcp = "must_change_password" not in existing_cols

            # Kolon ekleme
            if add_is_active or add_mcp:
                with eng.begin() as conn:
                    if add_is_active:
                        if is_pg:
                            conn.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE"))
                        else:
                            conn.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1"))
                    if add_mcp:
                        if is_pg:
                            conn.execute(text("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE"))
                        else:
                            conn.execute(text("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0"))

            # NULL değerleri güvenli default'a çek
            if add_is_active or add_mcp:
                with eng.begin() as conn:
                    if is_pg:
                        conn.execute(text("UPDATE users SET is_active=TRUE WHERE is_active IS NULL"))
                        conn.execute(text("UPDATE users SET must_change_password=FALSE WHERE must_change_password IS NULL"))
                    else:
                        conn.execute(text("UPDATE users SET is_active=1 WHERE is_active IS NULL"))
                        conn.execute(text("UPDATE users SET must_change_password=0 WHERE must_change_password IS NULL"))
    except Exception as e:
        app.logger.exception(f"DB hotfix failed: {e}")

# --- Template'te config erişimi için ---
@app.context_processor
def inject_globals():
    return {"config": app.config}

# --- Jinja filtresi: güvenli tarih formatlama ---
@app.template_filter('safe_date')
def safe_date(value):
    if not value:
        return ""
    if isinstance(value, (date, datetime)):
        return value.strftime("%Y-%m-%d")
    try:
        return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d")
    except Exception:
        return str(value)

# -------------------------------------------------
# DejaVuSans fontları
# -------------------------------------------------
def register_pdf_fonts():
    try:
        fonts_dir = os.path.join(app.root_path, "static", "fonts")
        normal_path = os.path.join(fonts_dir, "DejaVuSans.ttf")
        bold_path   = os.path.join(fonts_dir, "DejaVuSans-Bold.ttf")
        if fonts_dir not in TTFSearchPath:
            TTFSearchPath.append(fonts_dir)
        registered = set(pdfmetrics.getRegisteredFontNames())
        if "DejaVuSans" not in registered:
            pdfmetrics.registerFont(TTFont("DejaVuSans", normal_path))
        if "DejaVuSans-Bold" not in registered:
            pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", bold_path))
        pdfmetrics.registerFontFamily("DejaVuSans", normal="DejaVuSans", bold="DejaVuSans-Bold")
    except Exception as e:
        app.logger.exception(f"Font register hatası: {e}")

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

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# -------------------------------------------------
# Modeller
# -------------------------------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True)  # migration ile NOT NULL önerilir
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")  # user / admin
    # yeni alanlar
    is_active = db.Column(db.Boolean, nullable=False, server_default="1")        # True: aktif
    must_change_password = db.Column(db.Boolean, nullable=False, server_default="0")  # True: ilk girişte zorla değiştir

    tasks_created = db.relationship("Task", foreign_keys="Task.user_id", backref="assigner", lazy=True)
    tasks_assigned = db.relationship("Task", foreign_keys="Task.assigned_to", backref="assignee", lazy=True)

class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(200))
    location = db.Column(db.String(200))
    materials = db.Column(db.Text)
    date = db.Column(db.String(50))  # string tutuluyor
    needs_support = db.Column(db.String(50))
    status = db.Column(db.String(50))
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))
    accepted = db.Column(db.String(20), default="Bekliyor")  # Evet/Bekliyor
    completed = db.Column(db.String(20), default="Hayir")    # Evet/Hayir
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
def _user_flag_cols_exist() -> bool:
    """users tablosunda is_active / must_change_password var mı?"""
    try:
        insp = inspect(db.engine)
        cols = {c["name"] for c in insp.get_columns("users")}
        return "is_active" in cols and "must_change_password" in cols
    except Exception:
        return False

@app.before_request
def refresh_role():
    """Kolonlar eksikse patlamayı önle ve minimum alanlarla session güncelle."""
    uid = session.get("user_id")
    if not uid:
        return
    try:
        if not _user_flag_cols_exist():
            row = db.session.execute(
                text("SELECT id, username, role FROM users WHERE id=:id"),
                {"id": uid}
            ).first()
            if row:
                session["role"] = row.role
                session["username"] = row.username
            return
        # Kolonlar tam ise ORM
        u = User.query.get(uid)
        if u:
            session["role"] = u.role
            session["username"] = u.username
    except (OperationalError, ProgrammingError):
        return

def apply_filters(query, user_id):
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    mine = request.args.get("mine") == "1"
    assigned = (request.args.get("assigned") or "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Task.title.ilike(like),
                                 Task.location.ilike(like),
                                 Task.materials.ilike(like)))
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
    if 'user_id' not in session or session.get("role") != "admin":
        abort(403)

def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

# --- Sayaçlar ---
def dashboard_stats():
    total = db.session.query(db.func.count(Task.id)).scalar() or 0
    completed = db.session.query(db.func.count(Task.id)).filter(
        or_(Task.completed == "Evet", Task.status.ilike("%tamam%"))
    ).scalar() or 0
    planned = db.session.query(db.func.count(Task.id)).filter(Task.status.ilike("%plan%")).scalar() or 0
    in_progress = db.session.query(db.func.count(Task.id)).filter(
        Task.completed != "Evet"
    ).filter(
        or_(
            Task.status.ilike("%devam%"),
            Task.status.ilike("%bekle%"),
            Task.status.ilike("%çalış%"),
            Task.status.ilike("%calis%"),
            Task.accepted == "Evet",
        )
    ).scalar() or 0
    open_tasks = db.session.query(db.func.count(Task.id)).filter(
        or_(Task.completed != "Evet", Task.completed.is_(None))
    ).scalar() or 0
    return {"total": total, "completed": completed, "planned": planned,
            "in_progress": in_progress, "open": open_tasks}

# -------------------------------------------------
# PDF link_callback
# -------------------------------------------------
def xhtml2pdf_link_callback(uri, rel):
    try:
        if uri.startswith(("http://", "https://", "data:")):
            return uri
        root = current_app.root_path
        if uri.startswith("file://"):
            return uri.replace("file://", "")
        if uri.startswith("/static/"):
            path = os.path.join(root, uri.lstrip("/"))
            return path if os.path.isfile(path) else uri
        if uri.startswith("static/"):
            path = os.path.join(root, uri)
            return path if os.path.isfile(path) else uri
        if uri.startswith("/"):
            path = os.path.join(root, uri.lstrip("/"))
            return path if os.path.isfile(path) else uri
        path = os.path.join(root, uri)
        return path if os.path.isfile(path) else uri
    except Exception as e:
        current_app.logger.exception(f"[xhtml2pdf] link_callback hata: {uri} -> {e}")
        return uri

# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'user_id' in session else redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    has_email_col = any(c.name == "email" for c in User.__table__.columns)
    if request.method == 'POST':
        username = (request.form.get('username') or "").strip()
        password_raw = request.form.get('password') or ""
        email = (request.form.get('email') or "").strip().lower()
        if has_email_col:
            if not username or not password_raw or not email:
                return render_template('register.html', error="Kullanıcı adı, e-posta ve şifre zorunludur.",
                                       has_email_col=has_email_col)
            if not EMAIL_RE.match(email):
                return render_template('register.html', error="Geçerli bir e-posta giriniz.",
                                       has_email_col=has_email_col)
        else:
            if not username or not password_raw:
                return render_template('register.html', error="Kullanıcı adı ve şifre zorunludur.",
                                       has_email_col=has_email_col)
        try:
            user = User(
                username=username,
                password=generate_password_hash(password_raw, method="pbkdf2:sha256", salt_length=16),
                **({"email": email} if has_email_col else {})
            )
            db.session.add(user); db.session.commit()
            flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            msg = "Kullanıcı adı"
            if has_email_col: msg += " veya e-posta"
            msg += " zaten kayıtlı."
            return render_template('register.html', error=msg, has_email_col=has_email_col)
        except DataError as e:
            db.session.rollback()
            return render_template('register.html', error=f"Veri formatı hatası: {e.orig}", has_email_col=has_email_col)
        except Exception as e:
            db.session.rollback()
            return render_template('register.html', error=f"Kayıt sırasında hata: {e}", has_email_col=has_email_col)
    return render_template('register.html', has_email_col=has_email_col)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or "").strip()
        password = request.form.get('password') or ""

        # Kolonlar eksikse: minimum alanlarla ham SQL, aktiflik/zorunlu değişim kontrolünü atla
        if not _user_flag_cols_exist():
            row = db.session.execute(
                text("SELECT id, username, password, role FROM users WHERE username=:u LIMIT 1"),
                {"u": username}
            ).first()
            if row and check_password_hash(row.password, password):
                session['user_id'] = row.id
                session['role'] = row.role
                session['username'] = row.username
                return redirect(url_for('dashboard'))
            return render_template('login.html', error="Kullanıcı adı veya şifre hatalı.")

        # Kolonlar varsa normal ORM akışı
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # None olursa kilitlenmesin
            if user.is_active is False:
                return render_template('login.html', error="Hesabınız pasif durumdadır. Lütfen yönetici ile iletişime geçin.")
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            if user.must_change_password:
                return redirect(url_for('force_password_change'))
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Kullanıcı adı veya şifre hatalı.")
    return render_template('login.html')

# Kullanıcı kendi zorunlu şifre değişimi
@app.route("/account/force_password_change", methods=["GET", "POST"])
@require_login
def force_password_change():
    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        pw1 = (request.form.get("password") or "").strip()
        pw2 = (request.form.get("confirm") or "").strip()
        errs = []
        if len(pw1) < 8: errs.append("Şifre en az 8 karakter olmalı.")
        if pw1 != pw2: errs.append("Şifreler uyuşmuyor.")
        if not any(c.isalpha() for c in pw1) or not any(c.isdigit() for c in pw1):
            errs.append("Şifre harf ve rakam içermeli.")
        if errs: return render_template("force_password_change.html", error="<br>".join(errs))
        user.password = generate_password_hash(pw1, method="pbkdf2:sha256", salt_length=16)
        user.must_change_password = False
        db.session.commit()
        flash("Şifren güncellendi.", "success")
        return redirect(url_for("dashboard"))
    if not user.must_change_password:
        return redirect(url_for("dashboard"))
    return render_template("force_password_change.html")

# --- Şifre sıfırlama: e-posta ile ---
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
            body = ("Merhaba,\n\nŞifreni sıfırlamak için aşağıdaki linke tıkla (30 dakika geçerli):\n"
                    f"{link}\n\nEğer bu isteği sen yapmadıysan bu e-postayı yok sayabilirsin.")
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
        if len(pw1) < 8: errs.append("Şifre en az 8 karakter olmalı.")
        if pw1 != pw2: errs.append("Şifreler uyuşmuyor.")
        if not any(c.isalpha() for c in pw1) or not any(c.isdigit() for c in pw1):
            errs.append("Şifre harf ve rakam içermeli.")
        if errs: return render_template("reset_password.html", error="<br>".join(errs))
        user.password = generate_password_hash(pw1, method="pbkdf2:sha256", salt_length=16)
        user.must_change_password = False
        db.session.commit()
        return render_template("reset_password.html", message="Şifren güncellendi. Giriş yapabilirsin.")
    return render_template("reset_password.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']

    # --- KOLONLAR YOKSA: all_users ham SQL ile (id, username) ---
    if not _user_flag_cols_exist():
        rows = db.session.execute(
            text("SELECT id, username FROM users ORDER BY username ASC")
        ).fetchall()
        all_users = [SimpleNamespace(id=r.id, username=r.username) for r in rows]
    else:
        all_users = User.query.order_by(User.username.asc()).all()

    if request.method == 'POST':
        t = Task(
            user_id=user_id,
            title=(request.form.get('title') or "").strip(),
            location=(request.form.get('location') or "").strip(),
            materials=(request.form.get('materials') or "").strip(),
            date=(request.form.get('date') or "").strip(),
            needs_support=(request.form.get('needs_support') or "").strip(),
            status=(request.form.get('status') or "").strip(),
            assigned_to=int(request.form.get('assigned_to') or user_id)
        )
        db.session.add(t); db.session.commit()
        flash("Görev oluşturuldu.", "success")
        return redirect(url_for('dashboard', **request.args))

    base = Task.query.order_by(Task.id.desc())
    filtered = apply_filters(base, user_id)
    page = max(int(request.args.get("page", 1)), 1)
    tasks, total, pages = paginate(filtered, page, per_page=10)
    stats = dashboard_stats()
    return render_template('dashboard.html',
        tasks=tasks, all_users=all_users, current_user=user_id,
        total=total, pages=pages, page=page,
        q=request.args.get("q", ""), f_status=request.args.get("status", ""),
        mine=request.args.get("mine") == "1", f_assigned=request.args.get("assigned", ""),
        stats=stats)

@app.route('/assigned_tasks')
def assigned_tasks():
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']
    tasks = Task.query.filter_by(assigned_to=user_id, completed="Hayir").order_by(Task.id.desc()).all()
    return render_template('assigned_tasks.html', tasks=tasks, current_user=user_id)

@app.route('/completed_tasks')
def completed_tasks():
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']
    tasks = Task.query.filter_by(assigned_to=user_id, completed="Evet").order_by(Task.id.desc()).all()
    return render_template('completed_tasks.html', tasks=tasks)

@app.route('/report')
def report():
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']
    start_date = (request.args.get("start_date") or "").strip()
    end_date   = (request.args.get("end_date") or "").strip()
    statuses   = request.args.getlist("statuses")
    mine       = request.args.get("mine") == "1"
    assigned   = request.args.get("assigned", "")
    base = Task.query.order_by(Task.id.desc())
    tasks = apply_filters(base, user_id).all()
    return render_template('report.html',
        tasks=tasks, generated_at=datetime.now().strftime("%d.%m.%Y %H:%M"),
        start_date=start_date, end_date=end_date, statuses=statuses,
        mine=mine, assigned=assigned,
        ALL_STATUSES=["planned", "waiting", "in_progress", "done", "cancelled"])

@app.route('/export/excel')
def export_excel():
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']
    base = Task.query.filter_by(completed="Evet").order_by(Task.id.desc())
    tasks = apply_filters(base, user_id).all()
    rows = [[
        t.title, t.location, t.date, t.materials, t.needs_support, t.status,
        t.assigner_name, t.assignee_name, t.completion_note or ""
    ] for t in tasks]
    df = pd.DataFrame(rows, columns=[
        "Görev", "Yer", "Tarih", "Malzemeler", "Destek", "Durum",
        "Gorevi_Giren", "Atanan", "Aciklama"
    ])
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Tamamlanan Görevler")
    output.seek(0)
    resp = make_response(output.read())
    resp.headers["Content-Disposition"] = "attachment; filename=rapor.xlsx"
    resp.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return resp

@app.route('/export/pdf')
def export_pdf():
    if 'user_id' not in session: return redirect(url_for('login'))
    register_pdf_fonts(); pisa.DEFAULT_FONT = "DejaVuSans"
    user_id = session['user_id']
    base = Task.query.filter_by(completed="Evet").order_by(Task.id.desc())
    tasks = apply_filters(base, user_id).all()
    html = render_template("report_pdf.html",
        tasks=tasks, generated_at=datetime.now().strftime("%d.%m.%Y %H:%M"))
    pdf_io = BytesIO()
    try:
        result = pisa.CreatePDF(src=html, dest=pdf_io, encoding="utf-8",
                                link_callback=xhtml2pdf_link_callback)
    except Exception as e:
        app.logger.exception(f"PDF üretim istisnası: {e}")
        return f"PDF üretiminde hata oluştu: {e}", 500
    if result.err:
        app.logger.error("PDF oluşturulurken hata oluştu (pisa result.err=1).")
        return "PDF üretiminde hata oluştu. Sunucu loglarını kontrol edin.", 500
    pdf_io.seek(0)
    return send_file(pdf_io, as_attachment=True, download_name="rapor.pdf",
                     mimetype="application/pdf")

@app.route('/accept_task/<int:task_id>', methods=['POST'])
def accept_task(task_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']
    task = Task.query.filter_by(id=task_id, assigned_to=user_id).first()
    if task:
        task.accepted = "Evet"
        db.session.commit()
        flash("Görev kabul edildi.", "info")
    return redirect(url_for('assigned_tasks'))

@app.route('/complete_task/<int:task_id>', methods=['GET', 'POST'])
def complete_task(task_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']
    task = Task.query.filter_by(id=task_id, assigned_to=user_id).first()
    if not task:
        return redirect(url_for('assigned_tasks'))
    if request.method == 'POST':
        task.completed = "Evet"
        task.completion_note = (request.form.get('note') or "").strip()
        task.status = "Tamamlandi"
        db.session.commit()
        flash("Görev tamamlandı.", "success")
        return redirect(url_for('assigned_tasks'))
    return render_template('complete_task.html', task_id=task_id)

@app.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']; role = session.get("role", "user")
    task = Task.query.filter_by(id=task_id).first()
    if task and (task.user_id == user_id or role == "admin"):
        db.session.delete(task); db.session.commit()
        flash("Görev silindi.", "warning")
    return redirect(url_for('dashboard'))

# -------------------------
# Admin: Kullanıcı yönetimi
# -------------------------
@app.route('/admin/users')
def admin_users():
    require_admin()

    # Eğer users tablosunda yeni kolonlar yoksa, ham SQL ile listele (geçici mod)
    if not _user_flag_cols_exist():
        q = (request.args.get("q") or "").strip()
        role_f = (request.args.get("role") or "").strip()  # 'admin' / 'user' / ''
        # status_f yok sayılır çünkü is_active kolonu yok
        params = {}
        conds = []
        if q:
            conds.append("(username LIKE :like OR IFNULL(email,'') LIKE :like)")
            params["like"] = f"%{q}%"
        if role_f in ("admin", "user"):
            conds.append("role = :role")
            params["role"] = role_f
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        rows = db.session.execute(
            text(f"SELECT id, username, email, role FROM users {where} ORDER BY id ASC"),
            params
        ).fetchall()
        items = [SimpleNamespace(
            id=r.id, username=r.username, email=r.email, role=r.role,
            is_active=True, must_change_password=False
        ) for r in rows]
        # basit sayfalama
        page = max(int(request.args.get("page", 1)), 1)
        per_page = 12
        total = len(items)
        pages = ceil(total / per_page) if per_page else 1
        start = (page - 1) * per_page
        users = items[start:start+per_page]
        return render_template('users.html',
            users=users, total=total, pages=pages, page=page,
            q=q, role_f=role_f, status_f="")

    # Normal (kolonlar mevcut) yol
    q = (request.args.get("q") or "").strip()
    role_f = (request.args.get("role") or "").strip()
    status_f = (request.args.get("active") or "").strip()  # '1' aktif, '0' pasif
    base = User.query
    if q:
        like = f"%{q}%"
        base = base.filter(or_(User.username.ilike(like), User.email.ilike(like)))
    if role_f in ("admin", "user"):
        base = base.filter(User.role == role_f)
    if status_f in ("0", "1"):
        base = base.filter(User.is_active == (status_f == "1"))
    base = base.order_by(User.id.asc())
    page = max(int(request.args.get("page", 1)), 1)
    users, total, pages = paginate(base, page, per_page=12)
    return render_template('users.html',
        users=users, total=total, pages=pages, page=page, q=q, role_f=role_f, status_f=status_f)

@app.route('/admin/users/create', methods=['POST'])
def admin_create_user():
    require_admin()
    username = (request.form.get('username') or "").strip()
    email    = (request.form.get('email') or "").strip().lower()
    password = (request.form.get('password') or "").strip()
    role     = (request.form.get('role') or "user").strip()
    if not username or not password:
        flash("Kullanıcı adı ve şifre zorunlu.", "danger"); return redirect(url_for('admin_users'))
    if email and not EMAIL_RE.match(email):
        flash("Geçerli bir e-posta giriniz.", "danger"); return redirect(url_for('admin_users'))
    if role not in ("user", "admin"):
        role = "user"
    try:
        user = User(username=username,
                    email=email if email else None,
                    password=generate_password_hash(password, method="pbkdf2:sha256", salt_length=16),
                    role=role,
                    is_active=True,
                    must_change_password=True)  # ilk girişte değişsin
        db.session.add(user); db.session.commit()
        flash("Kullanıcı oluşturuldu (ilk girişte şifre değiştirme zorunlu).", "success")
    except IntegrityError:
        db.session.rollback(); flash("Kullanıcı adı veya e-posta zaten kayıtlı.", "danger")
    except Exception as e:
        db.session.rollback(); flash(f"Hata: {e}", "danger")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/reset_password_link', methods=['POST'])
def admin_reset_password_link(user_id):
    require_admin()
    user = User.query.get_or_404(user_id)
    if not user.email:
        flash("Bu kullanıcı için e-posta tanımlı değil.", "warning")
        return redirect(url_for('admin_users'))
    token = make_reset_token(user.id)
    link = url_for("reset_password", token=token, _external=True)
    body = ("Merhaba,\n\nŞifreni sıfırlamak için aşağıdaki linke tıkla (30 dakika geçerli):\n"
            f"{link}\n\nİsteği sen yapmadıysan bu e-postayı yok say.")
    ok = send_mail_plain(user.email, "Görev Takip – Şifre Sıfırlama", body)
    flash("Sıfırlama e-postası gönderildi." if ok else "E-posta gönderilemedi.",
          "success" if ok else "danger")
    return redirect(url_for('admin_users'))

# Admin: doğrudan şifre atama (kullanıcı ilk girişte değiştirmek zorunda)
@app.route('/admin/users/<int:user_id>/set_password', methods=['POST'])
def admin_set_password(user_id):
    require_admin()
    if user_id == session.get("user_id"):
        flash("Kendi şifrenizi buradan atayamazsınız.", "warning")
        return redirect(url_for('admin_users'))
    pw = (request.form.get("new_password") or "").strip()
    if len(pw) < 8 or not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw):
        flash("Şifre en az 8 karakter olmalı ve harf+rakam içermeli.", "danger")
        return redirect(url_for('admin_users'))
    u = User.query.get_or_404(user_id)
    u.password = generate_password_hash(pw, method="pbkdf2:sha256", salt_length=16)
    u.must_change_password = True
    db.session.commit()
    flash(f"{u.username} için yeni şifre atandı. İlk girişte değiştirmesi zorunlu.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/make_admin', methods=['POST'])
def admin_make_admin(user_id):
    require_admin()
    u = User.query.get_or_404(user_id)
    u.role = 'admin'; db.session.commit()
    flash(f"{u.username} artık admin.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/make_user', methods=['POST'])
def admin_make_user(user_id):
    require_admin()
    if user_id == session.get('user_id'):
        return "Kendi rolünüzü düşüremezsiniz.", 400
    u = User.query.get_or_404(user_id)
    u.role = 'user'; db.session.commit()
    flash(f"{u.username} artık user.", "info")
    return redirect(url_for('admin_users'))

# Pasife alma / Aktifleştirme
@app.route('/admin/users/<int:user_id>/deactivate', methods=['POST'])
def admin_deactivate_user(user_id):
    require_admin()
    if user_id == session.get('user_id'):
        flash("Kendi hesabınızı pasif yapamazsınız.", "warning"); return redirect(url_for('admin_users'))
    u = User.query.get_or_404(user_id)
    u.is_active = False
    db.session.commit()
    flash(f"{u.username} pasif yapıldı.", "warning")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/activate', methods=['POST'])
def admin_activate_user(user_id):
    require_admin()
    u = User.query.get_or_404(user_id)
    u.is_active = True
    db.session.commit()
    flash(f"{u.username} tekrar aktif.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    require_admin()
    if user_id == session.get('user_id'):
        return "Kendi hesabınızı silemezsiniz.", 400
    u = User.query.get_or_404(user_id)
    db.session.delete(u); db.session.commit()
    flash("Kullanıcı silindi.", "warning")
    return redirect(url_for('admin_users'))

# -------------------------
# Tek seferlik admin terfisi (GÜVENLİK: iş bitince SİL!)
# -------------------------
@app.route("/_once/make_me_admin", methods=["POST"])
@require_login
def make_me_admin_once():
    token = request.headers.get("X-PROMOTE-TOKEN") or request.args.get("token")
    expected = os.getenv("PROMOTE_TOKEN")
    if not expected or token != expected: abort(403)
    user = db.session.get(User, session["user_id"])
    if not user: abort(404)
    already = User.query.filter_by(role="admin").first()
    if already: return "Admin zaten var. Bu uç nokta kilitlendi.", 409
    user.role = "admin"; db.session.commit()
    return "Artık adminsiniz. Bu rotayı ve PROMOTE_TOKEN'ı KALDIRIN!", 200

# -------------------------
# TEŞHİS: Alembic ve tablo durumu
# -------------------------
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.config import Config

@app.route("/health/alembic")
def health_alembic():
    out = {}

    # DB'nin mevcut rev'i
    with db.engine.connect() as conn:
        context = MigrationContext.configure(conn)
        out["db_current_rev"] = context.get_current_revision()

    # alembic.ini yoksa/kusurluysa patlamasın
    try:
        cfg = Config("alembic.ini")
        script = ScriptDirectory.from_config(cfg)
        out["code_head_rev"] = script.get_current_head()
        out["alembic_ini"] = "ok"
    except Exception as e:
        out["code_head_rev"] = None
        out["alembic_ini"] = "missing_or_invalid"
        out["detail"] = str(e)

    insp = inspect(db.engine)
    out["tables"] = sorted(insp.get_table_names())
    return jsonify(out), 200

@app.route('/health/db')
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

# (Opsiyonel) AUTO_BOOTSTRAP=1 ise tablo yoksa create_all
with app.app_context():
    if os.getenv("AUTO_BOOTSTRAP") == "1":
        insp = inspect(db.engine)
        if not insp.has_table("users") or not insp.has_table("tasks"):
            db.create_all()

# 403
@app.errorhandler(403)
def forbidden(_):
    return render_template("403.html"), 403

if __name__ == '__main__':
    app.run(debug=True)
