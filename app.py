from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import or_, text
from sqlalchemy.exc import IntegrityError, DataError
from functools import wraps  # geçici admin rotası için
import os
import pandas as pd
from io import BytesIO
from xhtml2pdf import pisa
from math import ceil

# -------------------------------------------------
# Flask & DB config
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "gizli_anahtar")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'gorev_takip.db')}"

# psycopg3 (SQLAlchemy 2.x) için sürücü normalizasyonu:
# Render/ENV "postgresql://..." veriyorsa "postgresql+psycopg://..." yapıyoruz.
_db_url_final = DATABASE_URL or ""

if _db_url_final.startswith("postgresql://"):
    _db_url_final = _db_url_final.replace("postgresql://", "postgresql+psycopg://", 1)

# Neon güvenliği: sslmode yoksa ekle
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
# Modeller
# -------------------------------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
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
    """Kullanıcı girişliyse rol/username'i DB'den yenile."""
    uid = session.get("user_id")
    if uid:
        u = User.query.get(uid)
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

# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'user_id' in session else redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password_raw = request.form['password']
        if not username or not password_raw:
            return render_template('register.html', error="Kullanıcı adı ve şifre zorunludur.")
        try:
            user = User(username=username, password=generate_password_hash(password_raw))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            return render_template('register.html', error="Bu kullanıcı adı zaten kayıtlı.")
        except DataError as e:
            db.session.rollback()
            return render_template('register.html', error=f"Veri formatı hatası: {e.orig}")
        except Exception as e:
            db.session.rollback()
            return render_template('register.html', error=f"Kayıt sırasında hata: {e}")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Kullanıcı adı veya şifre hatalı.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    all_users = User.query.order_by(User.username.asc()).all()

    if request.method == 'POST':
        t = Task(
            user_id=user_id,
            title=request.form['title'].strip(),
            location=request.form['location'].strip(),
            materials=request.form['materials'].strip(),
            date=request.form['date'].strip(),
            needs_support=request.form['needs_support'].strip(),
            status=request.form['status'].strip(),
            assigned_to=int(request.form.get('assigned_to') or user_id)
        )
        db.session.add(t)
        db.session.commit()
        return redirect(url_for('dashboard', **request.args))

    base = Task.query.order_by(Task.id.desc())
    filtered = apply_filters(base, user_id)
    page = max(int(request.args.get("page", 1)), 1)
    tasks, total, pages = paginate(filtered, page, per_page=10)

    return render_template(
        'dashboard.html',
        tasks=tasks,
        all_users=all_users,
        current_user=user_id,
        total=total,
        pages=pages,
        page=page,
        q=request.args.get("q", ""),
        f_status=request.args.get("status", ""),
        mine=request.args.get("mine") == "1",
        f_assigned=request.args.get("assigned", "")
    )

@app.route('/assigned_tasks')
def assigned_tasks():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    tasks = Task.query.filter_by(assigned_to=user_id, completed="Hayir").order_by(Task.id.desc()).all()
    return render_template('assigned_tasks.html', tasks=tasks, current_user=user_id)

@app.route('/completed_tasks')
def completed_tasks():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    tasks = Task.query.filter_by(assigned_to=user_id, completed="Evet").order_by(Task.id.desc()).all()
    return render_template('completed_tasks.html', tasks=tasks)

@app.route('/report')
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    tasks = Task.query.order_by(Task.id.desc()).all()
    return render_template('report.html', tasks=tasks)

@app.route('/export/excel')
def export_excel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    tasks = Task.query.filter_by(completed="Evet").order_by(Task.id.desc()).all()
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
    if 'user_id' not in session:
        return redirect(url_for('login'))
    tasks = Task.query.filter_by(completed="Evet").order_by(Task.id.desc()).all()
    rendered = render_template("report_pdf.html", tasks=tasks)
    pdf_io = BytesIO()
    pisa.CreatePDF(rendered, dest=pdf_io)
    pdf_io.seek(0)
    resp = make_response(pdf_io.read())
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = "attachment; filename=rapor.pdf"
    return resp

@app.route('/accept_task/<int:task_id>', methods=['POST'])
def accept_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    task = Task.query.filter_by(id=task_id, assigned_to=user_id).first()
    if task:
        task.accepted = "Evet"
        db.session.commit()
    return redirect(url_for('assigned_tasks'))

@app.route('/complete_task/<int:task_id>', methods=['GET', 'POST'])
def complete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    task = Task.query.filter_by(id=task_id, assigned_to=user_id).first()
    if not task:
        return redirect(url_for('assigned_tasks'))
    if request.method == 'POST':
        task.completed = "Evet"
        task.completion_note = request.form['note'].strip()
        task.status = "Tamamlandi"
        db.session.commit()
        return redirect(url_for('assigned_tasks'))
    return render_template('complete_task.html', task_id=task_id)

@app.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    role = session.get("role", "user")
    task = Task.query.filter_by(id=task_id).first()
    if task and (task.user_id == user_id or role == "admin"):
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('dashboard'))

# -------------------------
# Admin: Kullanıcı yönetimi
# -------------------------
@app.route('/admin/users')
def admin_users():
    require_admin()
    users = User.query.order_by(User.id.asc()).all()
    return render_template('users.html', users=users)

@app.route('/admin/users/<int:user_id>/make_admin', methods=['POST'])
def admin_make_admin(user_id):
    require_admin()
    u = User.query.get_or_404(user_id)
    u.role = 'admin'
    db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/make_user', methods=['POST'])
def admin_make_user(user_id):
    require_admin()
    if user_id == session.get('user_id'):
        return "Kendi rolünüzü düşüremezsiniz.", 400
    u = User.query.get_or_404(user_id)
    u.role = 'user'
    db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    require_admin()
    if user_id == session.get('user_id'):
        return "Kendi hesabınızı silemezsiniz.", 400
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    return redirect(url_for('admin_users'))

# -------------------------
# Tek seferlik admin terfisi (GÜVENLİK: iş bitince SİL!)
# -------------------------
def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

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

    # İsteğe bağlı: sistemde zaten admin varsa kilitle
    already = User.query.filter_by(role="admin").first()
    if already:
        return "Admin zaten var. Bu uç nokta kilitlendi.", 409

    user.role = "admin"
    db.session.commit()
    return "Artık adminsiniz. Bu rotayı ve PROMOTE_TOKEN'ı KALDIRIN!", 200

# Sağlık kontrolü
@app.route('/health/db')
def health_db():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500

# Bağlantı dizesini görmek için (şifre maskeli) TEŞHİS ROTASI
@app.route("/health/db_url")
def health_db_url():
    url = app.config.get("SQLALCHEMY_DATABASE_URI", "not-set")
    # kullanıcı:şifre kısmını maskele
    safe = url
    if "://" in url and "@" in url:
        prefix, rest = url.split("://", 1)
        safe = f"{prefix}://****:****@" + rest.split("@", 1)[1]
    return jsonify({"db": safe}), 200

# 403
@app.errorhandler(403)
def forbidden(_):
    return render_template("403.html"), 403

if __name__ == '__main__':
    app.run(debug=True)
