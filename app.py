from flask import Flask, render_template, request, redirect, url_for, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import or_, text
import os
import pandas as pd
from io import BytesIO
from xhtml2pdf import pisa

# -------------------------------------------------
# Flask & DB config
# -------------------------------------------------
app = Flask(__name__)

# Güvenli anahtar – Render/Prod'da ENV’den al
app.secret_key = os.getenv("SECRET_KEY", "gizli_anahtar")

# Neon/Postgres bağlantısı (Render -> Environment'da ayarlanacak)
DATABASE_URL = os.getenv("DATABASE_URL")

# Yerelde ENV yoksa sqlite fallback
if not DATABASE_URL:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'gorev_takip.db')}"

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Neon TLS ister; sslmode=require
engine_opts = {"pool_pre_ping": True, "pool_recycle": 300}
if DATABASE_URL.startswith("postgresql"):
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
# Routes
# -------------------------------------------------
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'user_id' in session else redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = generate_password_hash(request.form['password'])
        try:
            db.session.add(User(username=username, password=password))
            db.session.commit()
        except Exception:
            db.session.rollback()
            return "Kullanıcı adı zaten var."
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        return "Hatalı giriş"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
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

    tasks = Task.query.order_by(Task.id.desc()).all()
    return render_template('dashboard.html', tasks=tasks, all_users=all_users, current_user=user_id)

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
    rows = [
        [
            t.title, t.location, t.date, t.materials, t.needs_support, t.status,
            t.assigner.username if t.assigner else "",
            t.assignee.username if t.assignee else "",
            t.completion_note or ""
        ]
        for t in tasks
    ]
    df = pd.DataFrame(
        rows,
        columns=["Görev", "Yer", "Tarih", "Malzemeler", "Destek", "Durum", "Gorevi_Giren", "Atanan", "Aciklama"]
    )

    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Tamamlanan Görevler')
    output.seek(0)

    response = make_response(output.read())
    response.headers["Content-Disposition"] = "attachment; filename=rapor.xlsx"
    response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return response

@app.route('/export/pdf')
def export_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    tasks = Task.query.filter_by(completed="Evet").order_by(Task.id.desc()).all()
    rendered = render_template("report_pdf.html", tasks=tasks)
    pdf_io = BytesIO()
    pisa.CreatePDF(rendered, dest=pdf_io)
    pdf_io.seek(0)

    response = make_response(pdf_io.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=rapor.pdf'
    return response

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
    task = Task.query.filter_by(id=task_id, user_id=user_id).first()
    if task:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('dashboard'))

# Sağlık kontrolü (Neon bağlantısı için pratik)
@app.route('/health/db')
def health_db():
    try:
        db.session.execute(text("SELECT 1"))
        return "db ok", 200
    except Exception as e:
        return f"db error: {e}", 500


if __name__ == '__main__':
    app.run(debug=True)
