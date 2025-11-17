import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

# -------------------------------------------
#  Flask 설정
# -------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default-secret-key")

# --- PostgreSQL 설정 ---
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ==============================================
#  DB 모델
# ==============================================
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    permissions = db.Column(db.String(500))  # permission1,permission2 형식


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100))
    password = db.Column(db.String(200))
    nickname = db.Column(db.String(50))
    role = db.Column(db.String(50), default="일반")
    warnings = db.Column(db.Integer, default=0)
    banned_until = db.Column(db.DateTime, nullable=True)
    is_banned = db.Column(db.Boolean, default=False)


class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class QNA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    email = db.Column(db.String(100))
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    answer = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    answered_at = db.Column(db.DateTime, nullable=True)


# ==============================================
#  로그인 로드
# ==============================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ==============================================
#  권한 체크 (완전 수정된 안정 버전)
# ==============================================
@app.context_processor
def inject_permission_checker():
    def has_permission(user, permission):
        if not user or not hasattr(user, "role"):
            return False

        user_role = user.role

        # --- role 이 문자열이면 Role 테이블에서 객체 가져옴 ---
        if isinstance(user_role, str):
            role_obj = Role.query.filter_by(name=user_role).first()
            if not role_obj:
                return False
            user_role = role_obj

        # --- Role 객체 없으면 False ---
        if user_role is None:
            return False

        perms = user_role.permissions

        # 리스트 형태
        if isinstance(perms, list):
            return permission in perms

        # 콤마 문자열
        if isinstance(perms, str):
            return permission in perms.split(",")

        return False

    return dict(has_permission=has_permission)


# ==============================================
#  이메일 발송
# ==============================================
def send_email(to_email, title, message):
    gmail_id = os.environ.get("GMAIL_EMAIL")
    gmail_pw = os.environ.get("GMAIL_PASSWORD")

    if not gmail_id or not gmail_pw:
        print("⚠ 이메일 환경변수 없음 → 이메일 전송 비활성화")
        return False

    msg = MIMEText(message)
    msg["Subject"] = title
    msg["From"] = gmail_id
    msg["To"] = to_email

    try:
        s = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        s.login(gmail_id, gmail_pw)
        s.sendmail(gmail_id, to_email, msg.as_string())
        s.quit()
        return True
    except Exception as e:
        print("EMAIL ERROR:", e)
        return False


# ==============================================
#  라우팅
# ==============================================
@app.route("/")
def index():
    return render_template("index.html")


# ---- 회원가입 ----
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        pw = request.form["password"]

        if User.query.filter_by(username=username).first():
            flash("이미 존재하는 아이디입니다.")
            return redirect("/register")

        user = User(
            username=username,
            email=email,
            password=generate_password_hash(pw),
            role="일반",
        )
        db.session.add(user)
        db.session.commit()

        flash("회원가입 완료!")
        return redirect("/login")

    return render_template("register.html")


# ---- 로그인 ----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        pw = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, pw):
            flash("로그인 정보가 올바르지 않습니다.")
            return redirect("/login")

        login_user(user)
        return redirect("/")

    return render_template("login.html")


# ---- 로그아웃 ----
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")


# ==============================================
#  공지사항
# ==============================================
@app.route("/notice")
def notice_list():
    notices = Notice.query.order_by(Notice.created_at.desc()).all()
    return render_template("notice.html", notices=notices)


@app.route("/notice/write", methods=["GET", "POST"])
@login_required
def notice_write():
    # 권한 체크
    from flask import abort

    def has_perm():
        user_role = current_user.role
        role_obj = Role.query.filter_by(name=user_role).first()
        if not role_obj:
            return False
        return "notice_write" in role_obj.permissions.split(",")

    if not has_perm():
        abort(403)

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]

        n = Notice(title=title, content=content, author_id=current_user.id)
        db.session.add(n)
        db.session.commit()
        return redirect("/notice")

    return render_template("notice_write.html")


# ==============================================
#  QNA 게시판
# ==============================================
@app.route("/qna")
def qna_list():
    qnas = QNA.query.order_by(QNA.created_at.desc()).all()
    return render_template("qna.html", qnas=qnas)


@app.route("/qna/write", methods=["GET", "POST"])
@login_required
def qna_write():
    if request.method == "POST":
        q = QNA(
            author_id=current_user.id,
            email=request.form["email"],
            title=request.form["title"],
            content=request.form["content"],
        )
        db.session.add(q)
        db.session.commit()
        return redirect("/qna")

    return render_template("qna_write.html")


@app.route("/qna/answer/<int:id>", methods=["POST"])
@login_required
def qna_answer(id):
    q = QNA.query.get(id)

    answer_text = request.form["answer"]
    q.answer = answer_text
    q.answered_at = datetime.utcnow()
    db.session.commit()

    # 이메일 발송
    send_email(q.email, f"[답변] {q.title}", answer_text)

    return redirect("/qna")


# ==============================================
#  관리자 대시보드
# ==============================================
@app.route("/admin")
@login_required
def admin():
    return render_template("admin.html")


@app.route("/init_db")
def init_db():
    db.drop_all()
    db.create_all()

    # 기본 역할 생성
    roles = [
        ("대표", "notice_write,warning_manage,promote,ban_user,answer_qna,delete_comment"),
        ("부대표", "notice_write,warning_manage,promote,ban_user,answer_qna,delete_comment"),
        ("매니저", "notice_write,warning_manage,answer_qna,delete_comment"),
        ("직원", "notice_write,answer_qna"),
        ("일반", "")
    ]

    for name, perms in roles:
        if not Role.query.filter_by(name=name).first():
            db.session.add(Role(name=name, permissions=perms))
    
    db.session.commit()

    return "DB 초기화 및 기본 Role 생성 완료!"


# ==============================================
#  실행
# ==============================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
