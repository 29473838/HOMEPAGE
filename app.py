import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

# -------------------------------------------
# Flask 설정
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
# DB 모델 (테이블명 명시 수정)
# ==============================================
class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    permissions = db.Column(db.String(500))  # 예: "notice_write,warning_manage"


class User(db.Model, UserMixin):
    __tablename__ = "users"

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
    __tablename__ = "notices"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class QNA(db.Model):
    __tablename__ = "qna"

    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    email = db.Column(db.String(100))
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    answer = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    answered_at = db.Column(db.DateTime, nullable=True)

class ContactTicket(db.Model):
    __tablename__ = "contact_tickets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    category = db.Column(db.String(50), nullable=False)
    email_reply_to = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="대기")  # 대기 / 처리중 / 완료
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



# ==============================================
# 로그인 로드
# ==============================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ==============================================
# 권한 체크 (수정된 안정 버전)
# ==============================================
@app.context_processor
def inject_permission_checker():
    def has_permission(user, permission):
        if not user or not hasattr(user, "role"):
            return False

        role_obj = Role.query.filter_by(name=user.role).first()

        if not role_obj or not role_obj.permissions:
            return False

        perms = role_obj.permissions.split(",")
        return permission in perms

    return dict(has_permission=has_permission)


# ==============================================
# 이메일 발송
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
# 라우팅
# ==============================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/link")
def link_page():
    return render_template("link.html")


@app.route("/business")
def business_page():
    return render_template("business.html")


@app.route("/contact", methods=["GET", "POST"])
def contact_page():
    if request.method == "POST":
        category = request.form.get("category")
        email_reply_to = request.form.get("email_reply_to")
        subject = request.form.get("subject")
        content = request.form.get("content")

        # 문의 이메일 관리자에게 전달
        msg = f"""
📌 카테고리: {category}
📧 회신 이메일: {email_reply_to}
👤 보낸사람(ID): {current_user.username if current_user.is_authenticated else '비로그인'}
------------------------------------

{content}
"""
        send_email(
            "관리자메일@gmail.com",    # ⚠️ 운영자 이메일로 변경!
            f"[문의접수] {subject}",
            msg
        )

        flash("문의가 정상적으로 접수되었습니다! 빠르게 답변드리겠습니다 😊", "success")
        return redirect("/contact")

    return render_template("contact.html")



@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        new_username = request.form.get("username")
        new_color = request.form.get("display_color")

        # 현재 유저 수정
        current_user.username = new_username
        current_user.display_color = new_color

        try:
            db.session.commit()
            flash("프로필이 성공적으로 수정되었습니다!", "success")
        except:
            db.session.rollback()
            flash("수정 중 오류가 발생했습니다.", "danger")

        return redirect("/profile")

    return render_template("profile.html")



@app.route("/dashboard")
@login_required
def dashboard():

    # 관리자 권한 체크 (직급: 대표/부대표/매니저만)
    if current_user.role not in ["대표", "부대표", "매니저"]:
        flash("접근 권한이 없습니다.")
        return redirect("/")

    # 최근 가입 유저 10명
    users = User.query.order_by(User.id.desc()).limit(10).all()

    # 최근 문의 내용 10개
    tickets = QNA.query.order_by(QNA.created_at.desc()).limit(10).all()

    return render_template("dashboard.html", users=users, tickets=tickets)


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
# 공지사항
# ==============================================
@app.route("/notice")
def notice_list():
    notices = Notice.query.order_by(Notice.created_at.desc()).all()
    return render_template("notice.html", notices=notices)


@app.route("/notice/write", methods=["GET", "POST"])
@login_required
def notice_write():
    # 권한: notice_write
    if not inject_permission_checker()["has_permission"](current_user, "notice_write"):
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
# QNA
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

    send_email(q.email, f"[답변] {q.title}", answer_text)

    return redirect("/qna")


# ==============================================
# 관리자 대시보드
# ==============================================
@app.route("/admin")
@login_required
def admin():
    return render_template("admin.html")


# ==============================================
# 실행
# ==============================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(host="0.0.0.0", port=5000, debug=True)
