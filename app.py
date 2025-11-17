import os
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, abort, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    current_user, login_required, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")
# Database 설정: Render PostgreSQL (DATABASE_URL) 사용, 없으면 로컬 SQLite 사용
db_url = os.environ.get("DATABASE_URL")
if db_url:
    # Render / Heroku 스타일 postgres:// 를 postgresql:// 로 보정
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
else:
    db_url = "sqlite:///" + os.path.join(BASE_DIR, "database.db")

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Mail (Gmail SMTP 예시)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "your_gmail@gmail.com")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "your_app_password")
app.config["MAIL_DEFAULT_SENDER"] = app.config["MAIL_USERNAME"]

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
mail = Mail(app)

# ---------- 권한/직급 ----------
ROLE_USER = "user"
ROLE_STAFF = "staff"
ROLE_MANAGER = "manager"
ROLE_VICE = "vice"
ROLE_OWNER = "owner"

ROLE_CHOICES = [ROLE_USER, ROLE_STAFF, ROLE_MANAGER, ROLE_VICE, ROLE_OWNER]

# 권한 맵
PERMISSIONS = {
    ROLE_USER: {
        "notice_write": False,
        "warning_manage": False,
        "comment_delete": False,
        "profile_force_edit": False,
        "suspend": False,
        "promote": False,
        "contact_reply": False,
    },
    ROLE_STAFF: {
        "notice_write": True,
        "warning_manage": False,
        "comment_delete": False,
        "profile_force_edit": False,
        "suspend": False,
        "promote": False,
        "contact_reply": True,
    },
    ROLE_MANAGER: {
        "notice_write": True,
        "warning_manage": True,
        "comment_delete": True,
        "profile_force_edit": True,
        "suspend": True,
        "promote": False,
        "contact_reply": True,
    },
    ROLE_VICE: {
        "notice_write": True,
        "warning_manage": True,
        "comment_delete": True,
        "profile_force_edit": True,
        "suspend": True,
        "promote": True,
        "contact_reply": True,
    },
    ROLE_OWNER: {
        "notice_write": True,
        "warning_manage": True,
        "comment_delete": True,
        "profile_force_edit": True,
        "suspend": True,
        "promote": True,
        "contact_reply": True,
    },
}

def has_permission(user, perm):
    if not user:
        return False
    role = user.role or ROLE_USER
    return PERMISSIONS.get(role, PERMISSIONS[ROLE_USER]).get(perm, False)

# ---------- Models ----------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default=ROLE_USER)
    display_color = db.Column(db.String(20), default="#ffffff")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    warnings = db.relationship("Warning", backref="target", foreign_keys="Warning.target_user_id")
    suspensions = db.relationship("Suspension", backref="target", foreign_keys="Suspension.target_user_id")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_suspended(self):
        now = datetime.utcnow()
        for s in self.suspensions:
            if s.is_active and (s.permanent or (s.until and s.until > now)):
                return True
        return False


class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)   # HTML 허용
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class NoticeComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    notice_id = db.Column(db.Integer, db.ForeignKey("notice.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)


class Warning(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    given_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    reason = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    revoked = db.Column(db.Boolean, default=False)


class Suspension(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    given_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    reason = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    until = db.Column(db.DateTime, nullable=True)
    permanent = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)


class ContactTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    category = db.Column(db.String(50), nullable=False)
    email_reply_to = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    replies = db.relationship("ContactReply", backref="ticket", lazy=True)


class ContactReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("contact_ticket.id"))
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class QnaPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ---------- Login ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------- Helpers ----------
def send_reply_email(to_email, subject, body):
    try:
        msg = Message(subject=subject, recipients=[to_email])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        # Render 환경에서 메일이 막혀있을 수 있으므로 실패해도 앱은 계속 동작
        print("Email send failed:", e)


# ---------- Routes ----------

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
        if not current_user.is_authenticated:
            flash("문의 작성은 로그인 후 이용 가능합니다.", "danger")
            return redirect(url_for("login"))
        email_reply_to = request.form.get("email_reply_to")
        category = request.form.get("category") or "기타"
        subject = request.form.get("subject")
        content = request.form.get("content")

        ticket = ContactTicket(
            user_id=current_user.id,
            category=category,
            email_reply_to=email_reply_to,
            subject=subject,
            content=content
        )
        db.session.add(ticket)
        db.session.commit()
        flash("문의가 접수되었습니다.", "success")
        return redirect(url_for("contact_page"))
    return render_template("contact.html")


@app.route("/notice")
def notice_list():
    notices = Notice.query.order_by(Notice.created_at.desc()).all()
    return render_template("notice.html", notices=notices)


@app.route("/notice/<int:notice_id>", methods=["GET", "POST"])
def notice_detail(notice_id):
    notice = Notice.query.get_or_404(notice_id)
    comments = NoticeComment.query.filter_by(notice_id=notice.id).order_by(NoticeComment.created_at.asc()).all()
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("댓글 작성은 로그인 후 이용 가능합니다.", "danger")
            return redirect(url_for("login"))
        content = request.form.get("content")
        if content:
            c = NoticeComment(notice_id=notice.id, author_id=current_user.id, content=content)
            db.session.add(c)
            db.session.commit()
            flash("댓글이 등록되었습니다.", "success")
        return redirect(url_for("notice_detail", notice_id=notice.id))
    return render_template("notice_detail.html", notice=notice, comments=comments)


@app.route("/notice/new", methods=["GET", "POST"])
@login_required
def notice_new():
    if not has_permission(current_user, "notice_write"):
        abort(403)
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")  # HTML
        if not title or not content:
            flash("제목과 내용을 입력해주세요.", "danger")
        else:
            n = Notice(title=title, content=content, author_id=current_user.id)
            db.session.add(n)
            db.session.commit()
            flash("공지글이 등록되었습니다.", "success")
            return redirect(url_for("notice_list"))
    return render_template("notice_form.html")


@app.route("/notice/<int:notice_id>/edit", methods=["GET", "POST"])
@login_required
def notice_edit(notice_id):
    notice = Notice.query.get_or_404(notice_id)
    if not has_permission(current_user, "notice_write"):
        abort(403)
    if request.method == "POST":
        notice.title = request.form.get("title")
        notice.content = request.form.get("content")
        db.session.commit()
        flash("공지글이 수정되었습니다.", "success")
        return redirect(url_for("notice_detail", notice_id=notice.id))
    return render_template("notice_form.html", notice=notice)


@app.route("/notice/<int:notice_id>/delete", methods=["POST"])
@login_required
def notice_delete(notice_id):
    notice = Notice.query.get_or_404(notice_id)
    if not has_permission(current_user, "notice_write"):
        abort(403)
    db.session.delete(notice)
    db.session.commit()
    flash("공지글이 삭제되었습니다.", "success")
    return redirect(url_for("notice_list"))


@app.route("/admin/contact")
@login_required
def admin_contact_list():
    if not has_permission(current_user, "contact_reply"):
        abort(403)
    tickets = ContactTicket.query.order_by(ContactTicket.created_at.desc()).all()
    return render_template("admin_contact.html", tickets=tickets)


@app.route("/admin/contact/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def admin_contact_detail(ticket_id):
    if not has_permission(current_user, "contact_reply"):
        abort(403)
    ticket = ContactTicket.query.get_or_404(ticket_id)
    if request.method == "POST":
        reply_content = request.form.get("reply")
        if reply_content:
            r = ContactReply(ticket_id=ticket.id, admin_id=current_user.id, content=reply_content)
            ticket.status = "answered"
            db.session.add(r)
            db.session.commit()
            # 이메일 발송
            send_reply_email(
                ticket.email_reply_to,
                f"[ShowkerTMS 문의답변] {ticket.subject}",
                reply_content
            )
            flash("답변이 등록되고 이메일이 발송되었습니다.(실패 시 로그 확인)", "success")
        return redirect(url_for("admin_contact_detail", ticket_id=ticket.id))
    return render_template("admin_contact_detail.html", ticket=ticket)


@app.route("/qna", methods=["GET", "POST"])
def qna_list():
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("QnA 작성은 로그인 후 이용 가능합니다.", "danger")
            return redirect(url_for("login"))
        title = request.form.get("title")
        content = request.form.get("content")
        if title and content:
            q = QnaPost(user_id=current_user.id, title=title, content=content)
            db.session.add(q)
            db.session.commit()
            flash("QnA가 등록되었습니다.", "success")
            return redirect(url_for("qna_list"))
    posts = QnaPost.query.order_by(QnaPost.created_at.desc()).all()
    return render_template("qna.html", posts=posts)


@app.route("/dashboard")
@login_required
def dashboard():
    if not has_permission(current_user, "warning_manage") and not has_permission(current_user, "promote"):
        abort(403)
    users = User.query.order_by(User.created_at.desc()).all()
    tickets = ContactTicket.query.order_by(ContactTicket.created_at.desc()).limit(5).all()
    return render_template("dashboard.html", users=users, tickets=tickets)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        username = request.form.get("username")
        color = request.form.get("display_color")
        if username:
            current_user.username = username
        if color:
            current_user.display_color = color
        db.session.commit()
        flash("프로필이 수정되었습니다.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if user.is_suspended:
                flash("정지된 계정입니다.", "danger")
                return redirect(url_for("login"))
            login_user(user)
            flash("로그인되었습니다.", "success")
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        else:
            flash("이메일 또는 비밀번호가 올바르지 않습니다.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("로그아웃되었습니다.", "success")
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash("이미 사용 중인 이메일 또는 닉네임입니다.", "danger")
        else:
            u = User(email=email, username=username, role=ROLE_USER)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("회원가입이 완료되었습니다. 로그인해주세요.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")

# 정적 파일 (음악, 이미지 등) - 기본 static 사용

# --- 앱 시작 시 한 번만 테이블 자동 생성 (Render / gunicorn 포함) ---
with app.app_context():
    db.create_all()



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)
