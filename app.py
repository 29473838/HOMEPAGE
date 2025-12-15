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

DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

from functools import wraps

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role not in ["대표", "부대표", "매니저"]:
            flash("관리자만 접근 가능합니다.")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

from werkzeug.utils import secure_filename

app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads", "qna")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "webm", "ogg"}

def allowed_file(filename):
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in (ALLOWED_IMAGE_EXTENSIONS | ALLOWED_VIDEO_EXTENSIONS)

def get_attachment_type(filename):
    ext = filename.rsplit(".", 1)[1].lower()
    if ext in ALLOWED_IMAGE_EXTENSIONS:
        return "image"
    if ext in ALLOWED_VIDEO_EXTENSIONS:
        return "video"
    return None


# ==============================================
# DB 모델 (테이블명 명시 수정)
# ==============================================
class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    permissions = db.Column(db.String(500)) 


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
    display_color = db.Column(db.String(7), default="#000000")
    title = db.Column(db.String(50), nullable=True)


class Notice(db.Model):
    __tablename__ = "notices"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship("User", foreign_keys=[author_id])


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

    is_hot = db.Column(db.Boolean, default=False)
    attachment = db.Column(db.String(300))
    attachment_type = db.Column(db.String(20))

    author = db.relationship("User", foreign_keys=[author_id])
    answer_admin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    answer_admin = db.relationship("User", foreign_keys=[answer_admin_id])


class ContactTicket(db.Model):
    __tablename__ = "contact_tickets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    category = db.Column(db.String(50))
    email_reply_to = db.Column(db.String(100))
    subject = db.Column(db.String(200))
    content = db.Column(db.Text)

    admin_reply = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="대기중")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id])
    admin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    admin = db.relationship("User", foreign_keys=[admin_id])


class NoticeComment(db.Model):
    __tablename__ = "notice_comments"

    id = db.Column(db.Integer, primary_key=True)
    notice_id = db.Column(db.Integer, db.ForeignKey("notices.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User")



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
@login_required
def contact_page():
    if request.method == "POST":
        category = request.form["category"]
        email_reply_to = request.form["email_reply_to"]
        subject = request.form["subject"]
        content = request.form["content"]

        ticket = ContactTicket(
            user_id=current_user.id,
            category=category,
            email_reply_to=email_reply_to,
            subject=subject,
            content=content
        )
        db.session.add(ticket)
        db.session.commit()

        flash("문의가 정상적으로 접수되었습니다!")
        return redirect("/contact")
    my_tickets = ContactTicket.query.filter_by(
        user_id=current_user.id
    ).order_by(ContactTicket.created_at.desc()).all()

    return render_template("contact.html", my_tickets=my_tickets)




@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        new_username = request.form.get("username") or current_user.username
        new_color = request.form.get("display_color") or current_user.display_color
        new_title = request.form.get("title") or None

        current_user.username = new_username
        current_user.display_color = new_color
        current_user.title = new_title

        try:
            db.session.commit()
            flash("프로필이 성공적으로 수정되었습니다!", "success")
        except Exception as e:
            db.session.rollback()
            print("PROFILE ERROR:", e)
            flash("수정 중 오류가 발생했습니다.", "danger")

        return redirect("/profile")

    return render_template("profile.html")


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role not in ["대표", "부대표", "매니저"]:
        flash("접근 권한이 없습니다.")
        return redirect("/")

    user_page = request.args.get("user_page", 1, type=int)
    ticket_page = request.args.get("ticket_page", 1, type=int)

    users = User.query.order_by(User.id.desc()).paginate(page=user_page, per_page=10)
    tickets = ContactTicket.query.order_by(ContactTicket.created_at.desc()).paginate(page=ticket_page, per_page=10)

    return render_template("dashboard.html", users=users, tickets=tickets)

@app.route("/admin/user/<int:user_id>/warn", methods=["POST"])
@admin_required
def admin_user_warn(user_id):
    user = User.query.get_or_404(user_id)
    user.warnings = (user.warnings or 0) + 1
    db.session.commit()
    flash("경고 1회가 추가되었습니다.")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/admin/user/<int:user_id>/ban", methods=["POST"])
@admin_required
def admin_user_ban(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = True
    db.session.commit()
    flash("해당 유저가 정지 처리되었습니다.")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/admin/user/<int:user_id>/unban", methods=["POST"])
@admin_required
def admin_user_unban(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    db.session.commit()
    flash("정지가 해제되었습니다.")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    user = User.query.get_or_404(user_id)

    ContactTicket.query.filter_by(user_id=user.id).delete()
    QNA.query.filter_by(author_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()
    flash("유저가 삭제되었습니다.")
    return redirect(request.referrer or url_for("dashboard"))

@app.route("/admin/user/<int:user_id>/force_logout", methods=["POST"])
@admin_required
def admin_user_force_logout(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = True
    user.banned_until = datetime.utcnow()
    db.session.commit()

    flash(f"{user.username}님 강제 로그아웃 처리 완료.")
    return redirect(url_for('dashboard'))

@app.route("/admin/ticket/<int:ticket_id>/status", methods=["POST"])
@admin_required
def admin_ticket_status(ticket_id):
    if current_user.role not in ["대표", "부대표", "매니저"]:
        flash("관리자 권한이 없습니다.")
        return redirect(url_for("dashboard"))

    ticket = ContactTicket.query.get(ticket_id)
    if not ticket:
        flash("문의 기록을 찾을 수 없습니다.")
        return redirect(url_for("dashboard"))

    new_status = request.form.get("status")
    admin_reply = request.form.get("answer", "").strip()

    allowed_status = ["대기중", "처리중", "처리완료", "처리불가"]
    if new_status not in allowed_status:
        flash("잘못된 상태입니다.")
        return redirect(url_for("dashboard"))
    ticket.status = new_status
    if admin_reply:
        ticket.admin_reply = admin_reply
        ticket.admin_id = current_user.id

    try:
        db.session.commit()
        flash("상태 및 답변이 저장되었습니다.")
    except Exception as e:
        db.session.rollback()
        print("TICKET STATUS ERROR:", e)
        flash("저장 중 오류가 발생했습니다.", "danger")

    return redirect(url_for("dashboard"))


@app.route("/admin/ticket/<int:ticket_id>/delete", methods=["POST"])
@login_required
def admin_ticket_delete(ticket_id):
    if current_user.role not in ["대표", "부대표", "매니저"]:
        flash("권한이 없습니다.")
        return redirect(url_for("dashboard"))

    ticket = ContactTicket.query.get_or_404(ticket_id)

    db.session.delete(ticket)
    db.session.commit()

    flash("문의가 삭제되었습니다.")
    return redirect(url_for("dashboard"))

@app.route("/admin/user/<int:user_id>/unwarn", methods=["POST"])
@login_required
def admin_user_unwarn(user_id):
    if current_user.role not in ["대표", "부대표", "매니저"]:
        flash("권한이 없습니다.")
        return redirect(url_for("dashboard"))

    user = User.query.get_or_404(user_id)
    if user.warnings > 0:
        user.warnings -= 1
        db.session.commit()
        flash(f"{user.username} 님의 경고를 1 감소시켰습니다.")
    else:
        flash("이미 경고가 0입니다.")

    return redirect(url_for("dashboard"))

# ==============================================
# 회원가입
# ==============================================
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


# ==============================================
# 로그인
# ==============================================
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
    if not inject_permission_checker()["has_permission"](current_user, "notice_write"):
        abort(403)

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]

        n = Notice(title=title, content=content, author_id=current_user.id)
        db.session.add(n)
        db.session.commit()

        flash("공지 등록 완료!")
        return redirect("/notice")

    return render_template("notice_write.html")
    

@app.route("/notice/delete/<int:notice_id>", methods=["POST"])
@login_required
def notice_delete(notice_id):
    if not inject_permission_checker()["has_permission"](current_user, "notice_write"):
        abort(403)

    notice = Notice.query.get_or_404(notice_id)
    db.session.delete(notice)
    db.session.commit()

    flash("공지사항이 삭제되었습니다.")
    return redirect(url_for("notice_list"))

@app.route("/notice/edit/<int:notice_id>", methods=["GET", "POST"])
@login_required
def notice_edit(notice_id):
    notice = Notice.query.get_or_404(notice_id)

    # 작성자 또는 관리자만 편집 가능
    if notice.author_id != current_user.id and current_user.role not in ["대표", "부대표", "매니저"]:
        abort(403)

    if request.method == "POST":
        notice.title = request.form["title"]
        notice.content = request.form["content"]
        db.session.commit()

        flash("공지사항이 수정되었습니다.")
        return redirect(url_for("notice_detail", notice_id=notice.id))

    return render_template("notice_edit.html", notice=notice)

@app.route("/notice/<int:notice_id>/comment", methods=["POST"])
@login_required
def notice_comment(notice_id):
    notice = Notice.query.get_or_404(notice_id)
    comment_text = request.form.get("comment")

    if not comment_text or comment_text.strip() == "":
        flash("댓글 내용을 입력해주세요.")
        return redirect(url_for("notice_detail", notice_id=notice.id))

    comment = NoticeComment(
        notice_id=notice.id,
        user_id=current_user.id,
        content=comment_text
    )
    db.session.add(comment)
    db.session.commit()

    flash("댓글이 작성되었습니다.")
    return redirect(url_for("notice_detail", notice_id=notice.id))

@app.route("/notice/<int:notice_id>")
def notice_detail(notice_id):
    notice = Notice.query.get_or_404(notice_id)
    comments = NoticeComment.query.filter_by(notice_id=notice.id) \
                                  .order_by(NoticeComment.created_at.asc()) \
                                  .all()
    return render_template("notice_detail.html", notice=notice, comments=comments)


# ==============================================
# QNA
# ==============================================
@app.route("/qna", methods=["GET", "POST"])
def qna_list():
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("로그인 후에 Q&A를 작성할 수 있습니다.")
            return redirect(url_for("login"))

        title = request.form.get("title")
        content = request.form.get("content")
        file = request.files.get("attachment")

        attachment = None
        attachment_type = None

        if file and file.filename:
            if not allowed_file(file.filename):
                flash("허용되지 않은 파일 형식입니다. (이미지: png/jpg/jpeg/gif, 영상: mp4/webm/ogg)")
                return redirect(url_for("qna_list"))

            filename = secure_filename(file.filename)
            name, ext = os.path.splitext(filename)
            filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{name}{ext}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)

            attachment = "/" + save_path.replace("\\", "/")
            attachment_type = get_attachment_type(filename)

        q = QNA(
            author_id=current_user.id,
            email=current_user.email, 
            title=title,
            content=content,
            attachment=attachment,
            attachment_type=attachment_type,
        )
        db.session.add(q)
        db.session.commit()
        flash("Q&A가 등록되었습니다.")
        return redirect(url_for("qna_list"))

    hot_qnas = (
        QNA.query.filter_by(is_hot=True)
        .order_by(QNA.created_at.desc())
        .limit(10)
        .all()
    )

    normal_qnas = (
        QNA.query.filter((QNA.is_hot == False) | (QNA.is_hot.is_(None)))
        .order_by(QNA.created_at.desc())
        .all()
    )

    return render_template("qna.html", hot_qnas=hot_qnas, qnas=normal_qnas)



@app.route("/qna/write", methods=["GET", "POST"])
@login_required
def qna_write():
    return redirect(url_for("qna_list"))

@app.route("/qna/<int:id>/hot", methods=["POST"])
@admin_required
def qna_toggle_hot(id):
    q = QNA.query.get_or_404(id)

    if not q.is_hot:
        hot_count = QNA.query.filter_by(is_hot=True).count()
        if hot_count >= 10:
            flash("HOT Q&A는 최대 10개까지만 지정할 수 있습니다.")
            return redirect(url_for("qna_list"))
        q.is_hot = True
        msg = "HOT Q&A로 지정되었습니다."
    else:
        q.is_hot = False
        msg = "HOT Q&A에서 해제되었습니다."

    db.session.commit()
    flash(msg)
    return redirect(url_for("qna_list"))

@app.route("/qna/answer/<int:id>", methods=["POST"])
@admin_required
def qna_answer(id):
    q = QNA.query.get_or_404(id)

    answer_text = request.form.get("answer")
    if not answer_text:
        flash("답변 내용을 입력하세요.")
        return redirect(url_for("qna_list"))

    q.answer = answer_text
    q.answered_at = datetime.utcnow()
    q.answer_admin_id = current_user.id
    db.session.commit()

    send_email(q.email, f"[답변] {q.title}", answer_text)

    flash("답변이 등록되었습니다.")
    return redirect(url_for("qna_list"))



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




# ==============================================
# 방송
# ==============================================
class StreamStatus(db.Model):
    __tablename__ = "stream_status"

    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), default="오프라인") 
    platform = db.Column(db.String(20), nullable=True) 
    url = db.Column(db.String(300), nullable=True)  
    thumbnail_url = db.Column(db.String(300), nullable=True)  
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    updated_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    updated_by = db.relationship("User", foreign_keys=[updated_by_id])


class StreamSchedule(db.Model):
    __tablename__ = "stream_schedule"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))             
    platform = db.Column(db.String(20))         
    start_at = db.Column(db.DateTime, nullable=False)
    end_at = db.Column(db.DateTime, nullable=True)
    memo = db.Column(db.String(200), nullable=True)

@app.context_processor
def inject_stream_info():
    status = StreamStatus.query.order_by(StreamStatus.updated_at.desc()).first()
    now = datetime.utcnow()
    upcoming = StreamSchedule.query.filter(StreamSchedule.start_at >= now) \
                                   .order_by(StreamSchedule.start_at.asc()) \
                                   .limit(7) \
                                   .all()

    return dict(current_stream=status, upcoming_streams=upcoming)


@app.route("/stream", methods=["GET", "POST"])
@login_required
def stream_page():
    if request.method == "POST":
        if current_user.role not in ["대표", "부대표", "매니저"]:
            flash("관리자만 방송 정보를 수정할 수 있습니다.", "danger")
            return redirect(url_for("stream_page"))

        form_type = request.form.get("form_type")

        if form_type == "status":
            status = request.form.get("status") 
            platform = request.form.get("platform") or None
            url = request.form.get("url") or None
            thumb = request.form.get("thumbnail_url") or None

            if status not in ["방송중", "녹화중", "업무중", "휴식중", "오프라인"]:
                flash("잘못된 상태입니다.", "danger")
                return redirect(url_for("stream_page"))

            cur = StreamStatus.query.order_by(StreamStatus.updated_at.desc()).first()
            if not cur:
                cur = StreamStatus()

            cur.status = status
            cur.platform = platform if status == "방송중" else None
            cur.url = url if status == "방송중" else None
            cur.thumbnail_url = thumb if status == "방송중" else None
            cur.updated_at = datetime.utcnow()
            cur.updated_by_id = current_user.id

            db.session.add(cur)
            db.session.commit()
            flash("방송 상태가 저장되었습니다.", "success")
            return redirect(url_for("stream_page"))

        elif form_type == "schedule_add":
            title = request.form.get("title")
            platform = request.form.get("platform")
            start_at_str = request.form.get("start_at")
            end_at_str = request.form.get("end_at") or None
            memo = request.form.get("memo") or None

            if not title or not platform or not start_at_str:
                flash("필수 항목이 비어 있습니다.", "danger")
                return redirect(url_for("stream_page"))
            try:
                start_at = datetime.strptime(start_at_str, "%Y-%m-%dT%H:%M")
                end_at = datetime.strptime(end_at_str, "%Y-%m-%dT%H:%M") if end_at_str else None
            except ValueError:
                flash("날짜/시간 형식이 올바르지 않습니다.", "danger")
                return redirect(url_for("stream_page"))

            s = StreamSchedule(
                title=title,
                platform=platform,
                start_at=start_at,
                end_at=end_at,
                memo=memo,
            )
            db.session.add(s)
            db.session.commit()
            flash("방송 일정이 추가되었습니다.", "success")
            return redirect(url_for("stream_page"))
    schedules = StreamSchedule.query.order_by(StreamSchedule.start_at.asc()).all()
    return render_template("stream.html", schedules=schedules)

@app.route("/stream/schedule/delete/<int:schedule_id>", methods=["POST"])
@login_required
def stream_schedule_delete(schedule_id):
    if current_user.role not in ["대표", "부대표", "매니저"]:
        flash("관리자만 삭제할 수 있습니다.", "danger")
        return redirect(url_for("stream_page"))

    s = StreamSchedule.query.get_or_404(schedule_id)
    db.session.delete(s)
    db.session.commit()
    flash("일정이 삭제되었습니다.", "success")
    return redirect(url_for("stream_page"))
