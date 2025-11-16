from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, datetime

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_TO_SOMETHING_RANDOM"

# 업로드 폴더 (공지 이미지용)
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ===================== DB 연결/초기화 =====================
def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # 유저 테이블 (role: 'admin' / 'user')
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
        """
    )

    # 공지 테이블
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            image_path TEXT,
            author TEXT,
            created_at TEXT
        )
        """
    )

    # 댓글 테이블
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            notice_id INTEGER,
            username TEXT,
            comment TEXT,
            created_at TEXT
        )
        """
    )

    # 기본 관리자 계정 생성
    c.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if not c.fetchone():
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "admin"),
        )

    conn.commit()
    conn.close()


init_db()


# ===================== 유틸 =====================
def current_user():
    return session.get("username")


def current_role():
    return session.get("role")


# ===================== 기본 페이지들 =====================
@app.route("/")
def home():
    return render_template("index.html", user=current_user(), role=current_role())


@app.route("/link")
def link_page():
    return render_template("link.html", user=current_user(), role=current_role())


@app.route("/business")
def business_page():
    return render_template("business.html", user=current_user(), role=current_role())


@app.route("/contact")
def contact_page():
    return render_template("contact.html", user=current_user(), role=current_role())


# ===================== 로그인 / 로그아웃 / 회원가입 =====================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("notice_list"))
        else:
            return render_template("login.html", error="아이디 또는 비밀번호가 올바르지 않습니다.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            return render_template("register.html", error="아이디와 비밀번호를 입력해주세요.")

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), "user"),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="이미 존재하는 아이디입니다.")
        conn.close()
        return redirect(url_for("login"))

    return render_template("register.html")


# ===================== 공지사항 =====================
@app.route("/notice")
def notice_list():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM notices ORDER BY id DESC")
    notices = c.fetchall()
    conn.close()
    return render_template("notice.html", notices=notices, user=current_user(), role=current_role())


@app.route("/notice/write", methods=["GET", "POST"])
def notice_write():
    if current_role() != "admin":
        return "권한이 없습니다. (관리자 전용)", 403

    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"].strip()
        image_path = None

        file = request.files.get("image")
        if file and file.filename:
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)
            image_path = "/static/uploads/" + filename

        conn = get_db()
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO notices (title, content, image_path, author, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                title,
                content,
                image_path,
                current_user(),
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            ),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("notice_list"))

    return render_template("notice_write.html", user=current_user(), role=current_role())


@app.route("/notice/<int:notice_id>", methods=["GET", "POST"])
def notice_view(notice_id):
    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        if not current_user():
            conn.close()
            return "댓글 작성은 로그인 후 가능합니다.", 403
        comment_text = request.form["comment"].strip()
        if comment_text:
            c.execute(
                """
                INSERT INTO comments (notice_id, username, comment, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    notice_id,
                    current_user(),
                    comment_text,
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                ),
            )
            conn.commit()

    c.execute("SELECT * FROM notices WHERE id = ?", (notice_id,))
    notice = c.fetchone()

    c.execute("SELECT * FROM comments WHERE notice_id = ? ORDER BY id DESC", (notice_id,))
    comments = c.fetchall()

    conn.close()
    return render_template(
        "notice_view.html",
        notice=notice,
        comments=comments,
        user=current_user(),
        role=current_role(),
    )


@app.route("/notice/<int:notice_id>/delete")
def notice_delete(notice_id):
    if current_role() != "admin":
        return "권한이 없습니다.", 403

    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM notices WHERE id = ?", (notice_id,))
    c.execute("DELETE FROM comments WHERE notice_id = ?", (notice_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("notice_list"))


@app.route("/notice/<int:notice_id>/edit", methods=["GET", "POST"])
def notice_edit(notice_id):
    if current_role() != "admin":
        return "권한이 없습니다.", 403

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"].strip()
        c.execute("UPDATE notices SET title=?, content=? WHERE id=?", (title, content, notice_id))
        conn.commit()
        conn.close()
        return redirect(url_for("notice_view", notice_id=notice_id))

    c.execute("SELECT * FROM notices WHERE id = ?", (notice_id,))
    notice = c.fetchone()
    conn.close()
    return render_template("notice_edit.html", notice=notice, user=current_user(), role=current_role())


if __name__ == "__main__":
    app.run(debug=True)
