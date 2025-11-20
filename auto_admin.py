from app import db, User, ROLE_OWNER, ROLE_VICE, ROLE_MANAGER, ROLE_STAFF

def create_initial_admins():
    # 대표
    if not User.query.filter_by(username="Showker").first():
        owner = User(
            email="create.swkr@gmail.com",
            username="Showker",
            role=ROLE_OWNER,
            display_color="#ff9bcf",
        )
        owner.set_password("Show1234")
        db.session.add(owner)

    # 예시 부대표/매니저/직원 계정
    presets = [
        ("vice@example.com", "부대표1", ROLE_VICE),
        ("manager@example.com", "매니저1", ROLE_MANAGER),
        ("staff@example.com", "직원1", ROLE_STAFF),
    ]
    for email, username, role in presets:
        if not User.query.filter_by(username=username).first():
            u = User(email=email, username=username, role=role, display_color="#b8e6ff")
            u.set_password("Pass1234")
            db.session.add(u)

    db.session.commit()
    print("기본 관리자/스태프 계정 생성 완료.")

if __name__ == "__main__":
    from app import app
    with app.app_context():
        create_initial_admins()
