"""
auto_admin.py
- Flask app의 init_db()를 호출해서
  테이블 생성 + 기본 admin 계정을 만들어주는 스크립트
"""
from app import init_db

if __name__ == "__main__":
    init_db()
    print("[OK] DB 초기화 및 기본 관리자(admin/admin123) 준비 완료.")
