"""
Minh hoa bien phap phong chong cho BFLA va Rate Limit.
Chay: uvicorn main_fixed:app --port 8001
"""
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from pydantic import BaseModel
from collections import defaultdict
import jwt, time

SECRET = "demo-secret-chi-dung-cho-lab"
app = FastAPI(title="Test API (fixed)")

users = {
    "toan":  {"password": "toan123",         "role": "user",  "id": 101, "email": "toan@shop.vn", "balance": 500000},
    "user1":   {"password": "user1@2026",               "role": "user",  "id": 102, "email": "user1@shop.vn",  "balance": 2000000},
    "admin": {"password": "S3cureAdmin!2026", "role": "admin", "id": 1,   "email": "admin@shop.vn","balance": 0},
}
otp_store = {"toan": "7391"}


def make_token(username: str) -> str:
    u = users[username]
    payload = {"sub": username, "role": u["role"], "id": u["id"], "iat": int(time.time())}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thieu token")
    token = authorization.split(" ", 1)[1]
    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token khong hop le")


def require_admin(user=Depends(current_user)):
    """VA BFLA: bat buoc vai tro admin moi cho qua."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Khong du quyen (yeu cau admin)")
    return user


# --- VA rate limit: dem so lan thu OTP theo tung user, khoa sau N lan ---
MAX_OTP_TRIES = 5
LOCK_WINDOW = 300  # giay
otp_attempts = defaultdict(list)  # username -> [timestamp,...]


class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
def login(body: LoginBody):
    u = users.get(body.username)
    if not u or u["password"] != body.password:
        raise HTTPException(status_code=401, detail="Sai thong tin dang nhap")
    return {"access_token": make_token(body.username), "role": u["role"]}


@app.get("/users/me")
def me(user=Depends(current_user)):
    return {"username": user["sub"], "role": user["role"], "id": user["id"]}


@app.get("/admin/users")
def admin_list_users(user=Depends(require_admin)):
    return {"users": [
        {"id": u["id"], "username": k, "email": u["email"], "role": u["role"]}
        for k, u in users.items()
    ]}


@app.delete("/admin/users/{username}")
def admin_delete_user(username: str, user=Depends(require_admin)):
    if username in users:
        del users[username]
        return {"deleted": username, "by": user["sub"]}
    raise HTTPException(status_code=404, detail="Khong tim thay user")


@app.post("/auth/verify-otp")
def verify_otp(username: str, otp: str):
    now = time.time()
    tries = [t for t in otp_attempts[username] if now - t < LOCK_WINDOW]
    if len(tries) >= MAX_OTP_TRIES:
        raise HTTPException(status_code=429,
                            detail=f"Qua nhieu lan thu, khoa {LOCK_WINDOW}s")
    otp_attempts[username] = tries + [now]
    real = otp_store.get(username)
    if real is None:
        raise HTTPException(status_code=404, detail="Khong co OTP")
    if otp == real:
        otp_attempts[username] = []
        return {"status": "ok", "message": "OTP dung - cap quyen truy cap"}
    raise HTTPException(status_code=401, detail="OTP sai")
