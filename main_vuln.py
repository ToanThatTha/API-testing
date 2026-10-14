"""
Lab phuc vu mon Bao mat he thong thong tin - CHI chay tren localhost.
Hai lo hong duoc cai cam:
  - API5:2023 BFLA  : endpoint /admin/* chi kiem tra XAC THUC, khong kiem tra VAI TRO
  - API4:2023 Rate : endpoint /auth/verify-otp khong gioi han so lan thu -> brute force OTP
Chay: uvicorn main_vuln:app --port 8000
"""
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import jwt, time

SECRET = "demo-secret-chi-dung-cho-lab"
app = FastAPI(title="VulnShop API (vulnerable)")

# CSDL gia lap trong bo nho
users = {
    "toan":  {"password": "toan123",               "role": "user",  "id": 101, "email": "toan@shop.vn", "balance": 500000},
    "mai":   {"password": "mai@2026",               "role": "user",  "id": 102, "email": "mai@shop.vn",  "balance": 2000000},
    "admin": {"password": "S3cureAdmin!2026",       "role": "admin", "id": 1,   "email": "admin@shop.vn","balance": 0},
}
# OTP 4 chu so dung cho demo rate limit (bi mat)
otp_store = {"toan": "7391"}


def make_token(username: str) -> str:
    u = users[username]
    payload = {"sub": username, "role": u["role"], "id": u["id"], "iat": int(time.time())}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def current_user(authorization: str = Header(None)):
    """CHI kiem tra token hop le (authentication).
    LOI: khong he kiem tra vai tro (authorization) o day."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thieu token")
    token = authorization.split(" ", 1)[1]
    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token khong hop le")


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


# ---------------- BFLA target (API5:2023) ----------------
@app.get("/admin/users")
def admin_list_users(user=Depends(current_user)):
    # LOI BFLA: thieu dong  if user["role"] != "admin": raise HTTPException(403)
    return {"users": [
        {"id": u["id"], "username": k, "email": u["email"], "role": u["role"], "balance": u["balance"]}
        for k, u in users.items()
    ]}


@app.delete("/admin/users/{username}")
def admin_delete_user(username: str, user=Depends(current_user)):
    # LOI BFLA: user thuong van goi duoc ham xoa tai khoan
    if username in users:
        del users[username]
        return {"deleted": username, "by": user["sub"]}
    raise HTTPException(status_code=404, detail="Khong tim thay user")


# ---------------- Rate limit target (API4:2023) ----------------
@app.post("/auth/verify-otp")
def verify_otp(username: str, otp: str):
    # LOI: khong dem so lan thu, khong khoa, khong delay -> brute force 0000..9999
    real = otp_store.get(username)
    if real is None:
        raise HTTPException(status_code=404, detail="Khong co OTP")
    if otp == real:
        return {"status": "ok", "message": "OTP dung - cap quyen truy cap"}
    raise HTTPException(status_code=401, detail="OTP sai")
