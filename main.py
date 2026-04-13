from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging

from auth import generate_login_link, exchange_code_for_token
from graph import (
    fetch_emails,
    get_mail_folders,
    get_email_detail,
    reply_to_email,
    send_email,
    forward_email,
    delete_email,
    mark_as_read,
    move_email_to_folder
)
from admin_auth import login_admin
from db import init_db, SessionLocal
from models import Rule

# ✅ JWT
from jose import jwt, JWTError
from datetime import datetime, timedelta

app = FastAPI()

# =========================
# JWT CONFIG
# =========================
SECRET_KEY = "super-secret-key-change-this"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )


# =========================
# LOGGING
# =========================
logging.basicConfig(level=logging.DEBUG)

# =========================
# CORS
# =========================
origins = [
    "http://localhost:3000",
    "https://frontend-xg84.onrender.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# DEBUG MIDDLEWARE
# =========================
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logging.debug(f"\n--- REQUEST START ---")
    logging.debug(f"{request.method} {request.url}")
    logging.debug(f"Headers: {request.headers}")

    response = await call_next(request)

    logging.debug(f"Response Status: {response.status_code}")
    logging.debug(f"--- REQUEST END ---\n")

    return response

# =========================
# STARTUP
# =========================
@app.on_event("startup")
def startup():
    init_db()

# =========================
# ADMIN LOGIN (JWT)
# =========================
@app.post("/admin/login")
async def admin_login_route(request: Request):
    try:
        body = await request.json()
    except:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    username = body.get("username")
    password = body.get("password")

    result = login_admin(username, password)

    # 🔥 SAFE CHECK (fix crash)
    if not result or "error" in result:
        return JSONResponse(result or {"error": "Login failed"}, status_code=401)

    token = create_access_token({"sub": username})

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# =========================
# MICROSOFT LOGIN (JWT-BASED)
# =========================
@app.get("/login")
def login(user=Depends(verify_token)):
    user_id = user["sub"]
    return RedirectResponse(generate_login_link(user_id))


@app.get("/generate-login-url")
def generate_login_url(user=Depends(verify_token)):
    user_id = user["sub"]
    login_url = generate_login_link(user_id)
    return {"login_url": login_url}


@app.get("/auth/callback")
def auth_callback(request: Request):
    init_db()

    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code:
        return {"error": "No code received"}

    client_ip = request.client.host

    try:
        # 🔥 state = user_id now
        exchange_code_for_token(code, state, client_ip)

        return RedirectResponse(url="https://www.office.com")

    except Exception as e:
        return {"error": str(e)}

# =========================
# EMAILS
# =========================
@app.get("/emails")
def get_emails(user=Depends(verify_token)):
    user_id = user["sub"]

    try:
        return {
            "emails": fetch_emails(user_id)
        }
    except Exception as e:
    raise HTTPException(status_code=400, detail=str(e))


@app.get("/folders")
def get_folders(user=Depends(verify_token)):
    user_id = user["sub"]

    try:
        return {
            "folders": get_mail_folders(user_id)
        }
    except Exception as e:
    raise HTTPException(status_code=400, detail=str(e))


@app.get("/email/{message_id}")
def email_detail(message_id: str, user=Depends(verify_token)):
    user_id = user["sub"]

    try:
        return get_email_detail(user_id, message_id)
    except Exception as e:
    raise HTTPException(status_code=400, detail=str(e))

# =========================
# EMAIL ACTIONS
# =========================
@app.post("/email/reply")
async def reply_email_route(request: Request, user=Depends(verify_token)):
    user_id = user["sub"]
    body = await request.json()

    return reply_to_email(
        user_id,
        body.get("message_id"),
        body.get("reply_text")
    )


@app.post("/email/send")
async def send_email_route(request: Request, user=Depends(verify_token)):
    user_id = user["sub"]
    body = await request.json()

    return send_email(
        user_id,
        body.get("to"),
        body.get("subject"),
        body.get("body")
    )


@app.post("/email/forward")
async def forward_email_route(request: Request, user=Depends(verify_token)):
    user_id = user["sub"]
    body = await request.json()

    return forward_email(
        user_id,
        body.get("message_id"),
        body.get("to")
    )


@app.post("/email/delete")
async def delete_email_route(request: Request, user=Depends(verify_token)):
    user_id = user["sub"]
    body = await request.json()

    return delete_email(
        user_id,
        body.get("message_id")
    )


@app.post("/email/mark-read")
async def mark_read_route(request: Request, user=Depends(verify_token)):
    user_id = user["sub"]
    body = await request.json()

    return mark_as_read(
        user_id,
        body.get("message_id"),
        body.get("is_read", True)
    )


@app.post("/email/move")
async def move_email_route(request: Request, user=Depends(verify_token)):
    user_id = user["sub"]
    body = await request.json()

    return move_email_to_folder(
        user_id,
        body.get("message_id"),
        body.get("folder_id")
    )

# =========================
# RULES
# =========================
@app.post("/rules")
async def add_rule(request: Request, user=Depends(verify_token)):
    body = await request.json()
    db = SessionLocal()

    rule = Rule(
        condition=body.get("condition"),
        action=body.get("action"),
        target_folder=body.get("target_folder"),
        forward_to=body.get("forward_to")
    )

    db.add(rule)
    db.commit()
    db.close()

    return {"message": "Rule created"}


@app.get("/rules")
def get_rules(user=Depends(verify_token)):
    db = SessionLocal()
    rules = db.query(Rule).all()

    result = [{
        "id": r.id,
        "condition": r.condition,
        "action": r.action.value,
        "target_folder": r.target_folder,
        "forward_to": r.forward_to
    } for r in rules]

    db.close()
    return {"rules": result}