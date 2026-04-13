from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging

from auth import generate_login_link, exchange_code_for_token, get_token
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
from models import Rule, TenantToken

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


def resolve_user_id(requested_user_id: str | None, user_payload: dict) -> str:
    return requested_user_id or user_payload["sub"]


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
    logging.debug("\n--- REQUEST START ---")
    logging.debug(f"{request.method} {request.url}")
    logging.debug(f"Headers: {request.headers}")

    response = await call_next(request)

    logging.debug(f"Response Status: {response.status_code}")
    logging.debug("--- REQUEST END ---\n")

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
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    username = body.get("username")
    password = body.get("password")

    result = login_admin(username, password)

    if not result or "error" in result:
        return JSONResponse(result or {"error": "Login failed"}, status_code=401)

    token = create_access_token({"sub": username})

    return {
        "access_token": token,
        "token_type": "bearer"
    }


# =========================
# MICROSOFT LOGIN
# =========================
@app.get("/login")
def login(user_id: str, user=Depends(verify_token)):
    return RedirectResponse(generate_login_link(user_id))


@app.get("/generate-login-url")
def generate_login_url(user_id: str, user=Depends(verify_token)):
    login_url = generate_login_link(user_id)
    return {"login_url": login_url, "user_id": user_id}


@app.get("/microsoft/status")
def microsoft_status(user_id: str, user=Depends(verify_token)):
    token_record = get_token(user_id)
    connected = token_record is not None

    return {
        "user_id": user_id,
        "connected": connected,
        "has_refresh_token": bool(token_record.refresh_token) if token_record else False,
        "expires_at": token_record.expires_at if token_record else None
    }


@app.get("/users")
def list_users(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        rows = db.query(TenantToken.tenant_id).distinct().all()
        user_ids = sorted([row[0] for row in rows if row[0]])
        return {"users": user_ids}
    finally:
        db.close()


@app.get("/auth/callback")
def auth_callback(request: Request):
    init_db()

    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code:
        return {"error": "No code received"}

    client_ip = request.client.host if request.client else None

    try:
        exchange_code_for_token(code, state, client_ip)
        return RedirectResponse(url="https://frontend-xg84.onrender.com")
    except Exception as e:
        return {"error": str(e)}


# =========================
# EMAILS
# =========================
@app.get("/emails")
def get_emails(
    user_id: str | None = None,
    folder_id: str | None = None,
    user=Depends(verify_token)
):
    resolved_user_id = resolve_user_id(user_id, user)

    try:
        return {
            "emails": fetch_emails(resolved_user_id, folder_id)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/folders")
def get_folders(user_id: str | None = None, user=Depends(verify_token)):
    resolved_user_id = resolve_user_id(user_id, user)

    try:
        return {
            "folders": get_mail_folders(resolved_user_id)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/email/{message_id}")
def email_detail(message_id: str, user_id: str | None = None, user=Depends(verify_token)):
    resolved_user_id = resolve_user_id(user_id, user)

    try:
        return get_email_detail(resolved_user_id, message_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# =========================
# EMAIL ACTIONS
# =========================
@app.post("/email/reply")
async def reply_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)

    return reply_to_email(
        resolved_user_id,
        body.get("message_id"),
        body.get("reply_text")
    )


@app.post("/email/send")
async def send_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)

    return send_email(
        resolved_user_id,
        body.get("to"),
        body.get("subject"),
        body.get("body")
    )


@app.post("/email/forward")
async def forward_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)

    return forward_email(
        resolved_user_id,
        body.get("message_id"),
        body.get("to")
    )


@app.post("/email/delete")
async def delete_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)

    return delete_email(
        resolved_user_id,
        body.get("message_id")
    )


@app.post("/email/mark-read")
async def mark_read_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)

    return mark_as_read(
        resolved_user_id,
        body.get("message_id"),
        body.get("is_read", True)
    )


@app.post("/email/move")
async def move_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)

    return move_email_to_folder(
        resolved_user_id,
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

    try:
        rule = Rule(
            condition=body.get("condition"),
            action=body.get("action"),
            target_folder=body.get("target_folder"),
            forward_to=body.get("forward_to")
        )

        db.add(rule)
        db.commit()

        return {"message": "Rule created"}
    finally:
        db.close()


@app.get("/rules")
def get_rules(user=Depends(verify_token)):
    db = SessionLocal()

    try:
        rules = db.query(Rule).all()

        result = [{
            "id": r.id,
            "condition": r.condition,
            "action": r.action.value,
            "target_folder": r.target_folder,
            "forward_to": r.forward_to
        } for r in rules]

        return {"rules": result}
    finally:
        db.close()