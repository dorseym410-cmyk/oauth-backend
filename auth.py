import requests
import os
from datetime import datetime
from urllib.parse import urlencode, quote_plus, unquote

from models import TenantToken
from db import SessionLocal

# =========================
# ENV CONFIG
# =========================
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")

AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

# =========================
# TELEGRAM ALERT
# =========================
def send_telegram_alert(message):
    try:
        token = os.environ.get("TELEGRAM_BOT_TOKEN")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID")

        if not token or not chat_id:
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        requests.post(url, json={"chat_id": chat_id, "text": message})
    except Exception as e:
        print("Telegram error:", e)

# =========================
# URL GENERATORS
# =========================
def generate_login_link(user_id, session_id=None):
    state = f"{user_id}:{session_id}" if session_id else user_id

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": "User.Read",
        "state": quote_plus(state),
    }

    return f"{AUTH_URL}?{urlencode(params)}"


def generate_mail_connect_link(user_id, session_id=None):
    state = f"{user_id}:{session_id}" if session_id else user_id

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": "User.Read Mail.Read Mail.ReadWrite Mail.Send offline_access",
        "state": quote_plus(state),
    }

    return f"{AUTH_URL}?{urlencode(params)}"


def generate_org_connect_link():
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": "User.Read",
        "prompt": "admin_consent",
    }

    return f"{AUTH_URL}?{urlencode(params)}"


def generate_org_mail_connect_link():
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": "User.Read Mail.Read Mail.ReadWrite Mail.Send offline_access",
        "prompt": "admin_consent",
    }

    return f"{AUTH_URL}?{urlencode(params)}"


def generate_admin_consent_url(tenant: str | None = None):
    tenant_value = tenant or "organizations"

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
    }

    return f"https://login.microsoftonline.com/{tenant_value}/adminconsent?{urlencode(params)}"


# =========================
# TOKEN STORAGE
# =========================
def save_token(user_id, access_token, refresh_token, expires_in):
    db = SessionLocal()

    expires_at = int(datetime.utcnow().timestamp()) + int(expires_in)

    existing = db.query(TenantToken).filter(
        TenantToken.tenant_id == user_id
    ).first()

    if existing:
        existing.access_token = access_token
        existing.refresh_token = refresh_token
        existing.expires_at = expires_at
    else:
        token = TenantToken(
            tenant_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
        )
        db.add(token)

    db.commit()
    db.close()


def get_token(user_id):
    db = SessionLocal()
    token = db.query(TenantToken).filter(
        TenantToken.tenant_id == user_id
    ).first()
    db.close()
    return token


# =========================
# TOKEN REFRESH
# =========================
def refresh_token(user_id):
    token_record = get_token(user_id)

    if not token_record or not token_record.refresh_token:
        return None

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": token_record.refresh_token,
        "redirect_uri": REDIRECT_URI,
        "scope": "User.Read Mail.Read Mail.ReadWrite Mail.Send offline_access",
    }

    response = requests.post(TOKEN_URL, data=data)
    result = response.json()

    if "access_token" not in result:
        return None

    save_token(
        user_id,
        result["access_token"],
        result.get("refresh_token"),
        result.get("expires_in", 3600),
    )

    return result


# =========================
# CODE EXCHANGE
# =========================
def exchange_code(code):
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }

    response = requests.post(TOKEN_URL, data=data)
    return response.json()