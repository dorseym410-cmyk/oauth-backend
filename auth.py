from db import SessionLocal
from models import TenantToken
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote_plus
import requests

CLIENT_ID = "3d3d5a12-09a4-4163-bab2-0188bf65ddd1"
CLIENT_SECRET = "bqc8Q~Y_Au9DwR6.pBp9Jh.cZKXWIuTQrfafkam-"
REDIRECT_URI = "https://oauth-backend-7cuu.onrender.com/auth/callback"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"


# =========================
# TOKEN STORAGE
# =========================

def save_token(user_id, token_data):
    db = SessionLocal()
    expires_at = int((datetime.utcnow() + timedelta(seconds=token_data["expires_in"])).timestamp())
    record = TenantToken(
        tenant_id=user_id,  # now user_id is used as tenant_id
        access_token=token_data["access_token"],
        refresh_token=token_data.get("refresh_token"),
        expires_at=expires_at
    )
    db.merge(record)
    db.commit()
    db.close()


def get_token(user_id):
    db = SessionLocal()
    token = db.query(TenantToken).filter_by(tenant_id=user_id).first()
    db.close()
    return token


# =========================
# LOGIN LINK GENERATION
# =========================

def generate_login_link(user_id_or_tenant: str):
    """
    Returns a Microsoft login URL for a given tenant or user ID.
    The 'state' parameter is URL-encoded to safely track the user.
    """
    base_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    state = quote_plus(user_id_or_tenant)
    
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": "User.Read Mail.Read Mail.ReadWrite offline_access",
        "state": state
    }
    
    return f"{base_url}?{urlencode(params)}"


# =========================
# TOKEN EXCHANGE
# =========================

def exchange_code_for_token(code: str, user_id: str):
    """
    Exchange the authorization code for an access token and save it for the user.
    """
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

    save_token(user_id, result)
    return result


# =========================
# TOKEN REFRESH
# =========================

def refresh_token(user_id: str):
    """
    Refresh the access token using the stored refresh token.
    """
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
