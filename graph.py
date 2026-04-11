# graph.py
import requests
from auth import get_token, refresh_token
from datetime import datetime


# =========================
# HELPER: CHECK EXPIRY
# =========================
def is_token_expired(token_record):
    return token_record.expires_at < int(datetime.utcnow().timestamp())


# =========================
# FETCH EMAILS
# =========================
def fetch_emails(user_id: str, session_id: str = None):
    """
    Fetch top 10 emails for a given user.
    Automatically refreshes the token if expired.
    Supports multi-device sessions.
    """

    # Get stored token
    token_record = get_token(user_id, session_id)
    if not token_record:
        raise Exception(f"No token found for user '{user_id}'. User must login first.")

    access_token = token_record.access_token

    # ✅ Refresh BEFORE request if expired
    if is_token_expired(token_record):
        refreshed = refresh_token(user_id, session_id)
        access_token = refreshed["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    url = "https://graph.microsoft.com/v1.0/me/messages?$top=10&$orderby=receivedDateTime desc"
    response = requests.get(url, headers=headers)

    # ✅ Retry if token rejected (edge case)
    if response.status_code == 401:
        refreshed = refresh_token(user_id, session_id)
        access_token = refreshed["access_token"]

        headers["Authorization"] = f"Bearer {access_token}"
        response = requests.get(url, headers=headers)

    data = response.json()

    if "error" in data:
        raise Exception(f"Graph API error: {data['error'].get('message')}")

    emails = data.get("value", [])

    return [
        {
            "subject": e.get("subject"),
            "from": e.get("from", {}).get("emailAddress", {}).get("address"),
            "preview": e.get("bodyPreview"),
            "date": e.get("receivedDateTime")
        }
        for e in emails
    ]