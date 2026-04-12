# graph.py
import requests
from auth import get_token, refresh_token
from datetime import datetime


# =========================
# TOKEN CHECK
# =========================
def is_token_expired(token_record):
    return token_record.expires_at < int(datetime.utcnow().timestamp())


def get_valid_token(user_id, session_id):
    token_record = get_token(user_id, session_id)

    if not token_record:
        raise Exception("No token found. Please login again.")

    if is_token_expired(token_record):
        print("Refreshing token...")
        refreshed = refresh_token(user_id, session_id)

        if not refreshed or "access_token" not in refreshed:
            raise Exception("Token refresh failed")

        return refreshed["access_token"]

    return token_record.access_token


# =========================
# REQUEST HELPER
# =========================
def graph_request(url, user_id, session_id):
    token = get_valid_token(user_id, session_id)

    headers = {"Authorization": f"Bearer {token}"}

    res = requests.get(url, headers=headers)

    if res.status_code == 401:
        print("Retry after refresh...")
        refreshed = refresh_token(user_id, session_id)
        headers["Authorization"] = f"Bearer {refreshed['access_token']}"
        res = requests.get(url, headers=headers)

    data = res.json()

    if "error" in data:
        raise Exception(data["error"]["message"])

    return data


# =========================
# EMAILS
# =========================
def fetch_emails(user_id, session_id=None, folder_id=None):
    if folder_id:
        url = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_id}/messages"
    else:
        url = "https://graph.microsoft.com/v1.0/me/messages"

    data = graph_request(url, user_id, session_id)

    return [
        {
            "id": e.get("id"),
            "conversationId": e.get("conversationId"),
            "subject": e.get("subject"),
            "from": e.get("from", {}).get("emailAddress", {}).get("address"),
            "preview": e.get("bodyPreview"),
        }
        for e in data.get("value", [])
    ]


# =========================
# FOLDERS
# =========================
def get_mail_folders(user_id, session_id):
    url = "https://graph.microsoft.com/v1.0/me/mailFolders"
    data = graph_request(url, user_id, session_id)

    return [
        {"id": f["id"], "name": f["displayName"]}
        for f in data.get("value", [])
    ]


# =========================
# EMAIL DETAIL
# =========================
def get_email_detail(user_id, session_id, message_id):
    token = get_valid_token(user_id, session_id)

    headers = {"Authorization": f"Bearer {token}"}

    msg = requests.get(
        f"https://graph.microsoft.com/v1.0/me/messages/{message_id}",
        headers=headers
    ).json()

    return {
        "id": msg.get("id"),
        "subject": msg.get("subject"),
        "from": msg.get("from", {}).get("emailAddress", {}).get("address"),
        "body": msg.get("body", {}).get("content"),
    }


# =========================
# SEND EMAIL
# =========================
def send_email(user_id, session_id, to, subject, body, attachments=None):
    token = get_valid_token(user_id, session_id)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body},
            "toRecipients": [{"emailAddress": {"address": to}}]
        }
    }

    res = requests.post(
        "https://graph.microsoft.com/v1.0/me/sendMail",
        headers=headers,
        json=payload
    )

    if res.status_code != 202:
        raise Exception(res.text)

    return {"status": "sent"}


# =========================
# REPLY
# =========================
def reply_to_email(user_id, session_id, message_id, message, attachments=None):
    token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/reply"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "message": {
            "body": {"contentType": "HTML", "content": message}
        }
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 202]:
        raise Exception(res.text)

    return {"status": "replied"}


# =========================
# FORWARD
# =========================
def forward_email(user_id, session_id, message_id, to):
    token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/forward"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "toRecipients": [{"emailAddress": {"address": to}}]
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 202]:
        raise Exception(res.text)

    return {"status": "forwarded"}


# =========================
# DELETE
# =========================
def delete_email(user_id, session_id, message_id):
    token = get_valid_token(user_id, session_id)

    headers = {"Authorization": f"Bearer {token}"}

    res = requests.delete(
        f"https://graph.microsoft.com/v1.0/me/messages/{message_id}",
        headers=headers
    )

    if res.status_code != 204:
        raise Exception(res.text)

    return {"status": "deleted"}


# =========================
# MARK READ
# =========================
def mark_as_read(user_id, session_id, message_id, is_read=True):
    token = get_valid_token(user_id, session_id)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {"isRead": is_read}

    res = requests.patch(
        f"https://graph.microsoft.com/v1.0/me/messages/{message_id}",
        headers=headers,
        json=payload
    )

    if res.status_code != 200:
        raise Exception(res.text)

    return {"status": "updated"}