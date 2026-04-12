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
# HELPER: GET VALID TOKEN
# =========================
def get_valid_token(user_id, session_id):
    token_record = get_token(user_id, session_id)

    if not token_record:
        raise Exception("❌ No token found. Please login again.")

    # If expired → refresh
    if is_token_expired(token_record):
        print("🔄 Token expired, refreshing...")

        refreshed = refresh_token(user_id, session_id)

        if not refreshed or "access_token" not in refreshed:
            raise Exception("❌ Token refresh failed. Please re-login.")

        return refreshed["access_token"]

    return token_record.access_token


# =========================
# HELPER: REQUEST WITH RETRY
# =========================
def graph_request(url, user_id, session_id):
    access_token = get_valid_token(user_id, session_id)

    headers = {"Authorization": f"Bearer {access_token}"}

    res = requests.get(url, headers=headers)

    # 🔥 If unauthorized → force refresh and retry ONCE
    if res.status_code == 401:
        print("⚠️ 401 received, forcing token refresh...")

        refreshed = refresh_token(user_id, session_id)
        headers["Authorization"] = f"Bearer {refreshed['access_token']}"

        res = requests.get(url, headers=headers)

    data = res.json()

    if "error" in data:
        raise Exception(data["error"].get("message"))

    return data


# =========================
# FETCH EMAILS
# =========================
def fetch_emails(user_id, session_id=None, folder_id=None):

    if folder_id:
        url = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_id}/messages?$top=20&$orderby=receivedDateTime desc"
    else:
        url = "https://graph.microsoft.com/v1.0/me/messages?$top=50&$orderby=receivedDateTime desc"

    data = graph_request(url, user_id, session_id)

    return [
        {
            "id": e.get("id"),
            "conversationId": e.get("conversationId"),
            "subject": e.get("subject"),
            "from": e.get("from", {}).get("emailAddress", {}).get("address"),
            "preview": e.get("bodyPreview"),
            "date": e.get("receivedDateTime"),
            "isRead": e.get("isRead")
        }
        for e in data.get("value", [])
    ]


# =========================
# GET CONVERSATION
# =========================
def get_conversation(user_id, session_id, conversation_id):

    url = f"https://graph.microsoft.com/v1.0/me/messages?$filter=conversationId eq '{conversation_id}'&$orderby=receivedDateTime asc"

    data = graph_request(url, user_id, session_id)

    return data.get("value", [])


# =========================
# GET FOLDERS
# =========================
def get_mail_folders(user_id, session_id=None):

    url = "https://graph.microsoft.com/v1.0/me/mailFolders"

    data = graph_request(url, user_id, session_id)

    return [
        {"id": f.get("id"), "name": f.get("displayName")}
        for f in data.get("value", [])
    ]


# =========================
# EMAIL DETAIL
# =========================
def get_email_detail(user_id, session_id, message_id):

    access_token = get_valid_token(user_id, session_id)

    headers = {"Authorization": f"Bearer {access_token}"}

    msg = requests.get(
        f"https://graph.microsoft.com/v1.0/me/messages/{message_id}",
        headers=headers
    ).json()

    att_res = requests.get(
        f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/attachments",
        headers=headers
    ).json()

    attachments = []

    for a in att_res.get("value", []):
        if a.get("@odata.type") == "#microsoft.graph.fileAttachment":
            attachments.append({
                "name": a.get("name"),
                "type": a.get("contentType"),
                "contentBytes": a.get("contentBytes")
            })

    return {
        "id": msg.get("id"),
        "conversationId": msg.get("conversationId"),
        "subject": msg.get("subject"),
        "from": msg.get("from", {}).get("emailAddress", {}).get("address"),
        "body": msg.get("body", {}).get("content"),
        "attachments": attachments
    }


# =========================
# SEND EMAIL
# =========================
def send_email(user_id, session_id, to, subject, body, files=None):

    access_token = get_valid_token(user_id, session_id)

    attachments = []

    if files:
        for f in files:
            attachments.append({
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": f["name"],
                "contentType": f["type"],
                "contentBytes": f["contentBytes"]
            })

    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body},
            "toRecipients": [{"emailAddress": {"address": to}}],
            "attachments": attachments
        }
    }

    headers = {
        "Authorization": f"Bearer {access_token},
        "Content-Type": "application/json"
    }

    res = requests.post(
        "https://graph.microsoft.com/v1.0/me/sendMail",
        headers=headers,
        json=payload
    )

    if res.status_code != 202:
        raise Exception(res.text)

    return {"status": "Email sent"}