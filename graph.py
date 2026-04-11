# graph.py
import requests
from auth import get_token, refresh_token
from datetime import datetime
import base64


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
        raise Exception("No token found.")

    access_token = token_record.access_token

    if is_token_expired(token_record):
        refreshed = refresh_token(user_id, session_id)
        access_token = refreshed["access_token"]

    return access_token


# =========================
# FETCH EMAILS
# =========================
def fetch_emails(user_id, session_id=None, folder_id=None):
    access_token = get_valid_token(user_id, session_id)

    headers = {"Authorization": f"Bearer {access_token}"}

    if folder_id:
        url = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_id}/messages?$top=20&$orderby=receivedDateTime desc"
    else:
        url = "https://graph.microsoft.com/v1.0/me/messages?$top=50&$orderby=receivedDateTime desc"

    res = requests.get(url, headers=headers)

    if res.status_code == 401:
        access_token = get_valid_token(user_id, session_id)
        headers["Authorization"] = f"Bearer {access_token}"
        res = requests.get(url, headers=headers)

    data = res.json()

    if "error" in data:
        raise Exception(data["error"].get("message"))

    return [
        {
            "id": e.get("id"),
            "conversationId": e.get("conversationId"),  # ✅ THREADING
            "subject": e.get("subject"),
            "from": e.get("from", {}).get("emailAddress", {}).get("address"),
            "preview": e.get("bodyPreview"),
            "date": e.get("receivedDateTime"),
            "isRead": e.get("isRead")
        }
        for e in data.get("value", [])
    ]


# =========================
# GET CONVERSATION (THREAD)
# =========================
def get_conversation(user_id, session_id, conversation_id):
    access_token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages?$filter=conversationId eq '{conversation_id}'&$orderby=receivedDateTime asc"

    headers = {"Authorization": f"Bearer {access_token}"}

    res = requests.get(url, headers=headers)
    data = res.json()

    if "error" in data:
        raise Exception(data["error"].get("message"))

    return data.get("value", [])


# =========================
# GET FOLDERS
# =========================
def get_mail_folders(user_id, session_id=None):
    access_token = get_valid_token(user_id, session_id)

    headers = {"Authorization": f"Bearer {access_token}"}
    url = "https://graph.microsoft.com/v1.0/me/mailFolders"

    res = requests.get(url, headers=headers)
    data = res.json()

    if "error" in data:
        raise Exception(data["error"].get("message"))

    return [
        {"id": f.get("id"), "name": f.get("displayName")}
        for f in data.get("value", [])
    ]


# =========================
# EMAIL DETAIL + ATTACHMENTS
# =========================
def get_email_detail(user_id, session_id, message_id):
    access_token = get_valid_token(user_id, session_id)

    headers = {"Authorization": f"Bearer {access_token}"}

    msg_url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}"
    msg = requests.get(msg_url, headers=headers).json()

    att_url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/attachments"
    att_res = requests.get(att_url, headers=headers).json()

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
# SEND EMAIL (WITH ATTACHMENTS)
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
                "contentBytes": f["contentBytes"]  # base64 string
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
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    res = requests.post(
        "https://graph.microsoft.com/v1.0/me/sendMail",
        headers=headers,
        json=payload
    )

    if res.status_code not in [202]:
        raise Exception(res.text)

    return {"status": "Email sent with attachments"}


# =========================
# REPLY WITH ATTACHMENTS
# =========================
def reply_to_email(user_id, session_id, message_id, reply_text, files=None):
    access_token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/reply"

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
            "body": {
                "contentType": "HTML",
                "content": reply_text
            },
            "attachments": attachments
        }
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 202]:
        raise Exception(res.text)

    return {"status": "Reply sent with attachments"}


# =========================
# FORWARD
# =========================
def forward_email(user_id, session_id, message_id, to):
    access_token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/forward"

    payload = {
        "toRecipients": [
            {"emailAddress": {"address": to}}
        ]
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 202]:
        raise Exception(res.text)

    return {"status": "Forwarded"}


# =========================
# DELETE EMAIL
# =========================
def delete_email(user_id, session_id, message_id):
    access_token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}"
    headers = {"Authorization": f"Bearer {access_token}"}

    res = requests.delete(url, headers=headers)

    if res.status_code != 204:
        raise Exception(res.text)

    return {"status": "Deleted"}


# =========================
# MARK READ / UNREAD
# =========================
def mark_as_read(user_id, session_id, message_id, is_read=True):
    access_token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    payload = {"isRead": is_read}

    res = requests.patch(url, headers=headers, json=payload)

    if res.status_code not in [200]:
        raise Exception(res.text)

    return {"status": "Updated"}


# =========================
# MOVE EMAIL TO FOLDER (FIXED)
# =========================
def move_email_to_folder(user_id, session_id, message_id, target_folder_id):
    access_token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/move"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "destinationId": target_folder_id
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 201]:
        raise Exception(f"Move failed: {res.text}")

    return {"status": "Moved"}