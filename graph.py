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

    if is_token_expired(token_record):
        print("🔄 Token expired, refreshing...")
        refreshed = refresh_token(user_id, session_id)

        if not refreshed or "access_token" not in refreshed:
            raise Exception("❌ Token refresh failed.")

        return refreshed["access_token"]

    return token_record.access_token

# =========================
# HELPER: REQUEST WITH RETRY
# =========================
def graph_request(url, user_id, session_id):
    access_token = get_valid_token(user_id, session_id)

    headers = {"Authorization": f"Bearer {access_token}"}

    res = requests.get(url, headers=headers)

    if res.status_code == 401:
        print("⚠️ 401 → refreshing token")
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
# GET CONVERSATION
# =========================
def get_conversation(user_id, session_id, conversation_id):
    url = f"https://graph.microsoft.com/v1.0/me/messages?$filter=conversationId eq '{conversation_id}'&$orderby=receivedDateTime asc"
    data = graph_request(url, user_id, session_id)
    return data.get("value", [])

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

    return {
        "id": msg.get("id"),
        "conversationId": msg.get("conversationId"),
        "subject": msg.get("subject"),
        "from": msg.get("from", {}).get("emailAddress", {}).get("address"),
        "body": msg.get("body", {}).get("content")
    }

# =========================
# SEND EMAIL
# =========================
def send_email(user_id, session_id, to, subject, body, files=None):
    access_token = get_valid_token(user_id, session_id)

    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body},
            "toRecipients": [{"emailAddress": {"address": to}}]
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

    if res.status_code != 202:
        raise Exception(res.text)

    return {"status": "Email sent"}

# =========================
# REPLY EMAIL ✅
# =========================
def reply_to_email(user_id, session_id, message_id, message, attachments=None):
    access_token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/reply"

    payload = {
        "message": {
            "body": {
                "contentType": "HTML",
                "content": message
            }
        }
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 202]:
        raise Exception(res.text)

    return {"status": "Reply sent"}

# =========================
# FORWARD EMAIL ✅
# =========================
def forward_email(user_id, session_id, message_id, to):
    access_token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/forward"

    payload = {
        "toRecipients": [{"emailAddress": {"address": to}}]
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
# DELETE EMAIL ✅
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
# MARK AS READ ✅
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

    if res.status_code != 200:
        raise Exception(res.text)

    return {"status": "Updated"}

# =========================
# MOVE EMAIL TO FOLDER ✅
# =========================
def move_email_to_folder(user_id, session_id, message_id, folder_id):
    """
    Move an email to a different folder.
    
    :param message_id: The ID of the email to move.
    :param folder_id: The ID of the target folder.
    """
    access_token = get_valid_token(user_id, session_id)

    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/move"

    payload = {
        "destinationId": folder_id
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 202]:
        raise Exception(f"Error moving email: {res.text}")

    return {"status": f"Email {message_id} moved to folder {folder_id}"}
