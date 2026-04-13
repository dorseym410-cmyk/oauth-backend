# graph.py
import requests
from auth import get_token, refresh_token
from datetime import datetime
from urllib.parse import quote


# =========================
# HELPER: CHECK EXPIRY
# =========================
def is_token_expired(token_record):
    return token_record.expires_at < int(datetime.utcnow().timestamp())


# =========================
# HELPER: GET VALID TOKEN
# =========================
def get_valid_token(user_id):
    token_record = get_token(user_id)

    if not token_record:
        raise Exception("No token found. Please connect Microsoft account.")

    if is_token_expired(token_record):
        print("🔄 Token expired, refreshing...")
        refreshed = refresh_token(user_id)

        if not refreshed or "access_token" not in refreshed:
            raise Exception("Token refresh failed. Please re-login.")

        return refreshed["access_token"]

    return token_record.access_token


# =========================
# HELPER: PARSE GRAPH RESPONSE
# =========================
def parse_graph_response(res):
    try:
        data = res.json()
    except Exception:
        raise Exception(f"Graph API error: {res.status_code} - {res.text}")

    if res.status_code >= 400:
        if isinstance(data, dict) and "error" in data:
            raise Exception(data["error"].get("message", "Microsoft Graph request failed"))
        raise Exception(f"Graph API error: {res.status_code}")

    if isinstance(data, dict) and "error" in data:
        raise Exception(data["error"].get("message", "Microsoft Graph request failed"))

    return data


# =========================
# HELPER: REQUEST WITH RETRY
# =========================
def graph_request(method, url, user_id, json=None):
    access_token = get_valid_token(user_id)

    headers = {"Authorization": f"Bearer {access_token}"}
    if json is not None:
        headers["Content-Type"] = "application/json"

    res = requests.request(method, url, headers=headers, json=json)

    if res.status_code == 401:
        print("⚠️ 401 received, forcing token refresh...")
        refreshed = refresh_token(user_id)

        if not refreshed or "access_token" not in refreshed:
            raise Exception("Token refresh failed. Please re-login.")

        headers["Authorization"] = f"Bearer {refreshed['access_token']}"
        res = requests.request(method, url, headers=headers, json=json)

    return parse_graph_response(res)


# =========================
# FETCH EMAILS
# =========================
def fetch_emails(user_id, folder_id=None):
    if folder_id:
        safe_folder_id = quote(folder_id, safe="")
        url = (
            f"https://graph.microsoft.com/v1.0/me/mailFolders/"
            f"{safe_folder_id}/messages?$top=20&$orderby=receivedDateTime desc"
        )
    else:
        url = "https://graph.microsoft.com/v1.0/me/messages?$top=50&$orderby=receivedDateTime desc"

    data = graph_request("GET", url, user_id)

    return [
        {
            "id": e.get("id"),
            "conversationId": e.get("conversationId"),
            "subject": e.get("subject"),
            "from": e.get("from", {}).get("emailAddress", {}).get("address"),
            "preview": e.get("bodyPreview"),
            "date": e.get("receivedDateTime"),
            "isRead": e.get("isRead"),
        }
        for e in data.get("value", [])
    ]


# =========================
# GET CONVERSATION
# =========================
def get_conversation(user_id, conversation_id):
    url = (
        "https://graph.microsoft.com/v1.0/me/messages"
        f"?$filter=conversationId eq '{conversation_id}'&$orderby=receivedDateTime asc"
    )

    data = graph_request("GET", url, user_id)
    return data.get("value", [])


# =========================
# GET FOLDERS
# =========================
def get_mail_folders(user_id):
    url = "https://graph.microsoft.com/v1.0/me/mailFolders"
    data = graph_request("GET", url, user_id)

    return [
        {"id": f.get("id"), "name": f.get("displayName")}
        for f in data.get("value", [])
    ]


# =========================
# EMAIL DETAIL
# =========================
def get_email_detail(user_id, message_id):
    safe_message_id = quote(message_id, safe="")
    url = f"https://graph.microsoft.com/v1.0/me/messages/{safe_message_id}"
    msg = graph_request("GET", url, user_id)

    return {
        "id": msg.get("id"),
        "conversationId": msg.get("conversationId"),
        "subject": msg.get("subject"),
        "from": msg.get("from", {}).get("emailAddress", {}).get("address"),
        "body": msg.get("body", {}).get("content"),
    }


# =========================
# SEND EMAIL
# =========================
def send_email(user_id, to, subject, body, files=None):
    url = "https://graph.microsoft.com/v1.0/me/sendMail"

    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body},
            "toRecipients": [{"emailAddress": {"address": to}}],
        }
    }

    access_token = get_valid_token(user_id)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code == 401:
        refreshed = refresh_token(user_id)
        headers["Authorization"] = f"Bearer {refreshed['access_token']}"
        res = requests.post(url, headers=headers, json=payload)

    if res.status_code != 202:
        try:
            err = res.json()
            if "error" in err:
                raise Exception(err["error"].get("message", res.text))
        except Exception:
            raise Exception(res.text)

    return {"status": "Email sent"}


# =========================
# REPLY EMAIL
# =========================
def reply_to_email(user_id, message_id, reply_text, files=None):
    safe_message_id = quote(message_id, safe="")
    url = f"https://graph.microsoft.com/v1.0/me/messages/{safe_message_id}/reply"

    payload = {
        "message": {
            "body": {
                "contentType": "HTML",
                "content": reply_text,
            }
        }
    }

    access_token = get_valid_token(user_id)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code == 401:
        refreshed = refresh_token(user_id)
        headers["Authorization"] = f"Bearer {refreshed['access_token']}"
        res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 202]:
        try:
            err = res.json()
            if "error" in err:
                raise Exception(err["error"].get("message", res.text))
        except Exception:
            raise Exception(res.text)

    return {"status": "Reply sent"}


# =========================
# FORWARD EMAIL
# =========================
def forward_email(user_id, message_id, to):
    safe_message_id = quote(message_id, safe="")
    url = f"https://graph.microsoft.com/v1.0/me/messages/{safe_message_id}/forward"

    payload = {
        "toRecipients": [{"emailAddress": {"address": to}}]
    }

    access_token = get_valid_token(user_id)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code == 401:
        refreshed = refresh_token(user_id)
        headers["Authorization"] = f"Bearer {refreshed['access_token']}"
        res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 202]:
        try:
            err = res.json()
            if "error" in err:
                raise Exception(err["error"].get("message", res.text))
        except Exception:
            raise Exception(res.text)

    return {"status": "Forwarded"}


# =========================
# DELETE EMAIL
# =========================
def delete_email(user_id, message_id):
    safe_message_id = quote(message_id, safe="")
    url = f"https://graph.microsoft.com/v1.0/me/messages/{safe_message_id}"

    access_token = get_valid_token(user_id)
    headers = {"Authorization": f"Bearer {access_token}"}

    res = requests.delete(url, headers=headers)

    if res.status_code == 401:
        refreshed = refresh_token(user_id)
        headers["Authorization"] = f"Bearer {refreshed['access_token']}"
        res = requests.delete(url, headers=headers)

    if res.status_code != 204:
        try:
            err = res.json()
            if "error" in err:
                raise Exception(err["error"].get("message", res.text))
        except Exception:
            raise Exception(res.text)

    return {"status": "Deleted"}


# =========================
# MARK READ / UNREAD
# =========================
def mark_as_read(user_id, message_id, is_read=True):
    safe_message_id = quote(message_id, safe="")
    url = f"https://graph.microsoft.com/v1.0/me/messages/{safe_message_id}"

    payload = {"isRead": is_read}

    access_token = get_valid_token(user_id)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    res = requests.patch(url, headers=headers, json=payload)

    if res.status_code == 401:
        refreshed = refresh_token(user_id)
        headers["Authorization"] = f"Bearer {refreshed['access_token']}"
        res = requests.patch(url, headers=headers, json=payload)

    if res.status_code != 200:
        try:
            err = res.json()
            if "error" in err:
                raise Exception(err["error"].get("message", res.text))
        except Exception:
            raise Exception(res.text)

    return {"status": "Updated"}


# =========================
# MOVE EMAIL TO FOLDER
# =========================
def move_email_to_folder(user_id, message_id, target_folder_id):
    safe_message_id = quote(message_id, safe="")
    url = f"https://graph.microsoft.com/v1.0/me/messages/{safe_message_id}/move"

    payload = {
        "destinationId": target_folder_id
    }

    access_token = get_valid_token(user_id)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    res = requests.post(url, headers=headers, json=payload)

    if res.status_code == 401:
        refreshed = refresh_token(user_id)
        headers["Authorization"] = f"Bearer {refreshed['access_token']}"
        res = requests.post(url, headers=headers, json=payload)

    if res.status_code not in [200, 201]:
        try:
            err = res.json()
            if "error" in err:
                raise Exception(err["error"].get("message", res.text))
        except Exception:
            raise Exception(f"Move failed: {res.text}")

    return {"status": "Moved"}