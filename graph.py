import requests
from datetime import datetime

from auth import get_token, refresh_token

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


# =========================
# TOKEN HELPERS
# =========================

def is_token_expired(token_record):
    if not token_record:
        return True

    if not getattr(token_record, "expires_at", None):
        return True

    return token_record.expires_at < int(datetime.utcnow().timestamp())


def get_valid_token(user_id):
    token_record = get_token(user_id)

    if not token_record:
        raise Exception("❌ No token found. Please login again.")

    if is_token_expired(token_record):
        print(f"🔄 Token expired for {user_id}, refreshing...")
        refreshed = refresh_token(user_id)

        if not refreshed or "access_token" not in refreshed:
            raise Exception("❌ Token refresh failed.")

        return refreshed["access_token"]

    return token_record.access_token


# =========================
# GENERIC GRAPH REQUEST
# =========================

def graph_request(method, url, user_id, json=None, params=None):
    access_token = get_valid_token(user_id)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        json=json,
        params=params,
        timeout=60,
    )

    # Retry once if token is stale
    if response.status_code == 401:
        print(f"🔄 401 from Graph for {user_id}, attempting refresh...")
        refreshed = refresh_token(user_id)

        if refreshed and "access_token" in refreshed:
            headers["Authorization"] = f"Bearer {refreshed['access_token']}"
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json,
                params=params,
                timeout=60,
            )

    if not response.ok:
        try:
            err_json = response.json()
            message = (
                err_json.get("error", {}).get("message")
                or err_json.get("message")
                or response.text
            )
        except Exception:
            message = response.text or "Microsoft Graph request failed"

        raise Exception(message)

    if response.status_code == 204:
        return {"success": True}

    if not response.text:
        return {"success": True}

    return response.json()


# =========================
# NORMALIZERS
# =========================

def normalize_sender(item):
    return (
        item.get("from", {})
        .get("emailAddress", {})
        .get("address")
        or item.get("sender", {})
        .get("emailAddress", {})
        .get("address")
        or "Unknown"
    )


def normalize_recipients(entries):
    output = []
    for entry in entries or []:
        addr = entry.get("emailAddress", {}).get("address")
        if addr:
            output.append(addr)
    return output


def normalize_email_item(item):
    return {
        "id": item.get("id"),
        "subject": item.get("subject") or "(No Subject)",
        "from": normalize_sender(item),
        "date": item.get("receivedDateTime") or item.get("sentDateTime") or "",
        "isRead": item.get("isRead", False),
        "bodyPreview": item.get("bodyPreview", ""),
        "conversationId": item.get("conversationId"),
        "webLink": item.get("webLink"),
    }


# =========================
# MAIL LIST / FOLDERS / DETAIL
# =========================

def fetch_emails(user_id, folder_id=None):
    if folder_id:
        url = f"{GRAPH_BASE_URL}/me/mailFolders/{folder_id}/messages"
    else:
        url = f"{GRAPH_BASE_URL}/me/messages"

    params = {
        "$top": 50,
        "$orderby": "receivedDateTime desc",
        "$select": (
            "id,subject,from,sender,receivedDateTime,sentDateTime,"
            "isRead,bodyPreview,conversationId,webLink"
        ),
    }

    data = graph_request("GET", url, user_id, params=params)
    return [normalize_email_item(item) for item in data.get("value", [])]


def get_mail_folders(user_id):
    url = f"{GRAPH_BASE_URL}/me/mailFolders"
    params = {
        "$top": 100,
        "$select": "id,displayName,childFolderCount,totalItemCount,unreadItemCount",
    }

    data = graph_request("GET", url, user_id, params=params)

    folders = []
    for folder in data.get("value", []):
        folders.append(
            {
                "id": folder.get("id"),
                "name": folder.get("displayName"),
                "childFolderCount": folder.get("childFolderCount", 0),
                "totalItemCount": folder.get("totalItemCount", 0),
                "unreadItemCount": folder.get("unreadItemCount", 0),
            }
        )

    return folders


def get_email_detail(user_id, message_id):
    url = f"{GRAPH_BASE_URL}/me/messages/{message_id}"
    params = {
        "$select": (
            "id,subject,from,toRecipients,ccRecipients,bccRecipients,"
            "receivedDateTime,sentDateTime,isRead,body,bodyPreview,"
            "conversationId,webLink,hasAttachments"
        )
    }

    data = graph_request("GET", url, user_id, params=params)

    return {
        "id": data.get("id"),
        "subject": data.get("subject") or "(No Subject)",
        "from": normalize_sender(data),
        "to": normalize_recipients(data.get("toRecipients")),
        "cc": normalize_recipients(data.get("ccRecipients")),
        "bcc": normalize_recipients(data.get("bccRecipients")),
        "date": data.get("receivedDateTime") or data.get("sentDateTime") or "",
        "isRead": data.get("isRead", False),
        "body": (data.get("body") or {}).get("content") or data.get("bodyPreview") or "",
        "bodyType": (data.get("body") or {}).get("contentType") or "text",
        "bodyPreview": data.get("bodyPreview", ""),
        "conversationId": data.get("conversationId"),
        "webLink": data.get("webLink"),
        "hasAttachments": data.get("hasAttachments", False),
    }


# =========================
# SEND / REPLY / FORWARD
# =========================

def send_email(user_id, to, subject, body):
    url = f"{GRAPH_BASE_URL}/me/sendMail"

    to_recipients = []
    for addr in [x.strip() for x in (to or "").split(",") if x.strip()]:
        to_recipients.append({"emailAddress": {"address": addr}})

    payload = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": body,
            },
            "toRecipients": to_recipients,
        },
        "saveToSentItems": True,
    }

    graph_request("POST", url, user_id, json=payload)
    return {"success": True, "message": "Email sent successfully"}


def reply_to_email(user_id, message_id, reply_text):
    url = f"{GRAPH_BASE_URL}/me/messages/{message_id}/reply"

    payload = {
        "message": {
            "body": {
                "contentType": "HTML",
                "content": reply_text,
            }
        }
    }

    graph_request("POST", url, user_id, json=payload)
    return {"success": True, "message": "Reply sent successfully"}


def forward_email(user_id, message_id, to):
    url = f"{GRAPH_BASE_URL}/me/messages/{message_id}/forward"

    to_recipients = []
    for addr in [x.strip() for x in (to or "").split(",") if x.strip()]:
        to_recipients.append({"emailAddress": {"address": addr}})

    payload = {
        "toRecipients": to_recipients,
    }

    graph_request("POST", url, user_id, json=payload)
    return {"success": True, "message": "Email forwarded successfully"}


# =========================
# DELETE / READ / MOVE
# =========================

def delete_email(user_id, message_id):
    url = f"{GRAPH_BASE_URL}/me/messages/{message_id}"
    graph_request("DELETE", url, user_id)
    return {"success": True, "message": "Email deleted successfully"}


def mark_as_read(user_id, message_id):
    url = f"{GRAPH_BASE_URL}/me/messages/{message_id}"
    payload = {"isRead": True}
    graph_request("PATCH", url, user_id, json=payload)
    return {"success": True, "message": "Email marked as read"}


def move_email_to_folder(user_id, message_id, folder_id):
    url = f"{GRAPH_BASE_URL}/me/messages/{message_id}/move"
    payload = {"destinationId": folder_id}
    data = graph_request("POST", url, user_id, json=payload)

    return {
        "success": True,
        "message": "Email moved successfully",
        "moved_message_id": data.get("id"),
    }


# =========================
# CONVERSATION
# =========================

def get_conversation(user_id, conversation_id):
    url = f"{GRAPH_BASE_URL}/me/messages"
    params = {
        "$filter": f"conversationId eq '{conversation_id}'",
        "$orderby": "receivedDateTime asc",
        "$select": (
            "id,subject,from,sender,receivedDateTime,"
            "isRead,bodyPreview,conversationId,webLink"
        ),
        "$top": 100,
    }

    data = graph_request("GET", url, user_id, params=params)
    return [normalize_email_item(item) for item in data.get("value", [])]