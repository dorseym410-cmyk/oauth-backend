import requests
from datetime import datetime
from urllib.parse import quote

from auth import get_token, refresh_token

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


def graph_id(value):
    """
    Safely encode Microsoft Graph path IDs.
    Message and folder IDs often contain characters that should not be placed
    raw inside a URL path.
    """
    if value is None:
        return ""
    return quote(str(value), safe="")


def extract_graph_error(response):
    try:
        err_json = response.json()
        error = err_json.get("error", {})
        if isinstance(error, dict):
            return (
                error.get("message")
                or error.get("code")
                or err_json.get("message")
                or response.text
            )
        return err_json.get("message") or str(error) or response.text
    except Exception:
        return response.text or "Microsoft Graph request failed"


# =========================
# TOKEN HELPERS
# =========================

def is_token_expired(token_record):
    if not token_record:
        return True

    if not getattr(token_record, "expires_at", None):
        return True

    # Refresh a little early so requests do not fail mid-call.
    return int(token_record.expires_at) <= int(datetime.utcnow().timestamp()) + 120


def get_valid_token(user_id):
    token_record = get_token(user_id)

    if not token_record:
        raise Exception(f"No Microsoft token found for {user_id}. Connect this mailbox again.")

    if is_token_expired(token_record):
        print(f"🔄 Token expired for {user_id}, refreshing...")
        refreshed = refresh_token(user_id)

        if not refreshed or "access_token" not in refreshed:
            raise Exception("Token refresh failed. Reconnect this mailbox.")

        return refreshed["access_token"]

    return token_record.access_token


# =========================
# GENERIC GRAPH REQUEST
# =========================

def graph_request(method, url, user_id, json=None, params=None):
    if not user_id:
        raise Exception("user_id is required for Microsoft Graph requests.")

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

    # Retry once if token is stale or revoked.
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
        message = extract_graph_error(response)

        if response.status_code in (401, 403):
            raise Exception(
                f"Microsoft Graph authorization failed for {user_id}: {message}. "
                "Reconnect the mailbox or confirm the app has the required delegated permissions."
            )

        if response.status_code == 404:
            raise Exception(f"Microsoft Graph item not found: {message}")

        if response.status_code == 429:
            raise Exception(f"Microsoft Graph throttled the request: {message}")

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
        url = f"{GRAPH_BASE_URL}/me/mailFolders/{graph_id(folder_id)}/messages"
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
    url = f"{GRAPH_BASE_URL}/me/messages/{graph_id(message_id)}"
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

    if not to:
        raise Exception("Recipient email is required.")

    to_recipients = []
    for addr in [x.strip() for x in (to or "").split(",") if x.strip()]:
        to_recipients.append({"emailAddress": {"address": addr}})

    if not to_recipients:
        raise Exception("At least one valid recipient email is required.")

    payload = {
        "message": {
            "subject": subject or "",
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
    if not message_id:
        raise Exception("message_id is required.")
    if not reply_text:
        raise Exception("reply_text is required.")

    url = f"{GRAPH_BASE_URL}/me/messages/{graph_id(message_id)}/reply"

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
    if not message_id:
        raise Exception("message_id is required.")
    if not to:
        raise Exception("Forward recipient is required.")

    url = f"{GRAPH_BASE_URL}/me/messages/{graph_id(message_id)}/forward"

    to_recipients = []
    for addr in [x.strip() for x in (to or "").split(",") if x.strip()]:
        to_recipients.append({"emailAddress": {"address": addr}})

    if not to_recipients:
        raise Exception("At least one valid forward recipient email is required.")

    payload = {
        "toRecipients": to_recipients,
    }

    graph_request("POST", url, user_id, json=payload)
    return {"success": True, "message": "Email forwarded successfully"}


# =========================
# DELETE / READ / MOVE
# =========================

def delete_email(user_id, message_id):
    if not message_id:
        raise Exception("message_id is required.")

    url = f"{GRAPH_BASE_URL}/me/messages/{graph_id(message_id)}"
    graph_request("DELETE", url, user_id)
    return {"success": True, "message": "Email deleted successfully"}


def mark_as_read(user_id, message_id, is_read=True):
    if not message_id:
        raise Exception("message_id is required.")

    url = f"{GRAPH_BASE_URL}/me/messages/{graph_id(message_id)}"
    payload = {"isRead": bool(is_read)}
    graph_request("PATCH", url, user_id, json=payload)

    return {
        "success": True,
        "message": "Email marked as read" if bool(is_read) else "Email marked as unread",
        "isRead": bool(is_read),
    }


def move_email_to_folder(user_id, message_id, folder_id):
    if not message_id:
        raise Exception("message_id is required.")
    if not folder_id:
        raise Exception("folder_id is required.")

    url = f"{GRAPH_BASE_URL}/me/messages/{graph_id(message_id)}/move"
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
    if not conversation_id:
        raise Exception("conversation_id is required.")

    safe_conversation_id = str(conversation_id).replace("'", "''")
    url = f"{GRAPH_BASE_URL}/me/messages"
    params = {
        "$filter": f"conversationId eq '{safe_conversation_id}'",
        "$orderby": "receivedDateTime asc",
        "$select": (
            "id,subject,from,sender,receivedDateTime,"
            "isRead,bodyPreview,conversationId,webLink"
        ),
        "$top": 100,
    }

    data = graph_request("GET", url, user_id, params=params)
    return [normalize_email_item(item) for item in data.get("value", [])]