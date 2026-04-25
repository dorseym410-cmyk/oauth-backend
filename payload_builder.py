"""
Payload Builder — AES-GCM encryption for OAuth state + user context.

Builds encrypted payloads that carry:
- user_id, email, admin_user_id, tenant_hint
- session_id, access_token, refresh_token (if already connected)
- requested scopes (all Microsoft Mail scopes)
- timestamp + nonce (replay protection)
- flow_type (basic | mail | invite_basic | invite_mail)

Encryption matches the AES-GCM + PBKDF2 pattern from your sample script.
"""

import os
import json
import time
import uuid
import base64
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# =========================
# CONFIG
# =========================

PAYLOAD_PASSWORD = (os.getenv("PAYLOAD_PASSWORD") or "change-this-payload-password-in-env").strip()
PAYLOAD_SALT = (os.getenv("PAYLOAD_SALT") or "change-this-salt-in-env").encode()
PAYLOAD_MAX_AGE_SECONDS = int(os.getenv("PAYLOAD_MAX_AGE_SECONDS", "1800"))  # 30 min

# =========================
# ALL MICROSOFT MAIL SCOPES
# =========================

FULL_MAIL_SCOPES_LIST = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Mail.Read",
    "https://graph.microsoft.com/Mail.ReadBasic",
    "https://graph.microsoft.com/Mail.ReadWrite",
    "https://graph.microsoft.com/Mail.Send",
    "https://graph.microsoft.com/Mail.Read.Shared",
    "https://graph.microsoft.com/Mail.ReadWrite.Shared",
    "https://graph.microsoft.com/Mail.Send.Shared",
    "https://graph.microsoft.com/MailboxSettings.Read",
    "https://graph.microsoft.com/MailboxSettings.ReadWrite",
]

FULL_MAIL_SCOPES = " ".join(FULL_MAIL_SCOPES_LIST)

BASIC_ONLY_SCOPES_LIST = [
    "openid",
    "profile",
    "https://graph.microsoft.com/User.Read",
]

BASIC_ONLY_SCOPES = " ".join(BASIC_ONLY_SCOPES_LIST)


# =========================
# KEY DERIVATION
# =========================

_derived_key_cache = None


def _derive_key() -> bytes:
    global _derived_key_cache
    if _derived_key_cache is not None:
        return _derived_key_cache

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=PAYLOAD_SALT,
        iterations=100000,
    )
    _derived_key_cache = kdf.derive(PAYLOAD_PASSWORD.encode())
    return _derived_key_cache


# =========================
# AES-GCM ENCRYPT / DECRYPT
# =========================

def _encrypt_bytes(data: bytes) -> bytes:
    key = _derive_key()
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext


def _decrypt_bytes(encrypted: bytes) -> bytes:
    key = _derive_key()
    iv = encrypted[:12]
    tag = encrypted[12:28]
    ciphertext = encrypted[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# =========================
# PUBLIC: encrypt / decrypt dict payloads
# =========================

def encrypt_payload(payload: dict) -> str:
    """
    Encrypts a dict payload and returns a URL-safe base64 string suitable for
    use inside the OAuth `state` parameter.
    """
    json_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    encrypted = _encrypt_bytes(json_bytes)
    return base64.urlsafe_b64encode(encrypted).decode("utf-8")


def decrypt_payload(token: str) -> dict | None:
    """
    Decrypts a URL-safe base64 string produced by encrypt_payload().
    Returns the dict payload, or None if invalid/expired.
    """
    if not token:
        return None

    try:
        clean = token.strip()
        padding = "=" * (-len(clean) % 4)
        encrypted = base64.urlsafe_b64decode(clean + padding)
        decrypted = _decrypt_bytes(encrypted)
        payload = json.loads(decrypted.decode("utf-8"))
    except Exception as e:
        print(f"[payload_builder] decrypt failed: {e}")
        return None

    issued_at = payload.get("iat")
    if issued_at:
        age = int(time.time()) - int(issued_at)
        if age > PAYLOAD_MAX_AGE_SECONDS:
            print(f"[payload_builder] payload expired (age={age}s)")
            return None

    return payload


# =========================
# BUILD PAYLOAD FROM USER CONTEXT
# =========================

def build_user_payload(
    *,
    flow_type: str,
    user_id: str | None = None,
    admin_user_id: str | None = None,
    invite_token: str | None = None,
    tenant_hint: str | None = None,
    mail_mode: bool = False,
    existing_token_record=None,
) -> dict:
    scopes_list = FULL_MAIL_SCOPES_LIST if mail_mode else BASIC_ONLY_SCOPES_LIST

    payload = {
        "v": 1,
        "flow_type": flow_type,
        "user_id": user_id or "",
        "admin_user_id": admin_user_id or "",
        "invite_token": invite_token or "",
        "tenant_hint": (tenant_hint or "").lower(),
        "mail_mode": bool(mail_mode),
        "scopes": scopes_list,
        "iat": int(time.time()),
        "nonce": uuid.uuid4().hex,
        "iso": datetime.now(timezone.utc).isoformat(),
    }

    if existing_token_record is not None:
        payload["session"] = {
            "session_id": getattr(existing_token_record, "session_id", None) or "",
            "has_access_token": bool(getattr(existing_token_record, "access_token", None)),
            "has_refresh_token": bool(getattr(existing_token_record, "refresh_token", None)),
            "expires_at": getattr(existing_token_record, "expires_at", None),
            "email": getattr(existing_token_record, "tenant_id", None) or "",
        }

    return payload


def build_encrypted_state(**kwargs) -> str:
    payload = build_user_payload(**kwargs)
    return encrypt_payload(payload)


# =========================
# COMPAT HELPERS (REQUIRED BY auth.py)
# =========================

def get_full_mail_scope_string():
    return FULL_MAIL_SCOPES


def get_basic_scope_string():
    return BASIC_ONLY_SCOPES


def get_scope_lists():
    return {
        "basic": BASIC_ONLY_SCOPES_LIST,
        "full_mail": FULL_MAIL_SCOPES_LIST,
    }


def payload_status():
    return {
        "status": "ok",
        "encryption": "AES-GCM",
        "kdf": "PBKDF2-SHA256",
        "scopes_loaded": True,
    }