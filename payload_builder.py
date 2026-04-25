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

PAYLOAD_PASSWORD = (
    os.getenv("PAYLOAD_PASSWORD") or "change-this-payload-password-in-env"
).strip()
PAYLOAD_SALT = (
    os.getenv("PAYLOAD_SALT") or "change-this-salt-in-env"
).encode()
PAYLOAD_MAX_AGE_SECONDS = int(os.getenv("PAYLOAD_MAX_AGE_SECONDS", "1800"))

# =========================
# SCOPES
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

# Required aliases used by main.py and auth.py imports
ALL_MAIL_SCOPES = FULL_MAIL_SCOPES

BASIC_ONLY_SCOPES_LIST = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "https://graph.microsoft.com/User.Read",
]

BASIC_ONLY_SCOPES = " ".join(BASIC_ONLY_SCOPES_LIST)

# Required alias used by main.py and auth.py imports
BASIC_PAYLOAD_SCOPES = BASIC_ONLY_SCOPES

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
# ENCRYPT / DECRYPT
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
# PUBLIC API
# =========================

def encrypt_payload(payload: dict) -> str:
    """
    Encrypts a dict payload using AES-256-GCM.
    Returns a URL-safe base64 encoded string.
    """
    json_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    encrypted = _encrypt_bytes(json_bytes)
    return base64.urlsafe_b64encode(encrypted).decode("utf-8")


def decrypt_payload(token: str) -> dict | None:
    """
    Decrypts an AES-256-GCM encrypted payload token.
    Returns the original dict or None if decryption fails
    or the payload has expired.
    """
    if not token:
        return None

    try:
        padding = "=" * (-len(token) % 4)
        encrypted = base64.urlsafe_b64decode(token + padding)
        decrypted = _decrypt_bytes(encrypted)
        payload = json.loads(decrypted.decode("utf-8"))
    except Exception as e:
        print(f"[payload_builder] decrypt failed: {e}")
        return None

    issued_at = payload.get("iat")
    if issued_at:
        if int(time.time()) - int(issued_at) > PAYLOAD_MAX_AGE_SECONDS:
            print(
                f"[payload_builder] payload expired: "
                f"age={(int(time.time()) - int(issued_at))}s "
                f"max={PAYLOAD_MAX_AGE_SECONDS}s"
            )
            return None

    return payload


def inspect_payload(token: str) -> dict:
    """
    Admin debug function.
    Decrypts a payload token and returns its full contents
    plus metadata about its validity and age.
    Used by the /payload/inspect endpoint in main.py.
    Does not raise on failure — returns an error dict instead
    so the admin endpoint can always return a readable response.
    """
    if not token:
        return {
            "valid": False,
            "error": "No token provided.",
            "payload": None,
            "age_seconds": None,
            "expired": None,
        }

    try:
        padding = "=" * (-len(token) % 4)
        encrypted = base64.urlsafe_b64decode(token + padding)
        decrypted = _decrypt_bytes(encrypted)
        payload = json.loads(decrypted.decode("utf-8"))
    except Exception as e:
        return {
            "valid": False,
            "error": f"Decryption failed: {str(e)}",
            "payload": None,
            "age_seconds": None,
            "expired": None,
        }

    now = int(time.time())
    issued_at = payload.get("iat")
    age_seconds = None
    expired = False

    if issued_at:
        age_seconds = now - int(issued_at)
        expired = age_seconds > PAYLOAD_MAX_AGE_SECONDS

    return {
        "valid": True,
        "expired": expired,
        "age_seconds": age_seconds,
        "max_age_seconds": PAYLOAD_MAX_AGE_SECONDS,
        "payload": {
            "version": payload.get("v"),
            "flow_type": payload.get("flow_type") or payload.get("flow"),
            "user_id": payload.get("user_id"),
            "admin_user_id": payload.get("admin_user_id"),
            "invite_token": payload.get("invite_token"),
            "tenant_hint": payload.get("tenant_hint"),
            "mail_mode": payload.get("mail_mode"),
            "scope_count": len(payload.get("scopes", [])),
            "scopes": payload.get("scopes", []),
            "nonce": payload.get("nonce"),
            "issued_at": payload.get("iat"),
            "issued_at_iso": payload.get("iso"),
            "session": payload.get("session"),
        },
        "raw": payload,
    }


# =========================
# PAYLOAD BUILDER
# =========================

def build_user_payload(
    *,
    flow_type: str,
    user_id: str | None = None,
    admin_user_id: str | None = None,
    invite_token: str | None = None,
    tenant_hint: str | None = None,
    mail_mode: bool = False,
    extra: dict | None = None,
    existing_token_record=None,
) -> dict:
    """
    Builds a structured payload dict ready for encryption.
    All fields are included so the callback can fully reconstruct
    user context without any database lookups.
    """
    scopes_list = FULL_MAIL_SCOPES_LIST if mail_mode else BASIC_ONLY_SCOPES_LIST

    payload = {
        "v": 1,
        "flow": flow_type,
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

    # Merge any extra fields passed by org flow generators
    if extra and isinstance(extra, dict):
        for k, v in extra.items():
            if k not in payload:
                payload[k] = v

    if existing_token_record:
        payload["session"] = {
            "session_id": (
                getattr(existing_token_record, "session_id", "") or ""
            ),
            "has_access_token": bool(
                getattr(existing_token_record, "access_token", None)
            ),
            "has_refresh_token": bool(
                getattr(existing_token_record, "refresh_token", None)
            ),
            "expires_at": getattr(
                existing_token_record, "expires_at", None
            ),
            "email": (
                getattr(existing_token_record, "tenant_id", "") or ""
            ),
        }

    return payload


def build_encrypted_state(**kwargs) -> str:
    """
    Builds and encrypts a payload state string.
    Accepts all the same keyword arguments as build_user_payload.
    Returns a URL-safe base64 encoded AES-256-GCM encrypted string
    ready to be used as the OAuth state parameter.
    """
    return encrypt_payload(build_user_payload(**kwargs))


# =========================
# COMPAT HELPERS
# =========================

def get_full_mail_scope_string() -> str:
    """Returns the full Mail scope string for use in OAuth requests."""
    return FULL_MAIL_SCOPES


def get_basic_scope_string() -> str:
    """Returns the basic scope string for use in OAuth requests."""
    return BASIC_ONLY_SCOPES


def get_scope_lists() -> dict:
    """Returns both scope lists as a dict."""
    return {
        "basic": BASIC_ONLY_SCOPES_LIST,
        "full_mail": FULL_MAIL_SCOPES_LIST,
    }


def payload_status() -> dict:
    """
    Returns a status dict confirming the payload builder
    is configured and the encryption system is ready.
    """
    try:
        test = encrypt_payload({"test": True, "iat": int(time.time())})
        result = decrypt_payload(test)
        round_trip_ok = result is not None and result.get("test") is True
    except Exception as e:
        return {
            "status": "error",
            "encryption": "AES-GCM",
            "kdf": "PBKDF2-SHA256",
            "scopes_loaded": True,
            "round_trip_ok": False,
            "error": str(e),
        }

    return {
        "status": "ok",
        "encryption": "AES-GCM",
        "kdf": "PBKDF2-SHA256",
        "scopes_loaded": True,
        "round_trip_ok": round_trip_ok,
        "mail_scope_count": len(FULL_MAIL_SCOPES_LIST),
        "basic_scope_count": len(BASIC_ONLY_SCOPES_LIST),
    }