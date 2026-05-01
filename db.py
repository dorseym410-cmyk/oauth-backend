import os
import time
import logging

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger(__name__)

# =========================
# DATABASE URL
# =========================
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./app.db",
)

# Fix for Render PostgreSQL URLs that use the legacy
# postgres:// scheme instead of postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://", "postgresql://", 1
    )

IS_SQLITE = DATABASE_URL.startswith("sqlite")
IS_POSTGRES = DATABASE_URL.startswith("postgresql")

# =========================
# ENGINE
# =========================
if IS_SQLITE:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=1800,
    )

# =========================
# SESSION
# =========================
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# =========================
# BASE
# =========================
Base = declarative_base()


# =========================
# MIGRATION DEFINITIONS
# Each entry is a tuple of:
# (table_name, column_name, sqlite_type, postgres_type)
# =========================
MIGRATIONS = [
    # -------------------------------------------------
    # tenant_tokens
    # -------------------------------------------------
    ("tenant_tokens", "session_id",    "VARCHAR",              "VARCHAR"),
    ("tenant_tokens", "email",         "VARCHAR",              "VARCHAR"),
    ("tenant_tokens", "scope_level",   "VARCHAR DEFAULT 'unknown'", "VARCHAR DEFAULT 'unknown'"),
    ("tenant_tokens", "flow_type",     "VARCHAR",              "VARCHAR"),
    ("tenant_tokens", "admin_user_id", "VARCHAR",              "VARCHAR"),
    ("tenant_tokens", "ip_address",    "VARCHAR",              "VARCHAR"),
    ("tenant_tokens", "user_agent",    "TEXT",                 "TEXT"),
    ("tenant_tokens", "location",      "VARCHAR",              "VARCHAR"),
    ("tenant_tokens", "created_at",    "INTEGER",              "INTEGER"),
    ("tenant_tokens", "updated_at",    "INTEGER",              "INTEGER"),
    # -------------------------------------------------
    # saved_users
    # -------------------------------------------------
    ("saved_users", "email",       "VARCHAR", "VARCHAR"),
    ("saved_users", "tenant_hint", "VARCHAR", "VARCHAR"),
    ("saved_users", "job_title",   "VARCHAR", "VARCHAR"),
    ("saved_users", "created_at",  "INTEGER", "INTEGER"),
    ("saved_users", "updated_at",  "INTEGER", "INTEGER"),
    # -------------------------------------------------
    # connect_invites
    # -------------------------------------------------
    ("connect_invites", "connect_mode",   "VARCHAR DEFAULT 'basic'", "VARCHAR DEFAULT 'basic'"),
    ("connect_invites", "tenant_hint",    "VARCHAR", "VARCHAR"),
    ("connect_invites", "resolved_email", "VARCHAR", "VARCHAR"),
    ("connect_invites", "payload_nonce",  "VARCHAR", "VARCHAR"),
    ("connect_invites", "job_title",      "VARCHAR", "VARCHAR"),
    ("connect_invites", "created_at",     "INTEGER", "INTEGER"),
    ("connect_invites", "updated_at",     "INTEGER", "INTEGER"),
    # -------------------------------------------------
    # tenant_consents
    # -------------------------------------------------
    ("tenant_consents", "notes",      "TEXT",    "TEXT"),
    ("tenant_consents", "created_at", "INTEGER", "INTEGER"),
    ("tenant_consents", "updated_at", "INTEGER", "INTEGER"),
    # -------------------------------------------------
    # rules
    # -------------------------------------------------
    ("rules", "target_folder", "VARCHAR",              "VARCHAR"),
    ("rules", "forward_to",    "VARCHAR",              "VARCHAR"),
    ("rules", "is_active",     "BOOLEAN DEFAULT 1",    "BOOLEAN DEFAULT TRUE"),
    ("rules", "created_at",    "INTEGER",              "INTEGER"),
    ("rules", "updated_at",    "INTEGER",              "INTEGER"),
    # -------------------------------------------------
    # alerts
    # -------------------------------------------------
    ("alerts", "user_id",    "VARCHAR",              "VARCHAR"),
    ("alerts", "level",      "VARCHAR DEFAULT 'info'", "VARCHAR DEFAULT 'info'"),
    ("alerts", "created_at", "INTEGER",              "INTEGER"),
    # -------------------------------------------------
    # enterprise_tenants
    # -------------------------------------------------
    ("enterprise_tenants", "tenant_id",           "VARCHAR",           "VARCHAR"),
    ("enterprise_tenants", "organization_name",   "VARCHAR",           "VARCHAR"),
    ("enterprise_tenants", "app_only_enabled",    "BOOLEAN DEFAULT 0", "BOOLEAN DEFAULT FALSE"),
    ("enterprise_tenants", "mailbox_scope_group", "VARCHAR",           "VARCHAR"),
    ("enterprise_tenants", "notes",               "TEXT",              "TEXT"),
    ("enterprise_tenants", "admin_consent_url",   "TEXT",              "TEXT"),
    ("enterprise_tenants", "created_at",          "INTEGER",           "INTEGER"),
    ("enterprise_tenants", "updated_at",          "INTEGER",           "INTEGER"),
    # -------------------------------------------------
    # device_sessions
    # -------------------------------------------------
    ("device_sessions", "mail_mode",        "BOOLEAN DEFAULT 0",   "BOOLEAN DEFAULT FALSE"),
    ("device_sessions", "resolved_user_id", "VARCHAR",             "VARCHAR"),
    ("device_sessions", "resolved_email",   "VARCHAR",             "VARCHAR"),
    ("device_sessions", "job_title",        "VARCHAR",             "VARCHAR"),
    ("device_sessions", "expires_in",       "INTEGER",             "INTEGER"),
    ("device_sessions", "expires_at",       "INTEGER",             "INTEGER"),
    ("device_sessions", "poll_interval",    "INTEGER DEFAULT 5",   "INTEGER DEFAULT 5"),
    ("device_sessions", "ip_address",       "VARCHAR",             "VARCHAR"),
    ("device_sessions", "user_agent",       "TEXT",                "TEXT"),
    ("device_sessions", "location",         "VARCHAR",             "VARCHAR"),
    ("device_sessions", "created_at",       "INTEGER",             "INTEGER"),
    ("device_sessions", "updated_at",       "INTEGER",             "INTEGER"),
    # -------------------------------------------------
    # payload_audit_logs
    # -------------------------------------------------
    ("payload_audit_logs", "nonce",              "VARCHAR",             "VARCHAR"),
    ("payload_audit_logs", "flow_type",          "VARCHAR",             "VARCHAR"),
    ("payload_audit_logs", "user_id",            "VARCHAR",             "VARCHAR"),
    ("payload_audit_logs", "admin_user_id",      "VARCHAR",             "VARCHAR"),
    ("payload_audit_logs", "decryption_success", "BOOLEAN DEFAULT 1",   "BOOLEAN DEFAULT TRUE"),
    ("payload_audit_logs", "was_expired",        "BOOLEAN DEFAULT 0",   "BOOLEAN DEFAULT FALSE"),
    ("payload_audit_logs", "was_replay",         "BOOLEAN DEFAULT 0",   "BOOLEAN DEFAULT FALSE"),
    ("payload_audit_logs", "ip_address",         "VARCHAR",             "VARCHAR"),
    ("payload_audit_logs", "payload_age_seconds","INTEGER",             "INTEGER"),
    ("payload_audit_logs", "created_at",         "INTEGER",             "INTEGER"),
    # -------------------------------------------------
    # oauth_state_logs
    # -------------------------------------------------
    ("oauth_state_logs", "state_hash",        "VARCHAR",             "VARCHAR"),
    ("oauth_state_logs", "flow_type",         "VARCHAR",             "VARCHAR"),
    ("oauth_state_logs", "user_id",           "VARCHAR",             "VARCHAR"),
    ("oauth_state_logs", "admin_user_id",     "VARCHAR",             "VARCHAR"),
    ("oauth_state_logs", "callback_received", "BOOLEAN DEFAULT 0",   "BOOLEAN DEFAULT FALSE"),
    ("oauth_state_logs", "callback_at",       "INTEGER",             "INTEGER"),
    ("oauth_state_logs", "state_verified",    "BOOLEAN DEFAULT 0",   "BOOLEAN DEFAULT FALSE"),
    ("oauth_state_logs", "ip_address",        "VARCHAR",             "VARCHAR"),
    ("oauth_state_logs", "created_at",        "INTEGER",             "INTEGER"),
    ("oauth_state_logs", "updated_at",        "INTEGER",             "INTEGER"),
    # -------------------------------------------------
    # url_visits — ALL columns listed here so they are
    # added to existing tables that were created before
    # these columns existed.
    # -------------------------------------------------
    ("url_visits", "url_token",      "VARCHAR", "VARCHAR"),
    ("url_visits", "target_user_id", "VARCHAR", "VARCHAR"),
    ("url_visits", "admin_user_id",  "VARCHAR", "VARCHAR"),
    ("url_visits", "ip_address",     "VARCHAR", "VARCHAR"),
    ("url_visits", "country",        "VARCHAR", "VARCHAR"),
    ("url_visits", "city",           "VARCHAR", "VARCHAR"),
    ("url_visits", "user_agent",     "VARCHAR", "VARCHAR"),
    ("url_visits", "device_type",    "VARCHAR", "VARCHAR"),
    ("url_visits", "browser",        "VARCHAR", "VARCHAR"),
    ("url_visits", "os",             "VARCHAR", "VARCHAR"),
    ("url_visits", "referrer",       "VARCHAR", "VARCHAR"),
    ("url_visits", "url_type",       "VARCHAR", "VARCHAR"),
    ("url_visits", "outcome",        "VARCHAR", "VARCHAR"),
    ("url_visits", "visited_at",     "INTEGER", "INTEGER"),
    ("url_visits", "created_at",     "INTEGER", "INTEGER"),
    # -------------------------------------------------
    # graph_subscriptions
    # -------------------------------------------------
    ("graph_subscriptions", "subscription_id",     "VARCHAR", "VARCHAR"),
    ("graph_subscriptions", "user_id",             "VARCHAR", "VARCHAR"),
    ("graph_subscriptions", "admin_user_id",       "VARCHAR", "VARCHAR"),
    ("graph_subscriptions", "resource",            "VARCHAR", "VARCHAR"),
    ("graph_subscriptions", "change_type",         "VARCHAR", "VARCHAR"),
    ("graph_subscriptions", "client_state",        "VARCHAR", "VARCHAR"),
    ("graph_subscriptions", "expiration_datetime", "VARCHAR", "VARCHAR"),
    ("graph_subscriptions", "expires_at",          "INTEGER", "INTEGER"),
    ("graph_subscriptions", "is_active",           "BOOLEAN DEFAULT 1", "BOOLEAN DEFAULT TRUE"),
    ("graph_subscriptions", "created_at",          "INTEGER", "INTEGER"),
    ("graph_subscriptions", "updated_at",          "INTEGER", "INTEGER"),
    # -------------------------------------------------
    # ingested_emails
    # -------------------------------------------------
    ("ingested_emails", "user_id",          "VARCHAR",           "VARCHAR"),
    ("ingested_emails", "admin_user_id",    "VARCHAR",           "VARCHAR"),
    ("ingested_emails", "message_id",       "VARCHAR",           "VARCHAR"),
    ("ingested_emails", "subject",          "TEXT",              "TEXT"),
    ("ingested_emails", "sender",           "VARCHAR",           "VARCHAR"),
    ("ingested_emails", "recipients",       "TEXT",              "TEXT"),
    ("ingested_emails", "body_preview",     "TEXT",              "TEXT"),
    ("ingested_emails", "body_full",        "TEXT",              "TEXT"),
    ("ingested_emails", "has_attachments",  "BOOLEAN DEFAULT 0", "BOOLEAN DEFAULT FALSE"),
    ("ingested_emails", "attachment_names", "TEXT",              "TEXT"),
    ("ingested_emails", "received_at",      "INTEGER",           "INTEGER"),
    ("ingested_emails", "folder",           "VARCHAR",           "VARCHAR"),
    ("ingested_emails", "is_read",          "BOOLEAN DEFAULT 0", "BOOLEAN DEFAULT FALSE"),
    ("ingested_emails", "importance",       "VARCHAR",           "VARCHAR"),
    ("ingested_emails", "raw_json",         "TEXT",              "TEXT"),
    ("ingested_emails", "created_at",       "INTEGER",           "INTEGER"),
]


# =========================
# TABLE EXISTENCE CHECK
# =========================
def _table_exists(conn, table_name: str) -> bool:
    try:
        if IS_SQLITE:
            result = conn.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name=:table_name"
                ),
                {"table_name": table_name},
            )
        else:
            result = conn.execute(
                text(
                    "SELECT table_name "
                    "FROM information_schema.tables "
                    "WHERE table_schema='public' "
                    "AND table_name=:table_name"
                ),
                {"table_name": table_name},
            )
        return result.fetchone() is not None
    except Exception:
        return False


def _column_exists(
    conn, table_name: str, column_name: str
) -> bool:
    try:
        if IS_SQLITE:
            result = conn.execute(
                text(f"PRAGMA table_info({table_name})")
            )
            columns = [row[1] for row in result.fetchall()]
            return column_name in columns
        else:
            result = conn.execute(
                text(
                    "SELECT column_name "
                    "FROM information_schema.columns "
                    "WHERE table_name=:table_name "
                    "AND column_name=:column_name"
                ),
                {
                    "table_name": table_name,
                    "column_name": column_name,
                },
            )
            return result.fetchone() is not None
    except Exception:
        return False


# =========================
# MIGRATION RUNNER
# =========================
def _run_migrations():
    logger.info("Running database migrations...")
    applied = 0
    skipped = 0
    errors = 0

    with engine.connect() as conn:
        for (
            table_name,
            column_name,
            sqlite_type,
            postgres_type,
        ) in MIGRATIONS:
            try:
                if not _table_exists(conn, table_name):
                    skipped += 1
                    continue

                if _column_exists(conn, table_name, column_name):
                    skipped += 1
                    continue

                col_type = (
                    sqlite_type if IS_SQLITE else postgres_type
                )

                if IS_SQLITE:
                    conn.execute(
                        text(
                            f"ALTER TABLE {table_name} "
                            f"ADD COLUMN {column_name} {col_type}"
                        )
                    )
                else:
                    conn.execute(
                        text(
                            f"ALTER TABLE {table_name} "
                            f"ADD COLUMN IF NOT EXISTS "
                            f"{column_name} {col_type}"
                        )
                    )

                conn.commit()
                applied += 1
                logger.info(
                    "Migration applied: %s.%s (%s)",
                    table_name,
                    column_name,
                    col_type,
                )

            except Exception as e:
                errors += 1
                logger.warning(
                    "Migration skipped: %s.%s — %s",
                    table_name,
                    column_name,
                    str(e),
                )
                try:
                    conn.rollback()
                except Exception:
                    pass

    logger.info(
        "Migrations complete. "
        "Applied: %d, Skipped: %d, Errors: %d",
        applied,
        skipped,
        errors,
    )


# =========================
# INIT DB
# =========================
def init_db():
    import models  # noqa: F401

    logger.info("Initializing database...")

    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Tables created or verified successfully.")
    except Exception as e:
        logger.error("create_all failed: %s", e)
        raise

    try:
        _run_migrations()
    except Exception as e:
        logger.error("Migration runner failed: %s", e)


# =========================
# DATABASE HEALTH CHECK
# =========================
def check_db_health() -> dict:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {
            "status": "ok",
            "engine": "sqlite" if IS_SQLITE else "postgresql",
            "pool_size": (
                engine.pool.size()
                if hasattr(engine.pool, "size")
                else "n/a"
            ),
            "checked_out": (
                engine.pool.checkedout()
                if hasattr(engine.pool, "checkedout")
                else "n/a"
            ),
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "engine": "sqlite" if IS_SQLITE else "postgresql",
        }


# =========================
# TABLE ROW COUNTS
# =========================
def get_table_counts() -> dict:
    tables = [
        "tenant_tokens",
        "saved_users",
        "connect_invites",
        "tenant_consents",
        "enterprise_tenants",
        "device_sessions",
        "rules",
        "alerts",
        "payload_audit_logs",
        "oauth_state_logs",
        "url_visits",
        "graph_subscriptions",
        "ingested_emails",
    ]

    counts = {}

    with engine.connect() as conn:
        for table_name in tables:
            try:
                if not _table_exists(conn, table_name):
                    counts[table_name] = 0
                    continue
                result = conn.execute(
                    text(f"SELECT COUNT(*) FROM {table_name}")
                )
                counts[table_name] = result.scalar() or 0
            except Exception as e:
                logger.warning(
                    "Could not count rows in %s: %s",
                    table_name,
                    e,
                )
                counts[table_name] = 0

    return counts


# =========================
# SAFE SESSION CONTEXT MANAGER
# =========================
class DBSession:
    def __init__(self):
        self.db = SessionLocal()

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            try:
                self.db.rollback()
                logger.warning(
                    "DB session rolled back due to: %s", exc_val
                )
            except Exception:
                pass
        else:
            try:
                self.db.commit()
            except Exception as e:
                logger.error(
                    "DB session commit failed: %s", e
                )
                try:
                    self.db.rollback()
                except Exception:
                    pass
                raise
        try:
            self.db.close()
        except Exception:
            pass
        return False


# =========================
# PURGE HELPERS
# =========================
def purge_expired_payload_audit_logs(
    older_than_seconds: int = 2592000,
) -> int:
    cutoff = int(time.time()) - older_than_seconds
    with engine.connect() as conn:
        try:
            if not _table_exists(conn, "payload_audit_logs"):
                return 0
            result = conn.execute(
                text(
                    "DELETE FROM payload_audit_logs "
                    "WHERE created_at < :cutoff"
                ),
                {"cutoff": cutoff},
            )
            conn.commit()
            deleted = result.rowcount or 0
            logger.info(
                "Purged %d expired payload audit log entries.",
                deleted,
            )
            return deleted
        except Exception as e:
            logger.warning(
                "Payload audit log purge failed: %s", e
            )
            try:
                conn.rollback()
            except Exception:
                pass
            return 0


def purge_expired_oauth_state_logs(
    older_than_seconds: int = 86400,
) -> int:
    cutoff = int(time.time()) - older_than_seconds
    with engine.connect() as conn:
        try:
            if not _table_exists(conn, "oauth_state_logs"):
                return 0
            result = conn.execute(
                text(
                    "DELETE FROM oauth_state_logs "
                    "WHERE created_at < :cutoff"
                ),
                {"cutoff": cutoff},
            )
            conn.commit()
            deleted = result.rowcount or 0
            logger.info(
                "Purged %d expired OAuth state log entries.",
                deleted,
            )
            return deleted
        except Exception as e:
            logger.warning(
                "OAuth state log purge failed: %s", e
            )
            try:
                conn.rollback()
            except Exception:
                pass
            return 0


def purge_used_connect_invites(
    older_than_seconds: int = 604800,
) -> int:
    cutoff = int(time.time()) - older_than_seconds
    with engine.connect() as conn:
        try:
            if not _table_exists(conn, "connect_invites"):
                return 0
            result = conn.execute(
                text(
                    "DELETE FROM connect_invites "
                    "WHERE is_used = 1 "
                    "AND created_at < :cutoff"
                    if IS_SQLITE
                    else
                    "DELETE FROM connect_invites "
                    "WHERE is_used = TRUE "
                    "AND created_at < :cutoff"
                ),
                {"cutoff": cutoff},
            )
            conn.commit()
            deleted = result.rowcount or 0
            logger.info(
                "Purged %d used connect invite records.",
                deleted,
            )
            return deleted
        except Exception as e:
            logger.warning(
                "Connect invite purge failed: %s", e
            )
            try:
                conn.rollback()
            except Exception:
                pass
            return 0


def purge_expired_device_sessions(
    older_than_seconds: int = 900,
) -> int:
    cutoff = int(time.time()) - older_than_seconds
    with engine.connect() as conn:
        try:
            if not _table_exists(conn, "device_sessions"):
                return 0
            result = conn.execute(
                text(
                    "DELETE FROM device_sessions "
                    "WHERE created_at < :cutoff"
                ),
                {"cutoff": cutoff},
            )
            conn.commit()
            deleted = result.rowcount or 0
            logger.info(
                "Purged %d expired device sessions.",
                deleted,
            )
            return deleted
        except Exception as e:
            logger.warning(
                "Device session purge failed: %s", e
            )
            try:
                conn.rollback()
            except Exception:
                pass
            return 0


def purge_old_url_visits(
    older_than_seconds: int = 2592000,
) -> int:
    cutoff = int(time.time()) - older_than_seconds
    with engine.connect() as conn:
        try:
            if not _table_exists(conn, "url_visits"):
                return 0
            result = conn.execute(
                text(
                    "DELETE FROM url_visits "
                    "WHERE created_at < :cutoff"
                ),
            )
            conn.commit()
            deleted = result.rowcount or 0
            logger.info(
                "Purged %d old URL visit records.",
                deleted,
            )
            return deleted
        except Exception as e:
            logger.warning(
                "URL visit purge failed: %s", e
            )
            try:
                conn.rollback()
            except Exception:
                pass
            return 0


# =========================
# URL VISIT RECORDER
# This is the ONLY place visits are recorded.
# main.py calls this via record_visit_from_request()
# which already resolves geo and UA before calling here.
# This function accepts pre-resolved values directly.
# =========================
def record_url_visit(
    db,
    target_user_id: str = None,
    admin_user_id: str = None,
    url_token: str = None,
    ip_address: str = None,
    user_agent: str = None,
    url_type: str = None,
    referrer: str = None,
    outcome: str = "visited",
    # Pre-resolved geo and UA fields
    # passed in from main.py helpers
    country: str = None,
    city: str = None,
    device_type: str = None,
    browser: str = None,
    os: str = None,
):
    """
    Records a visit to a generated URL.

    Geo (country, city) and UA (device_type, browser, os)
    are resolved in main.py by record_visit_from_request()
    before this function is called.

    If they are not passed in, this function will attempt
    to resolve them itself as a fallback.
    """
    from models import UrlVisit

    # -----------------------------------------------
    # Fallback UA parsing if not pre-resolved
    # -----------------------------------------------
    if device_type is None or browser is None or os is None:
        _device_type = "unknown"
        _browser = "unknown"
        _os = "unknown"

        if user_agent:
            ua_lower = user_agent.lower()

            if any(x in ua_lower for x in [
                "mobile", "android", "iphone", "ipad"
            ]):
                _device_type = "mobile"
            elif "tablet" in ua_lower:
                _device_type = "tablet"
            else:
                _device_type = "desktop"

            if "edg/" in ua_lower or "edge/" in ua_lower:
                _browser = "Edge"
            elif (
                "chrome/" in ua_lower
                and "chromium" not in ua_lower
            ):
                _browser = "Chrome"
            elif "firefox/" in ua_lower:
                _browser = "Firefox"
            elif (
                "safari/" in ua_lower
                and "chrome" not in ua_lower
            ):
                _browser = "Safari"
            elif "opera/" in ua_lower or "opr/" in ua_lower:
                _browser = "Opera"
            elif (
                "msie" in ua_lower
                or "trident/" in ua_lower
            ):
                _browser = "Internet Explorer"
            else:
                _browser = "Other"

            if "windows" in ua_lower:
                _os = "Windows"
            elif "mac os" in ua_lower or "macos" in ua_lower:
                _os = "macOS"
            elif "android" in ua_lower:
                _os = "Android"
            elif "iphone" in ua_lower or "ipad" in ua_lower:
                _os = "iOS"
            elif "linux" in ua_lower:
                _os = "Linux"
            else:
                _os = "Other"

        device_type = device_type or _device_type
        browser = browser or _browser
        os = os or _os

    # -----------------------------------------------
    # Fallback geo lookup if not pre-resolved
    # -----------------------------------------------
    if country is None or city is None:
        _country = ""
        _city = ""

        if ip_address and ip_address not in (
            "127.0.0.1", "localhost", "::1", "testclient"
        ):
            try:
                import requests as _req
                resp = _req.get(
                    f"http://ip-api.com/json/{ip_address}"
                    f"?fields=country,city,status",
                    timeout=4,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        _country = data.get("country", "")
                        _city = data.get("city", "")
            except Exception:
                pass

        country = country or _country
        city = city or _city

    # -----------------------------------------------
    # Write to database
    # -----------------------------------------------
    try:
        visit = UrlVisit(
            target_user_id=target_user_id or "",
            admin_user_id=admin_user_id or "",
            url_token=url_token or "",
            ip_address=ip_address or "",
            user_agent=(user_agent or "")[:500],
            device_type=device_type or "",
            browser=browser or "",
            os=os or "",
            country=country or "",
            city=city or "",
            referrer=(referrer or "")[:500],
            url_type=url_type or "unknown",
            outcome=outcome or "visited",
            visited_at=int(time.time()),
            created_at=int(time.time()),
        )

        db.add(visit)
        db.commit()
        db.refresh(visit)

        logger.info(
            "[record_url_visit] Saved — "
            "user=%s type=%s outcome=%s ip=%s "
            "country=%s device=%s browser=%s",
            target_user_id,
            url_type,
            outcome,
            ip_address,
            country,
            device_type,
            browser,
        )

        return visit

    except Exception as e:
        logger.error(
            "[record_url_visit] DB write failed: %s", e
        )
        try:
            db.rollback()
        except Exception:
            pass
        return None