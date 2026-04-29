from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    Text,
    Enum,
    UniqueConstraint,
)
import enum
import time

from db import Base


def current_timestamp():
    return int(time.time())


# =========================
# ENUMS
# =========================
class TenantConsentStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class EnterpriseMode(str, enum.Enum):
    PREVIEW = "preview"
    ENTERPRISE_FULL = "enterprise_full"
    APP_ONLY = "app_only"


class RuleAction(str, enum.Enum):
    move = "move"
    delete = "delete"
    forward = "forward"


class ScopeLevel(str, enum.Enum):
    """
    Tracks whether the stored token was issued with
    basic identity scopes only or full Mail scopes.
    basic  = openid + profile + User.Read only
    mail   = all Mail.Read/Write/Send scopes included
    """
    BASIC = "basic"
    MAIL = "mail"
    UNKNOWN = "unknown"


class DeviceSessionStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETE = "complete"
    EXPIRED = "expired"
    DECLINED = "declined"
    ERROR = "error"


# =========================
# TENANT TOKEN
# Stores OAuth access/refresh tokens per user.
# session_id links back to the encrypted payload nonce.
# scope_level tracks whether Mail scopes were granted.
# email caches the resolved Microsoft identity email.
# =========================
class TenantToken(Base):
    __tablename__ = "tenant_tokens"

    id = Column(Integer, primary_key=True, index=True)

    # Primary identity key — usually the userPrincipalName
    # or email from Microsoft Graph /me
    tenant_id = Column(
        String, index=True, nullable=False, unique=True
    )

    # Links to the encrypted payload nonce used during OAuth
    # Populated from the decrypted state payload on callback
    session_id = Column(String, index=True, nullable=True)

    # Cached email/UPN from Microsoft Graph identity fetch
    email = Column(String, index=True, nullable=True)

    # OAuth tokens
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=True)
    expires_at = Column(Integer, nullable=True)

    # Scope level tracking
    # Set to 'mail' when token was issued via mail-mode flow
    # Set to 'basic' when token was issued via basic sign-in
    scope_level = Column(
        Enum(ScopeLevel),
        default=ScopeLevel.UNKNOWN,
        nullable=True,
    )

    # Device/location metadata from OAuth callback
    ip_address = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    location = Column(String, nullable=True)

    # Payload metadata cached from the decrypted state
    # Stores the flow_type from the encrypted payload
    flow_type = Column(String, nullable=True)

    # Admin user who initiated the OAuth flow
    admin_user_id = Column(String, index=True, nullable=True)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )
    updated_at = Column(
        Integer,
        default=current_timestamp,
        onupdate=current_timestamp,
        nullable=True,
    )


# =========================
# SAVED USER
# Tracks which users an admin has saved/managed.
# =========================
class SavedUser(Base):
    __tablename__ = "saved_users"

    id = Column(Integer, primary_key=True, index=True)
    admin_user_id = Column(String, index=True, nullable=False)
    user_id = Column(String, index=True, nullable=False)
    job_title = Column(String, nullable=True)

    # Cached email from Microsoft Graph identity fetch
    email = Column(String, nullable=True)

    # Tenant domain extracted from user_id
    tenant_hint = Column(String, index=True, nullable=True)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )
    updated_at = Column(
        Integer,
        default=current_timestamp,
        onupdate=current_timestamp,
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "admin_user_id",
            "user_id",
            name="uq_saved_user_admin_user",
        ),
    )


# =========================
# CONNECT INVITE
# Tracks org-level OAuth invite tokens.
# Used by generate_org_connect_link and
# generate_org_mail_connect_link flows.
# =========================
class ConnectInvite(Base):
    __tablename__ = "connect_invites"

    id = Column(Integer, primary_key=True, index=True)
    admin_user_id = Column(String, index=True, nullable=False)
    invite_token = Column(
        String, unique=True, index=True, nullable=False
    )

    # basic = identity only, mail = full Mail scopes
    connect_mode = Column(String, default="basic")

    # Optional tenant domain hint for domain_hint OAuth param
    tenant_hint = Column(String, index=True, nullable=True)

    # Tracks whether this invite has been used
    is_used = Column(Boolean, default=False)
    used_at = Column(Integer, nullable=True)

    # Populated after OAuth callback resolves the identity
    resolved_user_id = Column(String, nullable=True)
    resolved_email = Column(String, nullable=True)
    job_title = Column(String, nullable=True)

    # Payload nonce from the encrypted state used for this invite
    payload_nonce = Column(String, nullable=True)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )
    updated_at = Column(
        Integer,
        default=current_timestamp,
        onupdate=current_timestamp,
        nullable=True,
    )


# =========================
# TENANT CONSENT
# Tracks standard tenant admin consent status.
# Also used as the enterprise tenant record via notes field.
# =========================
class TenantConsent(Base):
    __tablename__ = "tenant_consents"

    id = Column(Integer, primary_key=True, index=True)
    admin_user_id = Column(String, index=True, nullable=False)
    tenant_hint = Column(String, index=True, nullable=False)

    admin_consent_url = Column(Text, nullable=True)
    status = Column(
        Enum(TenantConsentStatus),
        default=TenantConsentStatus.PENDING,
        nullable=False,
    )

    # Stores mode, organization_name, and notes
    # as semicolon-separated key=value pairs
    # Example: mode=enterprise_full;org=Acme Corp;notes=approved
    notes = Column(Text, nullable=True)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )
    updated_at = Column(
        Integer,
        default=current_timestamp,
        onupdate=current_timestamp,
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "admin_user_id",
            "tenant_hint",
            name="uq_tenant_consent_admin_tenant",
        ),
    )


# =========================
# ENTERPRISE TENANT
# Dedicated enterprise tenant record separate from
# TenantConsent for cleaner enterprise management.
# =========================
class EnterpriseTenant(Base):
    __tablename__ = "enterprise_tenants"

    id = Column(Integer, primary_key=True, index=True)

    admin_user_id = Column(String, index=True, nullable=False)
    tenant_hint = Column(String, index=True, nullable=False)

    # Resolved Microsoft tenant ID from OAuth callback
    tenant_id = Column(String, index=True, nullable=True)

    organization_name = Column(String, nullable=True)

    mode = Column(
        Enum(EnterpriseMode),
        default=EnterpriseMode.PREVIEW,
        nullable=False,
    )
    consent_status = Column(
        Enum(TenantConsentStatus),
        default=TenantConsentStatus.PENDING,
        nullable=False,
    )

    admin_consent_url = Column(Text, nullable=True)

    # App-only access (service principal / client credentials)
    app_only_enabled = Column(Boolean, default=False)

    # Scope group label for mailbox scope management
    mailbox_scope_group = Column(String, nullable=True)

    notes = Column(Text, nullable=True)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )
    updated_at = Column(
        Integer,
        default=current_timestamp,
        onupdate=current_timestamp,
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "admin_user_id",
            "tenant_hint",
            name="uq_enterprise_tenant_admin_tenant",
        ),
    )


# =========================
# DEVICE SESSION
# Tracks active device code flow sessions.
# Allows polling status and linking resolved identities
# back to the admin who initiated the flow.
# =========================
class DeviceSession(Base):
    __tablename__ = "device_sessions"

    id = Column(Integer, primary_key=True, index=True)

    # Admin who initiated the device code flow
    admin_user_id = Column(String, index=True, nullable=False)

    # The device_code returned by Microsoft
    device_code = Column(
        String, unique=True, index=True, nullable=False
    )

    # The user_code shown to the end user
    user_code = Column(String, nullable=False)

    # The verification URI the user visits
    verification_uri = Column(String, nullable=False)

    # Whether this was a mail-mode flow
    mail_mode = Column(Boolean, default=False)

    # Resolved after polling completes
    resolved_user_id = Column(String, nullable=True)
    resolved_email = Column(String, nullable=True)
    job_title = Column(String, nullable=True)

    # Flow status
    status = Column(
        Enum(DeviceSessionStatus),
        default=DeviceSessionStatus.PENDING,
        nullable=False,
    )

    # Token expiry from Microsoft device code response
    expires_in = Column(Integer, nullable=True)
    expires_at = Column(Integer, nullable=True)

    # Polling interval in seconds
    poll_interval = Column(Integer, default=5, nullable=True)

    # Device/location metadata
    ip_address = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    location = Column(String, nullable=True)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )
    updated_at = Column(
        Integer,
        default=current_timestamp,
        onupdate=current_timestamp,
        nullable=True,
    )


# =========================
# RULE
# Email automation rules per user.
# =========================
class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(String, index=True, nullable=False)

    # subject | from | body | to
    condition = Column(String, nullable=False)
    keyword = Column(String, nullable=False)

    action = Column(Enum(RuleAction), nullable=False)

    # Used when action is 'move'
    target_folder = Column(String, nullable=True)

    # Used when action is 'forward'
    forward_to = Column(String, nullable=True)

    is_active = Column(Boolean, default=True)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )
    updated_at = Column(
        Integer,
        default=current_timestamp,
        onupdate=current_timestamp,
        nullable=True,
    )


# =========================
# ALERT
# System and audit alerts per user.
# =========================
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True, nullable=True)

    # info | warning | error | audit
    level = Column(String, nullable=True)

    message = Column(Text, nullable=False)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )


# =========================
# PAYLOAD AUDIT LOG
# Tracks encrypted payload usage for security auditing.
# Stores metadata only — never stores the raw payload
# or decrypted token contents.
# =========================
class PayloadAuditLog(Base):
    __tablename__ = "payload_audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    # The nonce from the decrypted payload
    # Used to detect replay attempts
    nonce = Column(String, unique=True, index=True, nullable=True)

    # Flow type from the payload
    flow_type = Column(String, nullable=True)

    # User context from the payload
    user_id = Column(String, index=True, nullable=True)
    admin_user_id = Column(String, index=True, nullable=True)

    # Whether the payload was successfully decrypted
    decryption_success = Column(Boolean, default=True)

    # Whether the payload was expired at time of use
    was_expired = Column(Boolean, default=False)

    # Whether this nonce had been seen before (replay attempt)
    was_replay = Column(Boolean, default=False)

    # Source IP of the OAuth callback request
    ip_address = Column(String, nullable=True)

    # Age of the payload in seconds at time of use
    payload_age_seconds = Column(Integer, nullable=True)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )


# =========================
# OAUTH STATE LOG
# Tracks OAuth state values used in authorization requests.
# Helps detect CSRF and state mismatch attacks.
# =========================
class OAuthStateLog(Base):
    __tablename__ = "oauth_state_logs"

    id = Column(Integer, primary_key=True, index=True)

    # The encrypted state value sent in the OAuth request
    # Stored as a hash only — never the raw encrypted value
    state_hash = Column(
        String, unique=True, index=True, nullable=True
    )

    # Flow context
    flow_type = Column(String, nullable=True)
    user_id = Column(String, index=True, nullable=True)
    admin_user_id = Column(String, index=True, nullable=True)

    # Whether the callback was received and matched
    callback_received = Column(Boolean, default=False)
    callback_at = Column(Integer, nullable=True)

    # Whether the state was successfully verified
    state_verified = Column(Boolean, default=False)

    ip_address = Column(String, nullable=True)

    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )
    updated_at = Column(
        Integer,
        default=current_timestamp,
        onupdate=current_timestamp,
        nullable=True,
    )


# =========================
# URL VISIT
# Tracks visits to admin-generated URLs.
# Records visit metadata, device info, and outcome
# for audit and analytics purposes.
# =========================
class UrlVisit(Base):
    __tablename__ = "url_visits"

    id = Column(Integer, primary_key=True, index=True)

    # Which generated URL was visited
    url_token = Column(String, index=True, nullable=True)

    # The user_id the URL was generated for
    target_user_id = Column(String, index=True, nullable=True)

    # The admin who generated the URL
    admin_user_id = Column(String, index=True, nullable=True)

    # Visit metadata
    ip_address = Column(String, nullable=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    device_type = Column(String, nullable=True)
    browser = Column(String, nullable=True)
    os = Column(String, nullable=True)
    referrer = Column(String, nullable=True)

    # URL metadata
    url_type = Column(String, nullable=True)

    # Outcome
    outcome = Column(String, nullable=True)

    # Timestamps
    visited_at = Column(Integer, nullable=True)
    created_at = Column(
        Integer, default=current_timestamp, nullable=True
    )