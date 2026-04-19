from sqlalchemy import Column, Integer, String, Boolean, Text, Enum, UniqueConstraint
import enum

from db import Base


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


class TenantToken(Base):
    __tablename__ = "tenant_tokens"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=False, unique=True)
    session_id = Column(String, index=True, nullable=True)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=True)
    expires_at = Column(Integer, nullable=True)

    ip_address = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    location = Column(String, nullable=True)


class SavedUser(Base):
    __tablename__ = "saved_users"

    id = Column(Integer, primary_key=True, index=True)
    admin_user_id = Column(String, index=True, nullable=False)
    user_id = Column(String, index=True, nullable=False)
    job_title = Column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint("admin_user_id", "user_id", name="uq_saved_user_admin_user"),
    )


class ConnectInvite(Base):
    __tablename__ = "connect_invites"

    id = Column(Integer, primary_key=True, index=True)
    admin_user_id = Column(String, index=True, nullable=False)
    invite_token = Column(String, unique=True, index=True, nullable=False)

    connect_mode = Column(String, default="basic")  # basic | mail
    tenant_hint = Column(String, index=True, nullable=True)

    is_used = Column(Boolean, default=False)
    used_at = Column(Integer, nullable=True)

    resolved_user_id = Column(String, nullable=True)
    job_title = Column(String, nullable=True)


class TenantConsent(Base):
    __tablename__ = "tenant_consents"

    id = Column(Integer, primary_key=True, index=True)
    admin_user_id = Column(String, index=True, nullable=False)
    tenant_hint = Column(String, index=True, nullable=False)

    admin_consent_url = Column(Text, nullable=True)
    status = Column(Enum(TenantConsentStatus), default=TenantConsentStatus.PENDING, nullable=False)
    notes = Column(Text, nullable=True)

    created_at = Column(Integer, nullable=True)
    updated_at = Column(Integer, nullable=True)

    __table_args__ = (
        UniqueConstraint("admin_user_id", "tenant_hint", name="uq_tenant_consent_admin_tenant"),
    )


class EnterpriseTenant(Base):
    __tablename__ = "enterprise_tenants"

    id = Column(Integer, primary_key=True, index=True)

    admin_user_id = Column(String, index=True, nullable=False)
    tenant_hint = Column(String, index=True, nullable=False)
    tenant_id = Column(String, index=True, nullable=True)

    organization_name = Column(String, nullable=True)

    mode = Column(Enum(EnterpriseMode), default=EnterpriseMode.PREVIEW, nullable=False)
    consent_status = Column(Enum(TenantConsentStatus), default=TenantConsentStatus.PENDING, nullable=False)

    admin_consent_url = Column(Text, nullable=True)

    app_only_enabled = Column(Boolean, default=False)
    mailbox_scope_group = Column(String, nullable=True)

    notes = Column(Text, nullable=True)

    created_at = Column(Integer, nullable=True)
    updated_at = Column(Integer, nullable=True)

    __table_args__ = (
        UniqueConstraint("admin_user_id", "tenant_hint", name="uq_enterprise_tenant_admin_tenant"),
    )


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(String, index=True, nullable=False)

    condition = Column(String, nullable=False)
    keyword = Column(String, nullable=False)

    action = Column(Enum(RuleAction), nullable=False)

    target_folder = Column(String, nullable=True)
    forward_to = Column(String, nullable=True)

    is_active = Column(Boolean, default=True)

    created_at = Column(Integer, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True, nullable=True)
    level = Column(String, nullable=True)
    message = Column(Text, nullable=False)
    created_at = Column(Integer, nullable=True)