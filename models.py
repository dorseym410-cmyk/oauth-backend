from sqlalchemy import Column, String, Integer, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from db import Base
from enum import Enum as PyEnum
import time


# =========================
# RULE ACTION ENUM
# =========================
class RuleAction(PyEnum):
    MOVE = "move"
    DELETE = "delete"
    FORWARD = "forward"


# =========================
# SAVED USER MODEL
# =========================
class SavedUser(Base):
    __tablename__ = "saved_users"

    id = Column(Integer, primary_key=True, index=True)

    # admin who saved this user
    admin_user_id = Column(String, index=True)

    # target mailbox user id/email/upn
    user_id = Column(String, index=True)

    # detected from Microsoft Graph
    job_title = Column(String, nullable=True)

    created_at = Column(Integer, default=lambda: int(time.time()))


# =========================
# CONNECT INVITE MODEL
# =========================
class ConnectInvite(Base):
    __tablename__ = "connect_invites"

    id = Column(Integer, primary_key=True, index=True)

    # admin who generated the org connect URL
    admin_user_id = Column(String, index=True)

    # random unique token placed in OAuth state
    invite_token = Column(String, unique=True, index=True)

    # who actually completed the flow
    resolved_user_id = Column(String, nullable=True, index=True)

    # detected from Microsoft Graph
    job_title = Column(String, nullable=True)

    # status
    is_used = Column(Boolean, default=False)

    created_at = Column(Integer, default=lambda: int(time.time()))
    used_at = Column(Integer, nullable=True)


# =========================
# RULE MODEL
# =========================
class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)

    # MULTI-TENANT SUPPORT
    user_id = Column(String, index=True)

    # Rule condition (human readable)
    condition = Column(String)

    # actual match field used by backend logic
    keyword = Column(String, index=True)

    action = Column(Enum(RuleAction))

    # Action targets
    target_folder = Column(String, nullable=True)
    forward_to = Column(String, nullable=True)

    # Enable / disable rule
    is_active = Column(Boolean, default=True)

    # Timestamp
    created_at = Column(Integer, default=lambda: int(time.time()))

    # Relationships
    alerts = relationship("Alert", back_populates="rule")


# =========================
# TENANT TOKENS
# =========================
class TenantToken(Base):
    __tablename__ = "tenant_tokens"

    tenant_id = Column(String, primary_key=True)
    session_id = Column(String, primary_key=True)

    access_token = Column(String)
    refresh_token = Column(String)
    expires_at = Column(Integer)

    ip_address = Column(String)
    user_agent = Column(String)
    location = Column(String)


# =========================
# ALERT MODEL
# =========================
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    # Link to rule
    rule_id = Column(Integer, ForeignKey("rules.id"))

    # MULTI-TENANT
    user_id = Column(String, index=True)

    # Alert content
    message = Column(String)

    # Extra useful metadata
    email_subject = Column(String)
    email_from = Column(String)
    message_id = Column(String)

    # Status tracking
    status = Column(String, default="triggered")  # triggered | sent | read

    # Timestamp
    timestamp = Column(Integer, default=lambda: int(time.time()))

    rule = relationship("Alert", back_populates="alerts")