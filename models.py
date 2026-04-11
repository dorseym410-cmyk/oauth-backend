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
# RULE MODEL
# =========================
class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)

    # 🔑 MULTI-TENANT SUPPORT (VERY IMPORTANT)
    user_id = Column(String, index=True)

    # Rule condition (human readable)
    condition = Column(String)

    # 🔥 ACTUAL MATCH FIELD (used by backend logic)
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
# TENANT TOKENS (SESSIONS)
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

    # 🔑 MULTI-TENANT
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

    rule = relationship("Rule", back_populates="alerts")