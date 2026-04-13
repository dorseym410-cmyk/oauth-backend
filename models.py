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

    # target mailbox user_id to manage later
    user_id = Column(String, index=True)

    created_at = Column(Integer, default=lambda: int(time.time()))


# =========================
# RULE MODEL
# =========================
class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(String, index=True)
    condition = Column(String)
    keyword = Column(String, index=True)
    action = Column(Enum(RuleAction))
    target_folder = Column(String, nullable=True)
    forward_to = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(Integer, default=lambda: int(time.time()))

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

    rule_id = Column(Integer, ForeignKey("rules.id"))
    user_id = Column(String, index=True)
    message = Column(String)
    email_subject = Column(String)
    email_from = Column(String)
    message_id = Column(String)
    status = Column(String, default="triggered")
    timestamp = Column(Integer, default=lambda: int(time.time()))

    rule = relationship("Rule", back_populates="alerts")