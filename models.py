from sqlalchemy import Column, String, Integer
from db import Base  # ✅ MUST come from db

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
