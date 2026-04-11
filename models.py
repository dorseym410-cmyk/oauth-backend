from sqlalchemy import Column, String, Integer

class TenantToken(Base):
    __tablename__ = "tenant_tokens"

    tenant_id = Column(String, primary_key=True)
    session_id = Column(String, primary_key=True)

    access_token = Column(String)
    refresh_token = Column(String)
    expires_at = Column(Integer)

    # ✅ NEW DEVICE INFO
    ip_address = Column(String)
    user_agent = Column(String)
    location = Column(String)
