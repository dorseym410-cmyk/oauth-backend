from sqlalchemy import Column, String, Integer
from db import Base

class TenantToken(Base):
    __tablename__ = "tenant_tokens"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, unique=True)

    access_token = Column(String)
    refresh_token = Column(String)

    expires_at = Column(Integer)