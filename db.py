from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./tokens.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# ✅ FIXED (added autocommit + autoflush)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# SAFE PLACE TO CREATE TABLES
def init_db():
    import models
    print(Base.metadata.tables.keys())  # ✅ ADD THIS LINE
    Base.metadata.create_all(bind=engine)