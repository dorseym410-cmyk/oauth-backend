import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# =========================
# DATABASE CONFIG
# =========================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./tokens.db")

# Render may provide postgres urls in old format.
# Normalize only if needed.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# SQLite needs check_same_thread=False
engine_kwargs = {
    "pool_pre_ping": True,
}

if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


# =========================
# DB SESSION DEPENDENCY
# =========================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# DB INIT
# =========================

def init_db():
    # Import models here so all tables register on Base.metadata
    import models  # noqa: F401

    try:
        print("📦 Tables registered:", Base.metadata.tables.keys())
    except Exception:
        pass

    Base.metadata.create_all(bind=engine)

    try:
        print("✅ Database initialized successfully")
    except Exception:
        pass