from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./tokens.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# ✅ Session config
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


# =========================
# INIT DB (🔥 FIXED PROPERLY)
# =========================
def init_db():
    # 🔥 IMPORTANT: import ALL models so SQLAlchemy registers them
    import models

    print("📦 Tables registered:", Base.metadata.tables.keys())

    # 🔥 Create tables if they don't exist
    Base.metadata.create_all(bind=engine)

    print("✅ Database initialized successfully")