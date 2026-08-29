from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybershield.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def init_db_and_migrate():
    """Create tables and ensure all new columns exist cleanly."""
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            res = conn.execute(text("PRAGMA table_info(scans)"))
            existing_cols = [row[1] for row in res.fetchall()]
            
            if existing_cols:
                if "threat_id" not in existing_cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN threat_id VARCHAR(50)"))
                if "is_notified" not in existing_cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN is_notified BOOLEAN DEFAULT 0"))
                if "scanned_at" not in existing_cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN scanned_at DATETIME"))
                conn.commit()
    except Exception as e:
        print(f"[Database Migration] Warning during column check: {e}")

def get_db():
    """Dependency for obtaining a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
