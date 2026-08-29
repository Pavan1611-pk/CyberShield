try:
    from .database import Base
except ImportError:
    from database import Base
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class ScanResult(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(50), nullable=True, unique=True, index=True) # Unique Threat ID e.g. CS-THREAT-A1B2C3D4
    user_id = Column(Integer, nullable=True, index=True)
    gmail_message_id = Column(String(100), nullable=True, index=True)
    sender = Column(String(255), nullable=True)
    sender_email = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=True)
    date_received = Column(String(100), nullable=True)
    snippet = Column(Text, nullable=True)
    content_type = Column(String(50), default="email")  # email, manual_text, manual_url
    
    # Risk Assessment
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(20), nullable=False, default="LOW")  # LOW, MEDIUM, HIGH
    
    # JSON-encoded string fields for flexibility
    evidence_json = Column(Text, nullable=True)         # JSON list of evidence reasons
    recommendations_json = Column(Text, nullable=True)  # JSON list of actionable next steps
    urls_json = Column(Text, nullable=True)             # JSON list of extracted & analyzed URLs
    signals_json = Column(Text, nullable=True)          # JSON object of signal breakdown
    
    is_notified = Column(Boolean, default=False)        # Tracks if browser alert was dispatched
    is_starred = Column(Boolean, default=False)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
