from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

# ================= USER SCHEMAS =================
class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    name: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

# ================= ANALYSIS & THREAT SCHEMAS =================
class ManualAnalyzeRequest(BaseModel):
    content_type: str = "text"  # "text", "email", "url"
    sender: Optional[str] = None
    subject: Optional[str] = None
    content: str  # body or url text

class UrlAnalysisItem(BaseModel):
    url: str
    domain: str
    is_https: bool
    is_suspicious_tld: bool
    has_ip_host: bool
    has_deceptive_keywords: bool
    has_shortener: bool
    url_score: int
    flags: List[str]

class AnalyzeResultResponse(BaseModel):
    id: Optional[int] = None
    threat_id: Optional[str] = None
    gmail_message_id: Optional[str] = None
    sender: Optional[str] = "Unknown"
    sender_email: Optional[str] = None
    subject: Optional[str] = "No Subject"
    date_received: Optional[str] = None
    snippet: Optional[str] = None
    content_type: str = "email"
    risk_score: int
    risk_level: str  # "LOW", "MEDIUM", "HIGH"
    evidence: List[str]
    recommendations: List[str]
    urls_analyzed: List[UrlAnalysisItem]
    signals: Dict[str, Any]
    is_notified: bool = False
    scanned_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

class LatestThreatItem(BaseModel):
    id: int
    threat_id: Optional[str] = None
    gmail_message_id: Optional[str] = None
    sender: str
    subject: str
    risk_score: int
    risk_level: str
    detected_at: Optional[str] = None
    is_new: bool = False

class ThreatItemResponse(BaseModel):
    id: int
    threat_id: str
    gmail_message_id: Optional[str] = None
    sender: str
    subject: str
    date_received: Optional[str] = None
    snippet: Optional[str] = None
    risk_score: int
    risk_level: str
    evidence: List[str]
    recommendations: List[str]
    urls_analyzed: List[UrlAnalysisItem]
    signals: Dict[str, Any]
    scanned_at: Optional[datetime] = None

class ScanSummaryStats(BaseModel):
    total_scanned: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    last_scanned_at: Optional[str] = None

class GmailScanResponse(BaseModel):
    status: str
    scanned_count: int
    threats_found: int
    results: List[AnalyzeResultResponse]

class MonitoringStatusResponse(BaseModel):
    is_monitoring: bool
    interval_seconds: int
    last_check_time: Optional[str] = None
    total_scanned: int
    active_threats: int
