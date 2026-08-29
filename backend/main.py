from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
from typing import List, Optional
import asyncio
import os
import json
from datetime import datetime

try:
    from .database import engine, Base, SessionLocal, get_db, init_db_and_migrate
    from .models import User, ScanResult
    from .schemas import (
        UserCreate, UserLogin, UserOut, Token,
        ManualAnalyzeRequest, AnalyzeResultResponse, GmailScanResponse,
        ScanSummaryStats, ThreatItemResponse, MonitoringStatusResponse,
        LatestThreatItem
    )
    from .auth import hash_password, verify_password, create_access_token, get_current_user_optional
    from .analyzer import analyze_content
    from .gmail_service import (
        is_gmail_connected, get_auth_url, exchange_code_for_token,
        disconnect_gmail, fetch_recent_emails, check_and_process_new_emails,
        generate_threat_id
    )
except ImportError:
    from database import engine, Base, SessionLocal, get_db, init_db_and_migrate
    from models import User, ScanResult
    from schemas import (
        UserCreate, UserLogin, UserOut, Token,
        ManualAnalyzeRequest, AnalyzeResultResponse, GmailScanResponse,
        ScanSummaryStats, ThreatItemResponse, MonitoringStatusResponse,
        LatestThreatItem
    )
    from auth import hash_password, verify_password, create_access_token, get_current_user_optional
    from analyzer import analyze_content
    from gmail_service import (
        is_gmail_connected, get_auth_url, exchange_code_for_token,
        disconnect_gmail, fetch_recent_emails, check_and_process_new_emails,
        generate_threat_id
    )

# Initialize SQLite tables and columns
init_db_and_migrate()

# ================= BACKGROUND MONITORING SCHEDULER =================
EMAIL_MONITOR_INTERVAL = int(os.getenv("EMAIL_MONITOR_INTERVAL", "30"))
MONITOR_STATE = {
    "is_running": True,
    "last_check_time": None,
    "total_cycles": 0
}

# Strong global references to prevent asyncio tasks from being garbage collected
BACKGROUND_TASKS = set()

async def background_inbox_monitor():
    """
    Continuous Asynchronous Non-Blocking Gmail Background Monitor:
    Runs reliably in the background, checking Gmail every 30s for new incoming emails.
    """
    print("[Monitor] Monitor started")
    while MONITOR_STATE["is_running"]:
        try:
            status_info = is_gmail_connected()
            if status_info.get("connected"):
                db = SessionLocal()
                try:
                    res = check_and_process_new_emails(db)
                    MONITOR_STATE["last_check_time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                    MONITOR_STATE["total_cycles"] += 1
                except Exception as inner_e:
                    print(f"[Monitor] Error during email processing: {inner_e}")
                finally:
                    db.close()
            else:
                MONITOR_STATE["last_check_time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print(f"[Monitor] Error: {e}")
        finally:
            print("[Monitor] Waiting for next check...")

        try:
            await asyncio.sleep(EMAIL_MONITOR_INTERVAL)
        except asyncio.CancelledError:
            print("[Monitor] Monitoring worker shutting down cleanly.")
            break

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI Lifespan: Start background worker task on startup, stop cleanly on shutdown."""
    MONITOR_STATE["is_running"] = True
    task = asyncio.create_task(background_inbox_monitor())
    BACKGROUND_TASKS.add(task)
    task.add_done_callback(BACKGROUND_TASKS.discard)
    
    yield
    
    MONITOR_STATE["is_running"] = False
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

app = FastAPI(
    title="CyberShield API",
    description="Intelligent Phishing, Scam & Automated Gmail Threat Protection",
    version="1.3.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")

def _model_to_response(scan: ScanResult) -> AnalyzeResultResponse:
    """Helper to convert SQLAlchemy ScanResult to Pydantic AnalyzeResultResponse."""
    return AnalyzeResultResponse(
        id=scan.id,
        threat_id=scan.threat_id,
        gmail_message_id=scan.gmail_message_id,
        sender=scan.sender,
        sender_email=scan.sender_email,
        subject=scan.subject,
        date_received=scan.date_received,
        snippet=scan.snippet,
        content_type=scan.content_type,
        risk_score=scan.risk_score,
        risk_level=scan.risk_level,
        evidence=json.loads(scan.evidence_json or "[]"),
        recommendations=json.loads(scan.recommendations_json or "[]"),
        urls_analyzed=json.loads(scan.urls_json or "[]"),
        signals=json.loads(scan.signals_json or "{}"),
        is_notified=scan.is_notified or False,
        scanned_at=scan.scanned_at or scan.created_at,
        created_at=scan.created_at
    )

# ================= SYSTEM HEALTH & STATUS =================
@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "service": "CyberShield Intelligent Threat Assistant",
        "gmail_connected": is_gmail_connected()["connected"],
        "monitoring_active": MONITOR_STATE["is_running"],
        "monitor_interval_seconds": EMAIL_MONITOR_INTERVAL
    }

@app.get("/api/monitor/status", response_model=MonitoringStatusResponse)
def get_monitor_status(db: Session = Depends(get_db)):
    """Retrieve current background monitoring service status."""
    total_scans = db.query(ScanResult).count()
    active_threats = db.query(ScanResult).filter(ScanResult.risk_score >= 50).count()
    return MonitoringStatusResponse(
        is_monitoring=MONITOR_STATE["is_running"],
        interval_seconds=EMAIL_MONITOR_INTERVAL,
        last_check_time=MONITOR_STATE["last_check_time"],
        total_scanned=total_scans,
        active_threats=active_threats
    )

# ================= GMAIL OAUTH & INGESTION =================
@app.get("/api/gmail/status")
def gmail_status():
    """Check if Gmail OAuth is authorized."""
    return is_gmail_connected()

@app.get("/api/gmail/auth-url")
def gmail_auth_url(redirect_uri: Optional[str] = None):
    """Retrieve Google OAuth consent URL."""
    try:
        url = get_auth_url(redirect_uri) if redirect_uri else get_auth_url()
        return {"auth_url": url}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@app.get("/api/gmail/oauth2callback")
def gmail_oauth_callback(
    code: str,
    state: Optional[str] = None,
    error: Optional[str] = None
):
    """Handle OAuth redirect code from Google with PKCE state verification."""
    if error:
        return RedirectResponse(url=f"/?gmail_error={error}")
    try:
        exchange_code_for_token(code=code, state=state)
        return RedirectResponse(url="/?gmail_connected=true")
    except Exception as e:
        return RedirectResponse(url=f"/?gmail_error={str(e)}")

@app.post("/api/gmail/disconnect")
def gmail_disconnect():
    """Disconnect Gmail account."""
    success = disconnect_gmail()
    return {"status": "success" if success else "failed", "connected": False}

@app.post("/api/gmail/scan", response_model=GmailScanResponse)
def scan_gmail_inbox(
    max_count: int = Query(default=15, ge=1, le=50),
    query: str = Query(default=""),
    db: Session = Depends(get_db)
):
    """Manual Scan Trigger: Fetches, analyzes, and saves inbox messages."""
    status_info = is_gmail_connected()
    if not status_info.get("connected"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Gmail is not connected. Please connect Gmail first via OAuth."
        )

    try:
        emails = fetch_recent_emails(max_count=max_count, query=query)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving Gmail messages: {str(e)}"
        )

    results = []
    threats_count = 0

    for email_item in emails:
        analysis = analyze_content(
            sender=email_item["sender"],
            subject=email_item["subject"],
            body=email_item["body"],
            urls=email_item["urls"]
        )

        risk_score = analysis["risk_score"]
        if risk_score >= 50:
            threats_count += 1

        threat_id = generate_threat_id() if risk_score >= 50 else None

        existing_scan = db.query(ScanResult).filter(
            ScanResult.gmail_message_id == email_item["id"]
        ).first()

        if existing_scan:
            existing_scan.risk_score = analysis["risk_score"]
            existing_scan.risk_level = analysis["risk_level"]
            if risk_score >= 50 and not existing_scan.threat_id:
                existing_scan.threat_id = threat_id
            existing_scan.evidence_json = json.dumps(analysis["evidence"])
            existing_scan.recommendations_json = json.dumps(analysis["recommendations"])
            existing_scan.urls_json = json.dumps(analysis["urls_analyzed"])
            existing_scan.signals_json = json.dumps(analysis["signals"])
            scan_obj = existing_scan
        else:
            scan_obj = ScanResult(
                threat_id=threat_id,
                gmail_message_id=email_item["id"],
                sender=email_item["sender"],
                subject=email_item["subject"],
                date_received=email_item["date"],
                snippet=email_item["snippet"][:400] if email_item["snippet"] else "",
                content_type="email",
                risk_score=analysis["risk_score"],
                risk_level=analysis["risk_level"],
                evidence_json=json.dumps(analysis["evidence"]),
                recommendations_json=json.dumps(analysis["recommendations"]),
                urls_json=json.dumps(analysis["urls_analyzed"]),
                signals_json=json.dumps(analysis["signals"]),
                is_notified=True,
                scanned_at=datetime.utcnow()
            )
            db.add(scan_obj)

        db.commit()
        db.refresh(scan_obj)
        results.append(_model_to_response(scan_obj))

    return GmailScanResponse(
        status="success",
        scanned_count=len(results),
        threats_found=threats_count,
        results=results
    )

# ================= THREAT NOTIFICATION & THREAT APIs =================
@app.get("/api/threats/latest", response_model=List[LatestThreatItem])
def get_latest_threats(
    limit: int = Query(default=15, ge=1, le=50),
    min_score: int = Query(default=50, ge=0, le=100),
    db: Session = Depends(get_db)
):
    """
    Primary Proactive Monitoring Endpoint:
    Returns recent threats with risk_score >= min_score (default 50: includes HIGH >=70 and SUSPICIOUS 50-69)
    """
    threats = db.query(ScanResult).filter(
        ScanResult.risk_score >= min_score
    ).order_by(ScanResult.created_at.desc()).limit(limit).all()

    response_items = []
    has_unnotified = False

    for threat in threats:
        if not threat.threat_id:
            threat.threat_id = generate_threat_id()

        is_new_threat = not bool(threat.is_notified)
        if is_new_threat:
            threat.is_notified = True
            has_unnotified = True

        detected_str = (
            threat.scanned_at.strftime("%Y-%m-%d %H:%M:%S")
            if threat.scanned_at
            else threat.created_at.strftime("%Y-%m-%d %H:%M:%S")
        )

        response_items.append(LatestThreatItem(
            id=threat.id,
            threat_id=threat.threat_id,
            gmail_message_id=threat.gmail_message_id,
            sender=threat.sender or "Unknown",
            subject=threat.subject or "No Subject",
            risk_score=threat.risk_score,
            risk_level=threat.risk_level,
            detected_at=detected_str,
            is_new=is_new_threat
        ))

    if has_unnotified:
        db.commit()

    return response_items

@app.get("/api/gmail/new-threats", response_model=List[AnalyzeResultResponse])
def get_new_threats(db: Session = Depends(get_db)):
    """
    Retrieve newly detected unnotified threats (score >= 50).
    Marks retrieved threats as is_notified=True so notifications are never duplicated.
    """
    unnotified_threats = db.query(ScanResult).filter(
        ScanResult.risk_score >= 50,
        ScanResult.is_notified == False
    ).order_by(ScanResult.created_at.desc()).all()

    response_items = []
    for threat in unnotified_threats:
        if not threat.threat_id:
            threat.threat_id = generate_threat_id()
        threat.is_notified = True
        response_items.append(_model_to_response(threat))

    if unnotified_threats:
        db.commit()

    return response_items

@app.get("/api/threats", response_model=List[AnalyzeResultResponse])
def list_threats(
    limit: int = Query(default=30, ge=1, le=100),
    min_score: int = Query(default=50, ge=0, le=100),
    db: Session = Depends(get_db)
):
    """Retrieve all detected threat records (risk_score >= min_score)."""
    threats = db.query(ScanResult).filter(
        ScanResult.risk_score >= min_score
    ).order_by(ScanResult.created_at.desc()).limit(limit).all()
    return [_model_to_response(t) for t in threats]

@app.get("/api/threats/{threat_id}", response_model=AnalyzeResultResponse)
def get_threat_detail(threat_id: str, db: Session = Depends(get_db)):
    """Retrieve detailed threat investigation breakdown by unique threat_id or database ID."""
    query = db.query(ScanResult).filter(
        (ScanResult.threat_id == threat_id) | (ScanResult.id == int(threat_id) if threat_id.isdigit() else False)
    ).first()

    if not query:
        raise HTTPException(
            status_code=404,
            detail=f"Threat record '{threat_id}' not found."
        )
    return _model_to_response(query)

# ================= MANUAL ANALYSIS =================
@app.post("/api/analyze/manual", response_model=AnalyzeResultResponse)
def analyze_manual_input(
    req: ManualAnalyzeRequest,
    db: Session = Depends(get_db)
):
    """Manual analysis endpoint for custom text, SMS, or URLs."""
    urls = [req.content] if req.content_type == "url" else None
    body = req.content if req.content_type != "url" else ""
    
    analysis = analyze_content(
        sender=req.sender or "",
        subject=req.subject or "",
        body=body,
        urls=urls
    )

    risk_score = analysis["risk_score"]
    threat_id = generate_threat_id() if risk_score >= 50 else None

    scan_obj = ScanResult(
        threat_id=threat_id,
        sender=req.sender or "Manual Entry",
        subject=req.subject or (req.content[:60] if req.content_type == "url" else "Manual Text Check"),
        snippet=req.content[:300],
        content_type=req.content_type,
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        evidence_json=json.dumps(analysis["evidence"]),
        recommendations_json=json.dumps(analysis["recommendations"]),
        urls_json=json.dumps(analysis["urls_analyzed"]),
        signals_json=json.dumps(analysis["signals"]),
        is_notified=True,
        scanned_at=datetime.utcnow()
    )
    db.add(scan_obj)
    db.commit()
    db.refresh(scan_obj)

    return _model_to_response(scan_obj)

# ================= SCAN HISTORY & STATS =================
@app.get("/api/scans", response_model=List[AnalyzeResultResponse])
def list_scans(
    level: Optional[str] = None,
    content_type: Optional[str] = None,
    limit: int = Query(default=30, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Retrieve past scan results from database."""
    query = db.query(ScanResult)
    if level and level.upper() != "ALL":
        query = query.filter(ScanResult.risk_level == level.upper())
    if content_type:
        query = query.filter(ScanResult.content_type == content_type)
    scans = query.order_by(ScanResult.created_at.desc()).limit(limit).all()
    return [_model_to_response(s) for s in scans]

@app.delete("/api/scans")
def clear_all_scans(db: Session = Depends(get_db)):
    """Clear all scan records from database for a fresh demo."""
    db.query(ScanResult).delete()
    db.commit()
    return {"status": "cleared", "message": "All scan records cleared."}

@app.get("/api/scans/stats", response_model=ScanSummaryStats)
def get_scan_stats(db: Session = Depends(get_db)):
    """Retrieve statistical summary of scans."""
    total = db.query(ScanResult).count()
    high = db.query(ScanResult).filter(ScanResult.risk_level == "HIGH").count()
    medium = db.query(ScanResult).filter(ScanResult.risk_level == "MEDIUM").count()
    low = db.query(ScanResult).filter(ScanResult.risk_level == "LOW").count()
    last_scan = db.query(ScanResult).order_by(ScanResult.created_at.desc()).first()
    
    return ScanSummaryStats(
        total_scanned=total,
        high_risk_count=high,
        medium_risk_count=medium,
        low_risk_count=low,
        last_scanned_at=last_scan.created_at.strftime("%Y-%m-%d %H:%M:%S") if last_scan else None
    )

@app.get("/api/scans/{scan_id}", response_model=AnalyzeResultResponse)
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    """Get single scan detailed evidence and breakdown."""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return _model_to_response(scan)

@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a single scan record."""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")
    db.delete(scan)
    db.commit()
    return {"status": "deleted", "id": scan_id}

# ================= FRONTEND & THREAT DETAIL ROUTES =================
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/threat/{threat_id}")
    def serve_threat_detail_page(threat_id: str):
        """Serve the dedicated Threat Details investigation page."""
        threat_page = os.path.join(FRONTEND_DIR, "threat_detail.html")
        if os.path.exists(threat_page):
            return FileResponse(threat_page)
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    @app.get("/threat.html")
    def serve_threat_html():
        """Serve the Threat Details page via threat.html alias."""
        return FileResponse(os.path.join(FRONTEND_DIR, "threat_detail.html"))

    @app.get("/threat_detail.html")
    def serve_threat_detail_html():
        """Serve the Threat Details page via threat_detail.html alias."""
        return FileResponse(os.path.join(FRONTEND_DIR, "threat_detail.html"))

    @app.get("/")
    def serve_frontend_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    @app.get("/{full_path:path}")
    def serve_frontend_files(full_path: str):
        file_path = os.path.join(FRONTEND_DIR, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
