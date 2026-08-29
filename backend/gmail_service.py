import os
import json
import base64
import re
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

try:
    from .analyzer import analyze_content, extract_urls
    from .models import ScanResult
except ImportError:
    from analyzer import analyze_content, extract_urls
    from models import ScanResult

# Read-only Gmail scope for maximum security and privacy
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(BASE_DIR, "token.json")
CREDENTIALS_FILE = os.path.join(BASE_DIR, "credentials.json")
STATE_CACHE_FILE = os.path.join(BASE_DIR, ".oauth_states.json")

#Google auth URL
GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "http://localhost:8000/api/gmail/oauth2callback"
)   

OAUTH_STATES: Dict[str, str] = {}

if not os.path.exists(CREDENTIALS_FILE):
    root_creds = os.path.join(os.path.dirname(BASE_DIR), "credentials.json")
    if os.path.exists(root_creds):
        CREDENTIALS_FILE = root_creds

def generate_threat_id() -> str:
    """Generate a unique, clean CyberShield Threat Identifier."""
    return f"CS-THREAT-{uuid.uuid4().hex[:8].upper()}"

def _save_state_verifier(state: str, verifier: Optional[str]):
    """Persist OAuth state to PKCE verifier mapping in memory and on disk."""
    if not verifier:
        return
    OAUTH_STATES[state] = verifier
    OAUTH_STATES["_latest"] = verifier
    try:
        data = {}
        if os.path.exists(STATE_CACHE_FILE):
            try:
                with open(STATE_CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {}
        data[state] = verifier
        data["_latest"] = verifier
        with open(STATE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass

def _get_state_verifier(state: Optional[str]) -> Optional[str]:
    """Retrieve saved PKCE code_verifier for given state."""
    if state and state in OAUTH_STATES:
        return OAUTH_STATES[state]
    if "_latest" in OAUTH_STATES:
        return OAUTH_STATES["_latest"]
        
    if os.path.exists(STATE_CACHE_FILE):
        try:
            with open(STATE_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if state and state in data:
                    return data[state]
                if "_latest" in data:
                    return data["_latest"]
        except Exception:
            pass
    return None

def get_client_config() -> Optional[Dict[str, Any]]:
    """Retrieve Google OAuth configuration."""

    config = None

    # Load credentials.json if available
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception:
            pass

    # Environment variables
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

    redirect_uri = GOOGLE_REDIRECT_URI

    # If credentials.json exists
    if config:
        web = config.get("web", {})

        # Override redirect URI for deployment
        web["redirect_uris"] = [redirect_uri]

        config["web"] = web

        return config

    # Otherwise use environment variables
    if client_id and client_secret:
        return {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [redirect_uri]
            }
        }

    return None
            

def get_credentials() -> Optional[Credentials]:
    """Load credentials and refresh automatically if expired."""
    if not os.path.exists(TOKEN_FILE):
        return None
    try:
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(creds.to_json())
        return creds if (creds and creds.valid) else None
    except Exception as e:
        print(f"[Gmail Auth] Token refresh error: {e}")
        return None

def is_gmail_connected() -> Dict[str, Any]:
    """Check if valid Gmail credentials exist."""
    if not os.path.exists(TOKEN_FILE):
        return {"connected": False, "email": None, "message": "Gmail is not connected."}
    
    try:
        creds = get_credentials()
        if creds and creds.valid:
            return {
                "connected": True,
                "email": "Connected Gmail User",
                "message": "Gmail authorized"
            }
    except Exception as e:
        return {"connected": False, "email": None, "error": str(e)}
        
    return {"connected": False, "email": None}

def create_oauth_flow(redirect_uri: str = GOOGLE_REDIRECT_URI, state: Optional[str] = None) -> Flow:
    """Create OAuth 2.0 flow instance."""
    config = get_client_config()
    if not config:
        raise ValueError(
            "Google OAuth credentials missing. Please add 'credentials.json' to the backend folder "
            "or set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env"
        )
    flow = Flow.from_client_config(config, scopes=SCOPES, redirect_uri=redirect_uri, state=state)
    return flow

def get_auth_url(redirect_uri: str = GOOGLE_REDIRECT_URI) -> str:
    """Generate Google authorization consent URL with PKCE tracking."""
    flow = create_oauth_flow(redirect_uri)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    _save_state_verifier(state, getattr(flow, "code_verifier", None))
    return auth_url

def exchange_code_for_token(
    code: str,
    state: Optional[str] = None,
    redirect_uri: str = GOOGLE_REDIRECT_URI
) -> Credentials:
    """Exchange authorization code for tokens, restoring PKCE code_verifier, and save to token.json."""
    flow = create_oauth_flow(redirect_uri, state=state)
    verifier = _get_state_verifier(state)
    if verifier:
        flow.code_verifier = verifier

    flow.fetch_token(code=code)
    creds = flow.credentials
    with open(TOKEN_FILE, "w", encoding="utf-8") as token:
        token.write(creds.to_json())
        
    if os.path.exists(STATE_CACHE_FILE):
        try:
            os.remove(STATE_CACHE_FILE)
        except Exception:
            pass

    return creds

def disconnect_gmail() -> bool:
    """Remove saved token.json."""
    if os.path.exists(TOKEN_FILE):
        try:
            os.remove(TOKEN_FILE)
            return True
        except Exception:
            return False
    return True

def get_gmail_service():
    """Build authorized Gmail API client service with automatic token refresh."""
    creds = get_credentials()
    if not creds:
        raise ValueError("Gmail is not authorized or token expired. Please connect Gmail first via OAuth.")
    return build("gmail", "v1", credentials=creds)

def _clean_html_tags(raw_html: str) -> str:
    """Strip HTML tags and scripts to extract readable text body."""
    cleaned = re.sub(r'<(script|style).*?</\1>', '', raw_html, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<br\s*/?>', '\n', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'</p>', '\n', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'<[^<]+?>', ' ', cleaned)
    cleaned = cleaned.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
    cleaned = re.sub(r'[ \t]+', ' ', cleaned)
    return cleaned.strip()

def _extract_body_and_urls(payload: dict) -> Tuple[str, List[str]]:
    """Recursively parse multipart payload to extract text body and URLs."""
    body_text = ""
    html_text = ""
    urls = []
    
    def walk_parts(part):
        nonlocal body_text, html_text, urls
        mime_type = part.get("mimeType", "")
        body_data = part.get("body", {}).get("data")
        
        if body_data:
            try:
                decoded = base64.urlsafe_b64decode(body_data.encode("ASCII")).decode("utf-8", errors="ignore")
                if mime_type == "text/plain":
                    body_text += "\n" + decoded
                    urls.extend(extract_urls(decoded))
                elif mime_type == "text/html":
                    html_text += "\n" + decoded
                    href_urls = re.findall(r'href=[\'"](https?://[^\'"]+)[\'"]', decoded, re.IGNORECASE)
                    urls.extend(href_urls)
                    urls.extend(extract_urls(decoded))
            except Exception:
                pass
                
        parts = part.get("parts", [])
        for sub_part in parts:
            walk_parts(sub_part)
            
    walk_parts(payload)
    
    final_body = body_text.strip()
    if not final_body and html_text:
        final_body = _clean_html_tags(html_text)
        
    clean_urls = list(dict.fromkeys(extract_urls(final_body) + urls))
    return final_body, clean_urls

def parse_message_payload(msg: dict) -> Dict[str, Any]:
    """Parse raw Gmail message object into clean dictionary."""
    msg_id = msg.get("id")
    snippet = msg.get("snippet", "")
    payload = msg.get("payload", {})
    headers = payload.get("headers", [])
    
    sender = "Unknown Sender"
    subject = "No Subject"
    date_str = ""
    
    for h in headers:
        name = h.get("name", "").lower()
        if name == "from":
            sender = h.get("value", "")
        elif name == "subject":
            subject = h.get("value", "")
        elif name == "date":
            date_str = h.get("value", "")
            
    body_text, urls = _extract_body_and_urls(payload)
    
    if not body_text:
        body_text = snippet
        urls.extend(extract_urls(snippet))
        
    return {
        "id": msg_id,
        "sender": sender,
        "subject": subject,
        "date": date_str,
        "snippet": snippet,
        "body": body_text,
        "urls": urls
    }

def fetch_recent_emails(max_count: int = 15, query: str = "") -> List[Dict[str, Any]]:
    """Retrieve and parse recent messages from Gmail inbox."""
    service = get_gmail_service()
    kwargs = {"userId": "me", "maxResults": max_count}
    if query:
        kwargs["q"] = query
    res = service.users().messages().list(**kwargs).execute()
    messages_meta = res.get("messages", [])
    
    parsed_emails = []
    for m in messages_meta:
        try:
            full_msg = service.users().messages().get(userId="me", id=m["id"], format="full").execute()
            parsed = parse_message_payload(full_msg)
            parsed_emails.append(parsed)
        except Exception:
            continue
            
    return parsed_emails

def check_and_process_new_emails(db) -> Dict[str, int]:
    """
    Automated Background Monitoring Job:
    Checks Gmail for new incoming messages, prevents duplicate scanning via SQLite,
    and runs the risk engine on new messages with detailed terminal logging.
    """
    print("[Monitor] Checking Gmail for new emails...")

    try:
        service = get_gmail_service()
    except Exception as e:
        print(f"[Monitor] Gmail service authentication error: {e}")
        return {"scanned_new": 0, "new_threats": 0}

    try:
        res = service.users().messages().list(userId="me", maxResults=15).execute()
        messages_meta = res.get("messages", [])
    except Exception as e:
        print(f"[Monitor] Error retrieving Gmail messages: {e}")
        return {"scanned_new": 0, "new_threats": 0}

    print(f"[Monitor] Gmail returned {len(messages_meta)} messages")

    new_scans_count = 0
    new_threats_count = 0

    for m in messages_meta:
        msg_id = m.get("id")
        if not msg_id:
            continue

        print(f"[Monitor] Checking message ID: {msg_id}")

        # Check SQLite if already scanned - PREVENTS DUPLICATE SCANNING
        existing_scan = db.query(ScanResult).filter(
            ScanResult.gmail_message_id == msg_id
        ).first()

        if existing_scan:
            print("[Monitor] Message already scanned")
            continue

        # New email detected! Fetch full message
        try:
            full_msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
            parsed_email = parse_message_payload(full_msg)
        except Exception as e:
            print(f"[Monitor] Error fetching details for message {msg_id}: {e}")
            continue

        print(f"[Monitor] NEW EMAIL DETECTED: {parsed_email['subject']}")
        print("[Analyzer] Starting analysis")

        try:
            analysis = analyze_content(
                sender=parsed_email["sender"],
                subject=parsed_email["subject"],
                body=parsed_email["body"],
                urls=parsed_email["urls"]
            )
        except Exception as e:
            print(f"[Analyzer] Error analyzing email content: {e}")
            continue

        risk_score = analysis["risk_score"]
        risk_level = analysis["risk_level"]
        print(f"[Analyzer] Risk score: {risk_score} ({risk_level})")

        threat_id = generate_threat_id() if risk_score >= 50 else None
        if risk_level == "HIGH":
            new_threats_count += 1
            print(f"[Threat] High-risk email detected")
        elif risk_score >= 50:
            new_threats_count += 1
            print(f"[Threat] Suspicious email warning (Score: {risk_score})")

        try:
            scan_obj = ScanResult(
                threat_id=threat_id,
                gmail_message_id=msg_id,
                sender=parsed_email["sender"],
                subject=parsed_email["subject"],
                date_received=parsed_email["date"],
                snippet=parsed_email["snippet"][:400] if parsed_email["snippet"] else "",
                content_type="email",
                risk_score=risk_score,
                risk_level=risk_level,
                evidence_json=json.dumps(analysis["evidence"]),
                recommendations_json=json.dumps(analysis["recommendations"]),
                urls_json=json.dumps(analysis["urls_analyzed"]),
                signals_json=json.dumps(analysis["signals"]),
                is_notified=False,
                scanned_at=datetime.utcnow()
            )
            db.add(scan_obj)
            db.commit()
            print(f"[Database] Threat saved successfully (Threat ID: {threat_id or 'N/A'})")
            new_scans_count += 1
        except Exception as e:
            db.rollback()
            print(f"[Database] Error saving scan record to database: {e}")

    return {"scanned_new": new_scans_count, "new_threats": new_threats_count}
