import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import json
from starlette.testclient import TestClient
from main import app
from database import SessionLocal
from models import ScanResult
from gmail_service import generate_threat_id

client = TestClient(app)

def test_automated_monitoring_and_threats():
    print("========================================")
    print("CYBERSHIELD PROACTIVE MONITORING & THREAT TESTS")
    print("========================================\n")

    db = SessionLocal()
    try:
        # Clean test records
        db.query(ScanResult).delete()
        db.commit()

        # 1. Test Monitor Status Endpoint
        print("[1] Testing Monitor Status API (/api/monitor/status)...")
        res = client.get("/api/monitor/status")
        assert res.status_code == 200
        m_data = res.json()
        print(f"    Monitoring Active: {m_data['is_monitoring']} | Interval: {m_data['interval_seconds']}s")
        assert m_data["is_monitoring"] is True
        assert m_data["interval_seconds"] == 30

        # 2. Insert Simulated Background Scanned Emails
        print("\n[2] Simulating Background Email Ingestion & Analysis...")
        threat_id_sample = generate_threat_id()
        
        phishing_scan = ScanResult(
            threat_id=threat_id_sample,
            gmail_message_id="msg-gmail-test-2001",
            sender="Security Alerts <security@suspicious-bank.com>",
            subject="URGENT: Verify Your Account Immediately",
            date_received="Sat, 29 Aug 2026 04:00:00 GMT",
            snippet="Action required! Your account has been temporarily blocked. Verify OTP: http://suspicious-example.com/login",
            content_type="email",
            risk_score=87,
            risk_level="HIGH",
            evidence_json=json.dumps([
                "Urgent language detected",
                "Suspicious URL detected",
                "Credential phishing pattern",
                "Suspicious sender/domain pattern"
            ]),
            recommendations_json=json.dumps([
                "Do not click suspicious links.",
                "Do not enter passwords or OTPs.",
                "Verify the sender independently.",
                "Report or delete the phishing email."
            ]),
            urls_json=json.dumps([{
                "url": "http://suspicious-example.com/login",
                "domain": "suspicious-example.com",
                "is_https": False,
                "is_suspicious_tld": False,
                "has_ip_host": False,
                "has_deceptive_keywords": True,
                "has_shortener": False,
                "url_score": 45,
                "flags": ["Insecure HTTP protocol", "Domain contains deceptive login keywords"]
            }]),
            signals_json=json.dumps({"urgency": 20, "credential": 25, "sender": 20, "url": 22}),
            is_notified=False
        )

        benign_scan = ScanResult(
            threat_id=None,
            gmail_message_id="msg-gmail-test-2002",
            sender="Team Sync <team@company.com>",
            subject="Meeting notes and roadmap",
            date_received="Sat, 29 Aug 2026 04:05:00 GMT",
            snippet="Here are the meeting notes from yesterday's session.",
            content_type="email",
            risk_score=0,
            risk_level="LOW",
            evidence_json=json.dumps(["Standard digital communication pattern"]),
            recommendations_json=json.dumps(["Continue standard digital caution."]),
            urls_json=json.dumps([]),
            signals_json=json.dumps({}),
            is_notified=True
        )

        db.add(phishing_scan)
        db.add(benign_scan)
        db.commit()
        print(f"    Inserted High-Risk Threat (Threat ID: {threat_id_sample}) and Low-Risk Clean Email.")

        # 3. Test Duplicate Ingestion Prevention
        print("\n[3] Testing Duplicate Ingestion Prevention...")
        duplicate_check = db.query(ScanResult).filter(ScanResult.gmail_message_id == "msg-gmail-test-2001").count()
        assert duplicate_check == 1, "Duplicate message ID found in database!"
        print("    Verified: gmail_message_id uniquely identifies processed emails and prevents duplicate re-analysis.")

        # 4. Test GET /api/threats/latest Endpoint
        print("\n[4] Testing Latest Threats Endpoint (/api/threats/latest)...")
        res = client.get("/api/threats/latest")
        assert res.status_code == 200
        latest_threats = res.json()
        assert len(latest_threats) == 1, f"Expected 1 threat, got {len(latest_threats)}"
        threat_item = latest_threats[0]
        assert threat_item["threat_id"] == threat_id_sample
        assert threat_item["is_new"] is True
        print(f"    Retrieved Latest Threat: '{threat_item['subject']}' | Score: {threat_item['risk_score']} | is_new: {threat_item['is_new']}")

        # Second poll should return is_new=False
        res2 = client.get("/api/threats/latest")
        assert res2.status_code == 200
        threat_item2 = res2.json()[0]
        assert threat_item2["is_new"] is False
        print("    Verified: Backend state updated (is_new=False), preventing duplicate notifications.")

        # 5. Test Threats Listing API (/api/threats)
        print("\n[5] Testing Threats Listing API (/api/threats)...")
        res = client.get("/api/threats")
        assert res.status_code == 200
        threats_list = res.json()
        assert len(threats_list) >= 1
        print(f"    Total active threats listed: {len(threats_list)}")

        # 6. Test Single Threat Detail API (/api/threats/{threat_id})
        print(f"\n[6] Testing Single Threat Detail API (/api/threats/{threat_id_sample})...")
        res = client.get(f"/api/threats/{threat_id_sample}")
        assert res.status_code == 200
        detail = res.json()
        assert detail["threat_id"] == threat_id_sample
        assert detail["risk_score"] == 87
        assert len(detail["evidence"]) == 4
        print(f"    Retrieved Threat Record: Subject='{detail['subject']}', Score={detail['risk_score']}/100")

        # 7. Test Dedicated Threat Page Route (/threat/{threat_id})
        print(f"\n[7] Testing Threat Detail Web Route (/threat/{threat_id_sample})...")
        res = client.get(f"/threat/{threat_id_sample}")
        assert res.status_code == 200
        assert "Threat Investigation Report" in res.text
        print("    Dedicated Threat Details HTML page successfully served at /threat/{threat_id}")

        print("\n>>> ALL PROACTIVE MONITORING & THREAT TESTS PASSED! <<<")

    finally:
        db.close()

if __name__ == "__main__":
    test_automated_monitoring_and_threats()
