import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from starlette.testclient import TestClient
from main import app

client = TestClient(app)

def test_api():
    print("========================================")
    print("CYBERSHIELD API & ENDPOINT INTEGRATION TESTS")
    print("========================================\n")
    
    # 1. Test Health Endpoint
    print("[1] Testing Health Endpoint (/api/health)...")
    res = client.get("/api/health")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    health_data = res.json()
    print(f"    Health Status: {health_data['status']} | Service: {health_data['service']}")
    
    # 2. Test Gmail Status Endpoint
    print("\n[2] Testing Gmail Status Endpoint (/api/gmail/status)...")
    res = client.get("/api/gmail/status")
    assert res.status_code == 200
    status_data = res.json()
    print(f"    Gmail Connected: {status_data.get('connected')}")
    
    # 3. Test Manual Phishing Analysis Endpoint
    print("\n[3] Testing Manual Phishing Analysis (/api/analyze/manual)...")
    payload = {
        "content_type": "email",
        "sender": "PayPal Fraud Security <security-dept@gmail.com>",
        "subject": "URGENT: Unauthorized $500 Payment - Confirm Identity in 12 Hours",
        "content": "A suspicious payment of $500 was initiated from your PayPal balance. If you did not make this transaction, you must login and verify your password and OTP immediately to freeze your account: http://192.168.1.50/paypal-auth/verify"
    }
    res = client.post("/api/analyze/manual", json=payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    scan_data = res.json()
    print(f"    Risk Level: {scan_data['risk_level']} | Risk Score: {scan_data['risk_score']}/100")
    print(f"    Evidence Count: {len(scan_data['evidence'])}")
    for ev in scan_data['evidence']:
        print(f"      - {ev}")
    print(f"    Recommendations Count: {len(scan_data['recommendations'])}")
    for rec in scan_data['recommendations']:
        print(f"      * {rec}")
    assert scan_data['risk_level'] == "HIGH", f"Expected HIGH risk for urgent phishing, got {scan_data['risk_level']}"
    scan_id = scan_data['id']
    
    # 4. Test Single Scan Detail Endpoint
    print(f"\n[4] Testing Scan Detail Retrieval (/api/scans/{scan_id})...")
    res = client.get(f"/api/scans/{scan_id}")
    assert res.status_code == 200
    detail_data = res.json()
    assert detail_data['id'] == scan_id
    print(f"    Successfully retrieved scan record #{scan_id} with subject: '{detail_data['subject']}'")
    
    # 5. Test Statistics Endpoint
    print("\n[5] Testing Statistics Summary (/api/scans/stats)...")
    res = client.get("/api/scans/stats")
    assert res.status_code == 200
    stats_data = res.json()
    print(f"    Total Scans: {stats_data['total_scanned']} | High: {stats_data['high_risk_count']} | Medium: {stats_data['medium_risk_count']} | Low: {stats_data['low_risk_count']}")
    assert stats_data['total_scanned'] >= 1
    
    # 6. Test Frontend Serving
    print("\n[6] Testing Frontend UI Serving (/)...")
    res = client.get("/")
    assert res.status_code == 200
    assert "CyberShield" in res.text
    print("    Frontend index.html successfully served from root /")

    print("\n>>> ALL API & SYSTEM INTEGRATION TESTS PASSED! <<<")

if __name__ == "__main__":
    test_api()
