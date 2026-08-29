import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from analyzer import analyze_content, is_trusted_domain

def run_tests():
    print("========================================")
    print("CYBERSHIELD INTELLIGENT RISK ENGINE TEST SUITE")
    print("========================================\n")
    
    # 1. Test Anti-Spoofing Domain Matching
    print("--- [1] Anti-Spoofing Trusted Domain Matching Tests ---")
    assert is_trusted_domain("google.com") is True, "google.com should be trusted"
    assert is_trusted_domain("accounts.google.com") is True, "accounts.google.com should be trusted"
    assert is_trusted_domain("mail.google.com") is True, "mail.google.com should be trusted"
    assert is_trusted_domain("microsoft.com") is True, "microsoft.com should be trusted"
    assert is_trusted_domain("login.microsoftonline.com") is True, "login.microsoftonline.com should be trusted"
    assert is_trusted_domain("google.com.evil.com") is False, "google.com.evil.com must NOT be trusted!"
    assert is_trusted_domain("fake-google.com") is False, "fake-google.com must NOT be trusted!"
    assert is_trusted_domain("goog1e.com") is False, "goog1e.com must NOT be trusted!"
    print("  ✅ All Anti-Spoofing Hostname Validation Tests Passed.\n")

    # 2. Comprehensive Legitimate & Suspicious Test Cases
    test_cases = [
        # --- LEGITIMATE CATEGORY ---
        {
            "category": "LEGITIMATE",
            "name": "1. Google Security Alert (Legitimate Domain)",
            "sender": "Google <no-reply@accounts.google.com>",
            "subject": "Security alert: New sign-in from Chrome on Windows",
            "body": "Your Google Account was recently signed in from a new device. You can review your security activity here: https://accounts.google.com/ManageAccount?nc=1",
            "urls": ["https://accounts.google.com/ManageAccount?nc=1"],
            "expected_level": "LOW"
        },
        {
            "category": "LEGITIMATE",
            "name": "2. Microsoft Account Security Notification",
            "sender": "Microsoft Account Team <account-security-noreply@accountprotection.microsoft.com>",
            "subject": "Microsoft account security code",
            "body": "Please use the following single-use code for your Microsoft account: 489201. If you did not request this, you can review activity: https://account.live.com/activity",
            "urls": ["https://account.live.com/activity"],
            "expected_level": "LOW"
        },
        {
            "category": "LEGITIMATE",
            "name": "3. Tech Newsletter with Long Tracking URLs",
            "sender": "Python Weekly <newsletter@pythonweekly.com>",
            "subject": "Python Weekly - Issue #650",
            "body": "Here are the top articles this week on FastAPI, machine learning, and asyncio performance.",
            "urls": ["https://newsletter.pythonweekly.com/track/click?utm_source=email_campaign&utm_medium=weekly&id=9283749823&token=abc123xyz789"],
            "expected_level": "LOW"
        },
        {
            "category": "LEGITIMATE",
            "name": "4. Long Google API URLs with Parameters",
            "sender": "Google Cloud Platform <cloud-noreply@google.com>",
            "subject": "Your Google Cloud Project Status",
            "body": "API usage metrics and quotas updated for project 'CyberShield-Dev'. View metrics at: https://googleapis.com/v1/auth/userinfo.profile?access_token=ya29.a0AfH6SM...&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly",
            "urls": ["https://googleapis.com/v1/auth/userinfo.profile?access_token=ya29.a0AfH6SM...&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly"],
            "expected_level": "LOW"
        },
        {
            "category": "LEGITIMATE",
            "name": "5. Legitimate HTTPS Login URL",
            "sender": "GitHub <notifications@github.com>",
            "subject": "Sign in to your GitHub account",
            "body": "Use this link to securely sign in to your GitHub account: https://github.com/login",
            "urls": ["https://github.com/login"],
            "expected_level": "LOW"
        },

        # --- SUSPICIOUS / PHISHING CATEGORY ---
        {
            "category": "SUSPICIOUS",
            "name": "6. Fake Google Login (Typosquatting/Lookalike)",
            "sender": "Google Security Desk <security-alert@gmail.com>",
            "subject": "URGENT: Unauthorized login detected on your Google Account",
            "body": "Your account has been accessed from an unknown location. Sign in immediately to verify your identity: http://goog1e-security-login.example/login",
            "urls": ["http://goog1e-security-login.example/login"],
            "expected_level": "HIGH"
        },
        {
            "category": "SUSPICIOUS",
            "name": "7. Credential Phishing with Urgent Threat",
            "sender": "Account Protection <service@untrusted-verify.xyz>",
            "subject": "Immediate action required: Account Suspension Notice",
            "body": "Verify your password immediately within 24 hours or your account will be suspended. Click here to confirm your password and OTP: http://untrusted-verify.xyz/auth",
            "urls": ["http://untrusted-verify.xyz/auth"],
            "expected_level": "HIGH"
        },
        {
            "category": "SUSPICIOUS",
            "name": "8. Financial Scam / Coercive Transfer",
            "sender": "Billing Department <billing@tax-claim.top>",
            "subject": "FINAL WARNING: Immediate wire transfer required to avoid lawsuit",
            "body": "Send payment of $5,000 immediately via wire transfer to avoid account closure and court order lawsuit: http://claim-funds.top/pay",
            "urls": ["http://claim-funds.top/pay"],
            "expected_level": "HIGH"
        },
        {
            "category": "SUSPICIOUS",
            "name": "9. Raw IP Address Phishing URL",
            "sender": "Bank Alert Center <security@bank-alert.com>",
            "subject": "URGENT: Your Bank Account Access is Suspended",
            "body": "Your bank account has been blocked. Enter your username, password, and OTP immediately at: http://192.168.10.50/login",
            "urls": ["http://192.168.10.50/login"],
            "expected_level": "HIGH"
        },
        {
            "category": "SUSPICIOUS",
            "name": "10. Fake PayPal Deceptive Domain",
            "sender": "PayPal Support <service@paypal-security-verify.example>",
            "subject": "Action Required: Update your PayPal credentials",
            "body": "We detected unauthorized transactions. Confirm your identity and payment method here: http://paypal-security-verify.example/account",
            "urls": ["http://paypal-security-verify.example/account"],
            "expected_level": "HIGH"
        }
    ]

    all_passed = True
    for t in test_cases:
        res = analyze_content(t["sender"], t["subject"], t["body"], t["urls"])
        passed = (res["risk_level"] == t["expected_level"])
        status = "PASSED [OK]" if passed else f"FAILED [Expected {t['expected_level']}, got {res['risk_level']}]"
        if not passed:
            all_passed = False
            
        print(f"[{t['category']}] {t['name']}")
        print(f"  Sender : {t['sender']}")
        print(f"  Subject: {t['subject']}")
        print(f"  Result : Score = {res['risk_score']}/100 | Level = {res['risk_level']} | Status: {status}")
        print("  Threat Indicators / Evidence:")
        for ev in res["evidence"]:
            print(f"    - {ev}")
        if res["urls_analyzed"]:
            print("  URL Analysis:")
            for u in res["urls_analyzed"]:
                print(f"    * {u['url']} -> Domain: {u['domain']}, Trusted: {u.get('is_trusted', False)}, Score: {u['url_score']}, Flags: {u['flags']}")
        print("-" * 65)
        
    if all_passed:
        print("\n>>> ALL 10 TEST SCENARIOS PASSED WITH ZERO FALSE POSITIVES! <<<")
    else:
        print("\n>>> SOME TESTS FAILED! <<<")
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
