import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple

# ================= TRUSTED DOMAINS WHITELIST =================
# Safe official corporate & service domains (strictly validated via hostname suffix)
TRUSTED_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "gmail.com", "youtube.com", "microsoft.com", "live.com", "office.com",
    "outlook.com", "microsoftonline.com", "github.com", "linkedin.com",
    "apple.com", "icloud.com", "amazon.com", "netflix.com", "paypal.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "twitter.com", "x.com",
    "facebook.com", "instagram.com", "adobe.com", "dropbox.com", "salesforce.com"
}

# Free webmail providers where anyone can register an address
FREE_WEBMAILS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "mail.com", "proton.me", "protonmail.com"
}

# High-risk top level domains frequently utilized in phishing and malware campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click",
    ".buzz", ".cc", ".rest", ".sbs", ".monster", ".fit", ".icu", ".cam", ".link", ".surf", ".gdn"
}

# Known URL shortener services
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "ow.ly", "buff.ly", "rb.gy"
}

# Deceptive security keywords used in phishing domain names
DECEPTIVE_DOMAIN_PATTERNS = [
    "secure-", "-login", "-verify", "-update", "-auth", "account-", "signin-",
    "banking-", "paypal-", "netflix-", "appleid-", "support-", "customer-service",
    "prize-claim", "claim-prize", "security-alert", "wallet-connect"
]

# Lookalike/typosquatting brand regex patterns (e.g. goog1e, paypa1, micros0ft)
LOOKALIKE_PATTERNS = [
    (r"\bgoog[1l]e\b", "Google"),
    (r"\bpaypa[1l]\b", "PayPal"),
    (r"\bmicros[0o]ft\b", "Microsoft"),
    (r"\bapp[1l]e\b", "Apple"),
    (r"\bnetf[1l]ix\b", "Netflix")
]

# ================= KEYWORD & PATTERN DEFINITIONS =================
URGENCY_KEYWORDS = [
    r"\burgent\b", r"\bimmediate(ly)?\b", r"\bact now\b", r"\bfinal warning\b",
    r"\baccount (will be|has been) (blocked|suspended|terminated|frozen|closed|restricted)\b",
    r"\bwithin (12|24|48) hours\b", r"\bverify now\b", r"\bunauthorized (access|activity|sign-in)\b",
    r"\bsecurity alert\b", r"\blast notice\b", r"\baction required\b",
    r"\btake action immediately\b", r"\brestricted account\b", r"\blimited access\b",
    r"\bimportant security notice\b", r"\bimmediate verification\b"
]

CREDENTIAL_KEYWORDS = [
    r"\bpassword\b", r"\botp\b", r"\bpin\b", r"\blogin\b", r"\bsign-?in\b",
    r"\bverify your (account|identity|email|details|credentials|password)\b",
    r"\bcredentials\b", r"\bsecurity question\b", r"\bpasscode\b",
    r"\bconfirm your (identity|password|pin|account)\b", r"\bre-?activate (your )?account\b",
    r"\bunlock (your )?account\b", r"\bupdate your (information|billing|profile|password|payment method)\b"
]

FINANCIAL_KEYWORDS = [
    r"\bwire transfer\b", r"\bupi\b", r"\bbank account\b", r"\brefund\b",
    r"\blottery\b", r"\bwon\b", r"\bwinner\b", r"\bgrand winner\b", r"\bprize\b",
    r"\bclaim (your )?(prize|funds|reward|cash|money)\b",
    r"\b\$[0-9,]+(\.\d{2})?\b", r"\bmillion (dollars|usd|pounds|euro)\b",
    r"\bcrypto(currency)?\b", r"\bbitcoin\b", r"\binvoice attached\b", r"\bpayment pending\b",
    r"\bunclaimed (funds|money|reward)\b", r"\btax (rebate|refund)\b",
    r"\bcredit card (declined|expired|details)\b"
]

THREAT_KEYWORDS = [
    r"\blegal action\b", r"\barrest warrant\b", r"\bcourt order\b",
    r"\blaw enforcement\b", r"\bpolice complaint\b", r"\bpermanently (deleted|terminated|forfeited)\b",
    r"\bpenalty fee\b", r"\blawsuit\b"
]

IMPERSONATION_TARGETS = [
    "bank", "paypal", "google", "microsoft", "apple", "amazon", "netflix", "chase",
    "wells fargo", "sbi", "hdfc", "icici", "fedex", "dhl", "ups", "irs", "incometax",
    "security team", "account team", "support desk", "helpdesk"
]

# Regex matches standard domains AND raw IP addresses
URL_REGEX = re.compile(
    r'https?://(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d+)?(?:/[^\s<>"]*)?',
    re.IGNORECASE
)

# ================= SAFE HOSTNAME & DOMAIN HELPERS =================
def extract_hostname(url_or_domain: str) -> str:
    """Extract clean lowercase hostname without ports or protocol."""
    if not url_or_domain:
        return ""
    if not url_or_domain.startswith(("http://", "https://")):
        url_or_domain = "http://" + url_or_domain
    try:
        parsed = urlparse(url_or_domain)
        host = parsed.netloc.lower().split(':')[0].strip()
        # Remove userinfo if present (e.g. user@domain.com)
        if "@" in host:
            host = host.split("@")[-1]
        return host
    except Exception:
        return ""

def is_trusted_domain(hostname: str) -> bool:
    """
    Robust Anti-Spoofing Trusted Domain Check:
    Matches exact domain or valid subdomains (e.g. accounts.google.com -> .google.com),
    while strictly preventing spoofing like google.com.evil.com or fake-google.com.
    """
    if not hostname:
        return False
    host = extract_hostname(hostname)
    return any(host == td or host.endswith("." + td) for td in TRUSTED_DOMAINS)

def extract_urls(text: str) -> List[str]:
    """Extract and sanitize URLs from raw text/HTML snippet."""
    if not text:
        return []
    raw_urls = URL_REGEX.findall(text)
    clean_urls = []
    for u in raw_urls:
        u_clean = re.sub(r'[\.,\);>"\']+$', '', u.strip())
        if u_clean and u_clean not in clean_urls:
            clean_urls.append(u_clean)
    return clean_urls

def analyze_url(url_str: str) -> Dict[str, Any]:
    """
    Analyze an individual URL for suspicious characteristics.
    Trusted domains receive 0 risk, eliminating false positives from long URLs/tokens.
    """
    parsed = urlparse(url_str)
    domain = extract_hostname(url_str)
    
    flags = []
    url_risk = 0
    is_https = parsed.scheme.lower() == "https"
    has_ip_host = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
    is_trusted = is_trusted_domain(domain)
    
    # 1. Trusted Domain Exemption (Google, Microsoft, GitHub, etc.)
    if is_trusted and not has_ip_host:
        return {
            "url": url_str,
            "domain": domain,
            "is_https": is_https,
            "is_trusted": True,
            "is_suspicious_tld": False,
            "has_ip_host": False,
            "has_deceptive_keywords": False,
            "has_shortener": False,
            "url_score": 0,
            "flags": ["Official trusted domain"]
        }

    # 2. Raw IP Address host (e.g. http://192.168.1.50/login) - Strong Phishing Signal (+35)
    if has_ip_host:
        flags.append(f"Host uses raw IP address instead of registered domain ({domain})")
        url_risk += 35

    # 3. High-Risk TLD (e.g. .xyz, .top, .click) (+25)
    is_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    if is_suspicious_tld:
        matched_tld = next(tld for tld in SUSPICIOUS_TLDS if domain.endswith(tld))
        flags.append(f"High-risk top level domain ({matched_tld}) commonly used in phishing campaigns")
        url_risk += 25

    # 4. Shortener service obscuring real destination (+10)
    has_shortener = domain in KNOWN_SHORTENERS
    if has_shortener:
        flags.append(f"URL shortener detected ({domain}) hiding the true destination")
        url_risk += 10

    # 5. Lookalike / Typosquatting Brand Impersonation in domain (e.g. goog1e, paypa1) (+35)
    for pattern, brand in LOOKALIKE_PATTERNS:
        if re.search(pattern, domain, re.IGNORECASE):
            flags.append(f"Deceptive typosquatting/lookalike domain impersonating {brand} ({domain})")
            url_risk += 35
            break

    # 6. Deceptive keywords in domain on untrusted host (+25)
    has_deceptive_keywords = any(p in domain for p in DECEPTIVE_DOMAIN_PATTERNS)
    if has_deceptive_keywords and not is_trusted:
        flags.append(f"Untrusted domain contains deceptive security/login keywords ({domain})")
        url_risk += 25

    # 7. Embedded @ symbol (credential/redirection trick) (+30)
    if "@" in parsed.netloc:
        flags.append("URL contains '@' symbol trick to spoof visible host")
        url_risk += 30

    # 8. Plain HTTP on untrusted domain (+5 - small factor only, NEVER marks email High-Risk alone)
    if not is_https and not is_trusted:
        flags.append("Insecure HTTP protocol (unencrypted connection)")
        url_risk += 5

    return {
        "url": url_str,
        "domain": domain,
        "is_https": is_https,
        "is_trusted": False,
        "is_suspicious_tld": is_suspicious_tld,
        "has_ip_host": has_ip_host,
        "has_deceptive_keywords": has_deceptive_keywords,
        "has_shortener": has_shortener,
        "url_score": min(url_risk, 100),
        "flags": flags
    }

def check_sender_risk(sender_str: str) -> Tuple[int, List[str], bool]:
    """
    Check sender address and display name for impersonation, deceptive names, and suspicious TLDs.
    Returns: (score, reasons, is_sender_trusted)
    """
    if not sender_str:
        return 0, [], False
    
    sender_lower = sender_str.lower()
    score = 0
    reasons = []
    
    # Extract email address
    match = re.search(r'<([^>]+)>', sender_str)
    email_addr = match.group(1).lower() if match else (sender_lower if "@" in sender_lower else "")
    domain = email_addr.split("@")[-1] if "@" in email_addr else ""
    
    # Is the sender explicitly on a trusted official corporate domain?
    is_sender_trusted = is_trusted_domain(domain)
    if is_sender_trusted and domain not in FREE_WEBMAILS:
        return 0, [], True

    # 1. Check if sender domain uses a high-risk TLD (+25)
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            reasons.append(f"Sender email domain uses high-risk TLD ({tld})")
            break

    # 2. Check for brand/authority impersonation from free webmails or lookalike domains
    for target in IMPERSONATION_TARGETS:
        if target in sender_lower:
            if domain in FREE_WEBMAILS:
                score += 25
                reasons.append(f"Sender claims authority/brand '{target.title()}' but sends from a free webmail service (@{domain})")
                break
            elif domain and not is_trusted_domain(domain):
                # Sender claims to be Google/Microsoft/PayPal but sends from untrusted domain
                score += 25
                reasons.append(f"Sender claims '{target.title()}' but domain (@{domain}) is not an authentic corporate domain")
                break
                
    return score, reasons, is_sender_trusted

def analyze_content(
    sender: str = "",
    subject: str = "",
    body: str = "",
    urls: List[str] = None
) -> Dict[str, Any]:
    """
    Main Explainable Risk Engine with Anti-Spoofing & False-Positive Elimination:
    Accurately scores emails while protecting legitimate corporate communications.
    """
    evidence = []
    signals = {
        "urgency_score": 0,
        "credential_score": 0,
        "financial_score": 0,
        "threat_score": 0,
        "sender_score": 0,
        "url_score": 0
    }
    
    full_text = f"{subject} {body}".lower()
    sender_risk, sender_reasons, is_sender_trusted = check_sender_risk(sender or "")
    
    # 1. Analyze URLs First
    if urls is None:
        urls = []
    extracted_from_body = extract_urls(body or "")
    all_urls = list(dict.fromkeys(urls + extracted_from_body))
    
    urls_analyzed = []
    max_url_risk = 0
    has_malicious_url = False
    
    for u in all_urls:
        u_res = analyze_url(u)
        urls_analyzed.append(u_res)
        if u_res["url_score"] > max_url_risk:
            max_url_risk = u_res["url_score"]
        if u_res["has_ip_host"] or u_res["is_suspicious_tld"] or u_res["has_deceptive_keywords"] or u_res["url_score"] >= 30:
            has_malicious_url = True
        for f in u_res["flags"]:
            if f != "Official trusted domain" and f"Link Flag: {f}" not in evidence:
                evidence.append(f"Link Flag: {f}")
                
    if urls_analyzed:
        signals["url_score"] = min(max_url_risk, 40)

    # 2. Check if entire email is an authentic communication from a trusted sender with safe URLs
    all_urls_trusted = len(urls_analyzed) > 0 and all(u.get("is_trusted", False) for u in urls_analyzed)
    
    # 3. Urgency Signals (+15)
    matched_urgency = [k for k in URGENCY_KEYWORDS if re.search(k, full_text, re.IGNORECASE)]
    if matched_urgency:
        # If from a verified trusted sender with safe links, security alert words are legitimate (+0 to +5)
        if is_sender_trusted and (all_urls_trusted or len(urls_analyzed) == 0):
            signals["urgency_score"] = 0
        else:
            signals["urgency_score"] = 15
            evidence.append("Urgent or fear-inducing language detected (pressure to act quickly)")

    # 4. Credential Harvest Signals (+20)
    matched_credentials = [k for k in CREDENTIAL_KEYWORDS if re.search(k, full_text, re.IGNORECASE)]
    if matched_credentials:
        if is_sender_trusted and (all_urls_trusted or len(urls_analyzed) == 0):
            signals["credential_score"] = 0
        else:
            signals["credential_score"] = 20
            evidence.append("Sensitive credential or password verification request detected")

    # 5. Financial Fraud Signals (+25)
    matched_financial = [k for k in FINANCIAL_KEYWORDS if re.search(k, full_text, re.IGNORECASE)]
    if matched_financial:
        signals["financial_score"] = 25
        evidence.append("Financial solicitation or prize/reward claim detected (wire transfer, lottery, or refund)")

    # 6. Threatening / Coercive Language (+15)
    matched_threat = [k for k in THREAT_KEYWORDS if re.search(k, full_text, re.IGNORECASE)]
    if matched_threat:
        signals["threat_score"] = 15
        evidence.append("Coercive or legal threats detected (e.g. arrest warrant, police report, or permanent forfeiture)")

    # 7. Sender Risk & Impersonation
    if sender_risk > 0:
        signals["sender_score"] = min(sender_risk, 30)
        evidence.extend(sender_reasons)

    # 8. Compound Attack Synergies (Phishing attacks combine multiple factors)
    compound_boost = 0
    if not is_sender_trusted:
        # Urgency + Credential Harvesting on untrusted message -> Strong attack synergy (+25)
        if signals["urgency_score"] > 0 and signals["credential_score"] > 0:
            compound_boost += 25
            evidence.append("High-risk attack pattern: Urgent pressure combined with credential harvesting")
        
        # Financial incentive + Suspicious link/sender -> Strong scam synergy (+20)
        if signals["financial_score"] > 0 and (signals["sender_score"] > 0 or signals["url_score"] > 0):
            compound_boost += 20
            evidence.append("High-risk attack pattern: Financial incentive paired with suspicious domain/sender")

        # Explicit Malicious URL (Raw IP / Typosquatting / High-risk TLD) + any social engineering (+20)
        if has_malicious_url and (signals["urgency_score"] > 0 or signals["credential_score"] > 0 or signals["financial_score"] > 0):
            compound_boost += 20

    # Calculate Final Score
    raw_total = sum(signals.values()) + compound_boost
    final_score = min(max(raw_total, 0), 100)

    # 9. Classify Risk Level
    if final_score >= 70:
        risk_level = "HIGH"
    elif final_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # 10. Formulate Actionable Safe Guidance
    recommendations = []
    if risk_level == "HIGH":
        recommendations.append("❌ Do NOT click any links or download attachments in this message.")
        recommendations.append("❌ Never provide passwords, OTPs, PINs, or banking credentials.")
        recommendations.append("❌ Do NOT make any urgent transfers or payments.")
        recommendations.append("🛡️ If you know the organization, verify independently via their official app or website.")
        recommendations.append("🚩 Mark and report this email as Phishing/Spam.")
    elif risk_level == "MEDIUM":
        recommendations.append("⚠️ Inspect the sender address and domain carefully before responding.")
        recommendations.append("🔍 Avoid clicking links directly; open the trusted website in a separate tab.")
        recommendations.append("🛡️ Do not submit passwords or sensitive data without independent confirmation.")
    else:
        recommendations.append("✅ No high-risk scam or phishing indicators were detected.")
        recommendations.append("💡 Continue standard digital caution when opening unexpected attachments or links.")

    if not evidence:
        evidence.append("Message content aligns with standard communication patterns.")

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "evidence": evidence,
        "recommendations": recommendations,
        "urls_analyzed": urls_analyzed,
        "signals": signals
    }
