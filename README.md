# 🛡️ CyberShield — Intelligent Phishing & Scam Detection Assistant

> **Proactive, Explainable Threat Detection for Gmail & Digital Communications**  
> Built for the 24-Hour Hackathon | Round 2 Proactive Defense Prototype

---

## 💡 The Core Innovation (Addressing Round 1 Feedback)

In Round 1, judges noted that manually copying and pasting suspicious links is a passive, baseline feature.  
**CyberShield transitions from passive scanning to a proactive assistant**:
- 📬 **Automated Gmail Integration**: Connects via official Google OAuth 2.0 with read-only permissions.
- 🔍 **Multi-Signal Ingestion**: Automatically extracts sender identity, subject, MIME body, and all embedded hyperlinks.
- ⚙️ **Explainable Risk Engine**: Transparent rules-based correlation of urgency, credential theft, financial scams, domain lookalikes, raw IP hosts, and deceptive TLDs.
- 📊 **Risk Scoring & Evidence**: Computes a transparent 0–100 Risk Score with clear evidence bullet points.
- 🛡️ **Actionable Guidance**: Direct safe-action checklists to protect users before they click.

---

## 🏗️ Project Architecture

```
                    GMAIL
                      │
                      ▼
              Gmail API / OAuth 2.0
                      │
                      ▼
              CyberShield Backend
               (FastAPI + SQLite)
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
   Email Parser              URL Extractor
         │                         │
         └────────────┬────────────┘
                      │
                      ▼
             Explainable Risk Engine
         ┌────────────┼────────────┐
         ▼            ▼            ▼
     Urgency     Credential     URL & Domain
     Signals       Theft          Signals
         │            │            │
         └────────────┼────────────┘
                      │
                      ▼
               Risk Assessment
         ┌────────────┴────────────┐
         ▼                         ▼
   Evidence Reasons          Safe Recommendations
         │                         │
         └────────────┬────────────┘
                      │
                      ▼
              SQLite Database
                      │
                      ▼
          Frontend Threat Dashboard
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Google Cloud Console account (for Gmail OAuth credentials)

### 2. Setup & Virtual Environment
```bash
# Navigate to project directory
cd CyberShield

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Windows (cmd):
.\venv\Scripts\activate.bat
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
```

### 3. Google OAuth Setup (For Gmail Scanning)
1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project: `CyberShield-Demo`.
3. Go to **APIs & Services > Library** and enable **Gmail API**.
4. Go to **APIs & Services > OAuth consent screen**:
   - Choose **External** user type.
   - Fill in App name (`CyberShield`) and your developer email.
   - Add Test Users: Add your test Gmail address.
5. Go to **APIs & Services > Credentials**:
   - Click **Create Credentials > OAuth client ID**.
   - Application type: **Web application**.
   - Authorized redirect URIs: `http://localhost:8000/api/gmail/oauth2callback`.
   - Download the JSON file and save it as `credentials.json` inside the `backend/` folder (or project root).
   - *(Alternatively, paste `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` into `.env`)*.

### 4. Run the Server
```bash
# From the CyberShield directory:
.\venv\Scripts\uvicorn backend.main:app --reload --port 8000
```
Open your browser at: **`http://localhost:8000`**

---

## 🧪 Testing & Verification

Run automated test suites anytime:

```bash
# Test the Explainable Risk Engine (5 benchmark scenarios):
.\venv\Scripts\python backend/test_analyzer.py

# Test API endpoints, SQLite persistence, and UI routes:
.\venv\Scripts\python backend/test_api.py
```

---

## 🎯 Deterministic Live Demo Plan (For Judges)

1. **Open Dashboard** (`http://localhost:8000`): Show clean UI and quick metrics.
2. **Connect Test Gmail**: Click "Connect Gmail", authenticate with Google OAuth.
3. **Inbox Scan**: Click "Scan Inbox Now" to pull recent emails and show automated threat flags.
4. **Deep Investigation**: Click "Investigate" on a High-Risk email:
   - **Score**: e.g., `100/100 HIGH RISK`
   - **Why is this suspicious?**: Displays exact triggers (Urgency, Credential Harvesting, Suspicious IP Host, Brand Spoofing).
   - **Link Analysis**: Shows breakdown of unencrypted HTTP, raw IP address, deceptive keywords.
   - **What should you do?**: Clear safety checklist (Do not click, report scam).
5. **Explain Round 2 Evolution**:
   > *"Based on Round 1 feedback, the user no longer has to bring the threat to CyberShield. CyberShield detects the threat where it arrives."*
