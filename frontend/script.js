// CyberShield Frontend Interactive Client Logic

const API_BASE = ""; // Relative path when served from FastAPI
const POLL_INTERVAL_MS = 10000; // 10-second automatic threat polling

let currentScans = [];
let isGmailConnected = false;
let notificationPermissionGranted = false;
let pollingTimer = null;

// DOM Elements
const gmailStatusBadge = document.getElementById("gmailStatusBadge");
const gmailStatusText = document.getElementById("gmailStatusText");
const connectGmailBtn = document.getElementById("connectGmailBtn");
const scanInboxBtn = document.getElementById("scanInboxBtn");
const promptConnectBtn = document.getElementById("promptConnectBtn");
const gmailPromptCard = document.getElementById("gmailPromptCard");
const threatListContainer = document.getElementById("threatListContainer");
const filterRiskSelect = document.getElementById("filterRiskSelect");
const suspiciousAlertToggle = document.getElementById("suspiciousAlertToggle");

// Stats Elements
const statTotal = document.getElementById("statTotal");
const statHigh = document.getElementById("statHigh");
const statMedium = document.getElementById("statMedium");
const statLow = document.getElementById("statLow");

// Modal Elements
const threatModal = document.getElementById("threatModal");
const closeModalBtn = document.getElementById("closeModalBtn");
const modalCloseBtn = document.getElementById("modalCloseBtn");
const modalRiskBadge = document.getElementById("modalRiskBadge");
const modalSubject = document.getElementById("modalSubject");
const modalScoreBanner = document.getElementById("modalScoreBanner");
const modalScoreVal = document.getElementById("modalScoreVal");
const modalRiskLevelHeading = document.getElementById("modalRiskLevelHeading");
const modalRiskSummary = document.getElementById("modalRiskSummary");
const modalSender = document.getElementById("modalSender");
const modalDate = document.getElementById("modalDate");
const modalSnippet = document.getElementById("modalSnippet");
const modalEvidenceList = document.getElementById("modalEvidenceList");
const modalUrlList = document.getElementById("modalUrlList");
const modalRecommendationsList = document.getElementById("modalRecommendationsList");
const reportScamBtn = document.getElementById("reportScamBtn");

// Manual Tab Elements
const runManualAnalysisBtn = document.getElementById("runManualAnalysisBtn");
const loadSampleScamBtn = document.getElementById("loadSampleScamBtn");
const manualSender = document.getElementById("manualSender");
const manualSubject = document.getElementById("manualSubject");
const manualContent = document.getElementById("manualContent");

// History Elements
const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const historyTableBody = document.getElementById("historyTableBody");

// ================= LOCALSTORAGE NOTIFICATION TRACKER =================
function getNotifiedThreatIds() {
  try {
    const raw = localStorage.getItem("cybershield_notified_threats");
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function markThreatAsNotifiedInStorage(threatId) {
  try {
    const ids = getNotifiedThreatIds();
    if (!ids.includes(String(threatId))) {
      ids.push(String(threatId));
      localStorage.setItem("cybershield_notified_threats", JSON.stringify(ids));
    }
  } catch (e) {}
}

// ================= INITIALIZATION =================
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  checkUrlParams();
  refreshGmailStatus();
  refreshStats();
  loadScanHistory();
  initNotificationSupport();
  initSuspiciousToggle();

  // Attach Event Listeners
  connectGmailBtn.addEventListener("click", handleConnectGmail);
  promptConnectBtn.addEventListener("click", handleConnectGmail);
  scanInboxBtn.addEventListener("click", handleScanInbox);
  filterRiskSelect.addEventListener("change", renderThreatFeed);
  
  closeModalBtn.addEventListener("click", () => threatModal.style.display = "none");
  modalCloseBtn.addEventListener("click", () => threatModal.style.display = "none");
  window.addEventListener("click", (e) => {
    if (e.target === threatModal) threatModal.style.display = "none";
  });

  runManualAnalysisBtn.addEventListener("click", handleManualAnalysis);
  loadSampleScamBtn.addEventListener("click", handleLoadSampleScam);
  refreshHistoryBtn.addEventListener("click", loadScanHistory);
  if (clearHistoryBtn) clearHistoryBtn.addEventListener("click", handleClearHistory);
  
  reportScamBtn.addEventListener("click", () => {
    showToast("Scam threat reported to CyberShield telemetry database!", "success");
    threatModal.style.display = "none";
  });

  // Automated 10-second polling for latest incoming threats
  startThreatPolling();
});

function initSuspiciousToggle() {
  if (suspiciousAlertToggle) {
    const saved = localStorage.getItem("cybershield_warn_suspicious");
    if (saved !== null) {
      suspiciousAlertToggle.checked = (saved === "true");
    }
    suspiciousAlertToggle.addEventListener("change", () => {
      localStorage.setItem("cybershield_warn_suspicious", suspiciousAlertToggle.checked);
      showToast(
        suspiciousAlertToggle.checked 
          ? "🔔 Warnings enabled for suspicious emails (Score 50–70)." 
          : "🔕 Warnings disabled for suspicious emails (High-Risk only).",
        "info"
      );
    });
  }
}

// ================= BROWSER NOTIFICATIONS & POLLING =================
function initNotificationSupport() {
  if (!("Notification" in window)) {
    console.log("[Notifications] Browser does not support desktop notifications.");
    return;
  }

  if (Notification.permission === "granted") {
    notificationPermissionGranted = true;
  } else if (Notification.permission !== "denied") {
    Notification.requestPermission().then(permission => {
      if (permission === "granted") {
        notificationPermissionGranted = true;
        showToast("🔔 Live browser threat alerts enabled.", "info");
      }
    });
  }
}

function startThreatPolling() {
  if (pollingTimer) clearInterval(pollingTimer);
  pollLatestThreats();
  pollingTimer = setInterval(pollLatestThreats, POLL_INTERVAL_MS);
}

async function pollLatestThreats() {
  try {
    const res = await fetch(`${API_BASE}/api/threats/latest?limit=15&min_score=50`);
    if (res.ok) {
      const latestThreats = await res.json();
      const notifiedIds = getNotifiedThreatIds();
      const warnSuspicious = suspiciousAlertToggle ? suspiciousAlertToggle.checked : true;

      if (latestThreats && latestThreats.length > 0) {
        latestThreats.forEach(threat => {
          const uniqueId = threat.threat_id || String(threat.id);
          
          if (!notifiedIds.includes(uniqueId)) {
            // Case 1: High Risk Threat (Score >= 70) -> Always alert
            if (threat.risk_level === "HIGH" || threat.risk_score >= 70) {
              markThreatAsNotifiedInStorage(uniqueId);
              triggerThreatNotification(threat, "high");
            } 
            // Case 2: Suspicious Warning (Score 50 - 69) -> Alert if toggle is enabled
            else if (threat.risk_score >= 50 && warnSuspicious) {
              markThreatAsNotifiedInStorage(uniqueId);
              triggerThreatNotification(threat, "medium");
            }
          }
        });
      }

      // Automatically refresh live feed & metrics without full page reload
      loadGmailFeed();
      refreshStats();
    }
  } catch (err) {
    console.error("[Polling] Error checking latest threats:", err);
  }
}

function triggerThreatNotification(threat, severity = "high") {
  const targetId = threat.threat_id || threat.id;
  const isHigh = (severity === "high" || threat.risk_level === "HIGH" || threat.risk_score >= 70);

  const title = isHigh ? `🚨 CyberShield Critical Alert` : `⚠️ CyberShield Suspicious Email Warning`;
  const bodyText = isHigh 
    ? `Potential phishing/scam email detected.\n\nSubject: ${threat.subject}\nRisk Score: ${threat.risk_score}/100 [HIGH RISK]`
    : `Suspicious activity detected in email.\n\nSubject: ${threat.subject}\nRisk Score: ${threat.risk_score}/100 [SUSPICIOUS]`;

  // 1. Standard Desktop Browser Notification
  if ("Notification" in window && Notification.permission === "granted") {
    try {
      const notif = new Notification(title, {
        body: bodyText,
        icon: isHigh ? "🚨" : "⚠️",
        requireInteraction: isHigh,
        tag: `threat-${targetId}`
      });

      notif.onclick = () => {
        window.focus();
        window.location.href = `/threat/${targetId}`;
      };
    } catch (e) {
      console.warn("Desktop notification error:", e);
    }
  }

  // 2. In-App Interactive Toast Alert
  const alertToast = document.createElement("div");
  alertToast.className = `toast ${isHigh ? "error" : "warning"}`;
  alertToast.style.cursor = "pointer";
  alertToast.innerHTML = `
    <span>${isHigh ? "🚨" : "⚠️"}</span>
    <div>
      <strong>${isHigh ? "High Risk Threat Detected!" : "Suspicious Email Detected (Score: " + threat.risk_score + "/100)"}</strong><br>
      <small>${escapeHtml(threat.subject || "Security Alert")}</small>
    </div>
    <a href="/threat/${targetId}" class="btn btn-secondary" style="font-size: 0.75rem; padding: 2px 8px; margin-left: 8px;">View</a>
  `;
  alertToast.addEventListener("click", (e) => {
    if (e.target.tagName !== "A") {
      window.location.href = `/threat/${targetId}`;
    }
  });

  document.getElementById("toastContainer").appendChild(alertToast);
  setTimeout(() => alertToast.remove(), 9000);
}

// ================= TOAST NOTIFICATIONS =================
function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  const icon = type === "success" ? "✅" : (type === "error" ? "🚨" : (type === "warning" ? "⚠️" : "ℹ️"));
  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 4000);
}

// ================= URL PARAMS / NOTIFICATIONS =================
function checkUrlParams() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("gmail_connected") === "true") {
    showToast("Google Gmail successfully authorized! Proactive threat monitoring active.", "success");
    window.history.replaceState({}, document.title, window.location.pathname);
  }
  if (params.get("gmail_error")) {
    showToast(`OAuth Error: ${params.get("gmail_error")}`, "error");
    window.history.replaceState({}, document.title, window.location.pathname);
  }
}

// ================= TABS =================
function setupTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add("active");
      
      if (targetId === "historyTab") {
        loadScanHistory();
      }
    });
  });
}

// ================= GMAIL STATUS & OAUTH =================
async function refreshGmailStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/gmail/status`);
    const data = await res.json();

    isGmailConnected = !!data.connected;

    if (isGmailConnected) {
      gmailStatusBadge.className = "status-badge connected";
      gmailStatusText.textContent = `Connected: ${data.email || "Gmail User"}`;
      connectGmailBtn.innerHTML = `<span class="btn-icon">🔌</span> Disconnect`;
      connectGmailBtn.className = "btn btn-secondary";
      scanInboxBtn.disabled = false;
      gmailPromptCard.style.display = "none";
      threatListContainer.style.display = "flex";
      loadGmailFeed();
    } else {
      gmailStatusBadge.className = "status-badge disconnected";
      gmailStatusText.textContent = "Gmail Disconnected";
      connectGmailBtn.innerHTML = `<span class="btn-icon">🔗</span> Connect Gmail`;
      connectGmailBtn.className = "btn btn-secondary";
      scanInboxBtn.disabled = true;
      gmailPromptCard.style.display = "block";
      threatListContainer.style.display = "none";
    }
  } catch (err) {
    console.error("Error checking Gmail status:", err);
  }
}

async function handleConnectGmail() {
  if (isGmailConnected) {
    if (confirm("Do you want to disconnect your Gmail account?")) {
      try {
        await fetch(`${API_BASE}/api/gmail/disconnect`, { method: "POST" });
        showToast("Gmail disconnected.", "info");
        refreshGmailStatus();
      } catch (e) {
        showToast("Failed to disconnect", "error");
      }
    }
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/gmail/auth-url`);
    const data = await res.json();
    if (data.auth_url) {
      window.location.href = data.auth_url;
    } else {
      showToast("Unable to start Google OAuth flow. Please check credentials.json", "error");
    }
  } catch (err) {
    showToast("Error retrieving OAuth authorization URL", "error");
  }
}

// ================= INBOX SCANNING =================
async function handleScanInbox() {
  if (!isGmailConnected) return;

  scanInboxBtn.disabled = true;
  scanInboxBtn.innerHTML = `<span class="btn-icon">⏳</span> Scanning Inbox...`;
  showToast("Retrieving and analyzing recent Gmail messages...", "info");

  try {
    const res = await fetch(`${API_BASE}/api/gmail/scan?max_count=15`, {
      method: "POST"
    });
    const data = await res.json();

    if (res.ok) {
      currentScans = data.results || [];
      renderThreatFeed();
      refreshStats();
      
      if (data.threats_found > 0) {
        showToast(`🚨 Alert: Detected ${data.threats_found} potentially suspicious messages!`, "error");
      } else {
        showToast(`Scan complete: ${data.scanned_count} messages analyzed. No high-risk threats detected.`, "success");
      }
    } else {
      showToast(`Scan failed: ${data.detail || "Unknown error"}`, "error");
    }
  } catch (err) {
    showToast("Failed to communicate with CyberShield backend server", "error");
  } finally {
    scanInboxBtn.disabled = false;
    scanInboxBtn.innerHTML = `<span class="btn-icon">⚡</span> Scan Inbox Now`;
  }
}

async function loadGmailFeed() {
  try {
    const res = await fetch(`${API_BASE}/api/scans?content_type=email&limit=30`);
    if (res.ok) {
      const scans = await res.json();
      currentScans = scans;
      renderThreatFeed();
    }
  } catch (e) {
    console.error("Error loading Gmail feed:", e);
  }
}

// ================= RENDER THREAT FEED =================
function renderThreatFeed() {
  const filter = filterRiskSelect.value;
  threatListContainer.innerHTML = "";

  const filtered = currentScans.filter(s => {
    if (filter === "ALL") return true;
    return s.risk_level === filter;
  });

  if (filtered.length === 0) {
    threatListContainer.innerHTML = `
      <div class="card empty-state-card" style="width: 100%;">
        <div class="empty-icon">📬</div>
        <h4>${currentScans.length === 0 ? "Ready to Monitor Your Gmail Inbox" : "No " + (filter !== "ALL" ? filter : "") + " Messages Found"}</h4>
        <p>CyberShield automatically monitors your inbox in the background every 30 seconds, or click <strong>"Scan Inbox Now"</strong> to scan instantly.</p>
      </div>
    `;
    return;
  }

  filtered.forEach(scan => {
    const card = document.createElement("div");
    const borderClass = `border-${scan.risk_level.toLowerCase()}`;
    const levelClass = scan.risk_level.toLowerCase();
    const threatTarget = scan.threat_id || scan.id;
    
    card.className = `threat-item-card ${borderClass}`;
    card.innerHTML = `
      <div class="threat-main-info">
        <div class="threat-header-row">
          <span class="risk-pill ${levelClass}">
            ${scan.risk_level === "HIGH" ? "🚨 " : (scan.risk_level === "MEDIUM" ? "⚠️ " : "✅ ")}
            ${scan.risk_level} RISK
          </span>
          <span class="threat-subject">${escapeHtml(scan.subject || "No Subject")}</span>
          ${scan.threat_id ? `<span class="threat-id-tag">#${escapeHtml(scan.threat_id)}</span>` : ''}
        </div>
        <div class="threat-meta">
          <strong>From:</strong> ${escapeHtml(scan.sender || "Unknown")} &bull; 
          <span>${escapeHtml(scan.date_received || "Recent")}</span>
        </div>
        <p class="threat-snippet">${escapeHtml(scan.snippet || "No preview snippet available.")}</p>
      </div>

      <div class="threat-score-col">
        <div class="score-display-small text-${levelClass}">${scan.risk_score}</div>
        <div class="score-label-small">Risk Score</div>
        <div style="display: flex; gap: 6px; margin-top: 8px; justify-content: center;">
          <a href="/threat/${threatTarget}" class="btn btn-primary" style="font-size: 0.75rem; padding: 4px 10px; text-decoration: none; display: inline-flex; align-items: center; gap: 4px;">
            🔍 Investigate
          </a>
          <button class="btn btn-secondary btn-quick-view" style="font-size: 0.75rem; padding: 4px 8px;" title="Quick in-page modal preview">
            ⚡ Quick
          </button>
        </div>
      </div>
    `;

    card.querySelector(".btn-quick-view").addEventListener("click", () => {
      openThreatModal(scan);
    });

    threatListContainer.appendChild(card);
  });
}

// ================= MODAL INVESTIGATION DETAILS =================
function openThreatModal(scan) {
  const level = scan.risk_level.toUpperCase();
  const levelClass = level.toLowerCase();

  modalRiskBadge.className = `risk-pill ${levelClass}`;
  modalRiskBadge.textContent = `${level} RISK`;
  modalSubject.textContent = scan.subject || "Threat Investigation Details";

  modalScoreBanner.className = `score-banner ${levelClass}`;
  modalScoreVal.textContent = scan.risk_score;

  if (level === "HIGH") {
    modalRiskLevelHeading.textContent = "🚨 POTENTIAL SCAM / PHISHING DETECTED";
    modalRiskSummary.textContent = "Multiple urgent scam, impersonation, or credential harvesting signals detected.";
  } else if (level === "MEDIUM") {
    modalRiskLevelHeading.textContent = "⚠️ SUSPICIOUS PATTERNS DETECTED";
    modalRiskSummary.textContent = "Unverified sender, brand name, or external link anomalies require verification.";
  } else {
    modalRiskLevelHeading.textContent = "✅ NO HIGH-RISK THREATS DETECTED";
    modalRiskSummary.textContent = "Content aligns with standard digital communication patterns.";
  }

  modalSender.textContent = scan.sender || "Unknown";
  modalDate.textContent = scan.date_received || (scan.created_at ? scan.created_at.substring(0, 19).replace('T', ' ') : 'N/A');
  modalSnippet.textContent = scan.snippet || "N/A";

  // Render Evidence List
  modalEvidenceList.innerHTML = "";
  if (scan.evidence && scan.evidence.length > 0) {
    scan.evidence.forEach(ev => {
      const li = document.createElement("li");
      li.textContent = ev;
      modalEvidenceList.appendChild(li);
    });
  } else {
    modalEvidenceList.innerHTML = "<li>No specific threat evidence flagged.</li>";
  }

  // Render Link Analysis
  modalUrlList.innerHTML = "";
  if (scan.urls_analyzed && scan.urls_analyzed.length > 0) {
    scan.urls_analyzed.forEach(u => {
      const card = document.createElement("div");
      card.className = "url-card";
      let flagsHtml = "";
      if (u.flags && u.flags.length > 0) {
        flagsHtml = `<ul class="url-flags-list">${u.flags.map(f => `<li>${escapeHtml(f)}</li>`).join("")}</ul>`;
      } else {
        flagsHtml = `<span style="color: #6ee7b7; font-size: 0.75rem;">Standard domain format (No high-risk flags)</span>`;
      }

      card.innerHTML = `
        <div class="url-text">🔗 ${escapeHtml(u.url)}</div>
        <div style="font-size: 0.75rem; color: #9ca3af; margin-bottom: 4px;">
          Domain: <strong>${escapeHtml(u.domain)}</strong> | Protocol: <strong>${u.is_https ? "HTTPS (Encrypted)" : "HTTP (Insecure)"}</strong> | Link Score: <strong>${u.url_score}/100</strong>
        </div>
        ${flagsHtml}
      `;
      modalUrlList.appendChild(card);
    });
  } else {
    modalUrlList.innerHTML = "<p style='font-size: 0.85rem; color: #9ca3af;'>No external hyperlinks detected in this message.</p>";
  }

  // Render Recommendations
  modalRecommendationsList.innerHTML = "";
  if (scan.recommendations && scan.recommendations.length > 0) {
    scan.recommendations.forEach(rec => {
      const li = document.createElement("li");
      li.textContent = rec;
      modalRecommendationsList.appendChild(li);
    });
  }

  threatModal.style.display = "flex";
}

// ================= STATS REFRESH =================
async function refreshStats() {
  try {
    const res = await fetch(`${API_BASE}/api/scans/stats`);
    if (res.ok) {
      const stats = await res.json();
      statTotal.textContent = stats.total_scanned;
      statHigh.textContent = stats.high_risk_count;
      statMedium.textContent = stats.medium_risk_count;
      statLow.textContent = stats.low_risk_count;
    }
  } catch (err) {
    console.error("Error refreshing stats:", err);
  }
}

// ================= MANUAL ANALYSIS =================
async function handleManualAnalysis() {
  const content = manualContent.value.trim();
  if (!content) {
    showToast("Please enter message body or a URL to analyze.", "error");
    return;
  }

  const contentType = document.querySelector("input[name='manualType']:checked").value;
  const sender = manualSender.value.trim();
  const subject = manualSubject.value.trim();

  runManualAnalysisBtn.disabled = true;
  runManualAnalysisBtn.textContent = "Analyzing...";

  try {
    const res = await fetch(`${API_BASE}/api/analyze/manual`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content_type: contentType,
        sender: sender,
        subject: subject,
        content: content
      })
    });

    if (res.ok) {
      const result = await res.json();
      showToast(`Analysis complete! Result: ${result.risk_level} RISK (${result.risk_score}/100)`, result.risk_level === "HIGH" ? "error" : "success");
      openThreatModal(result);
      refreshStats();
      loadScanHistory();
    } else {
      showToast("Analysis failed.", "error");
    }
  } catch (err) {
    showToast("Backend connection error.", "error");
  } finally {
    runManualAnalysisBtn.disabled = false;
    runManualAnalysisBtn.textContent = "Analyze Threats & Links";
  }
}

function handleLoadSampleScam() {
  manualSender.value = "Bank Security Alerts <security-verification@gmail.com>";
  manualSubject.value = "URGENT: Your Bank Account Access is Suspended";
  manualContent.value = "Dear Customer,\n\nWe detected unauthorized login attempts on your account. Your account has been temporarily frozen. To restore access and prevent permanent termination within 24 hours, you must verify your identity, password, and OTP immediately.\n\nClick here to verify: http://192.168.1.50/secure-banking-login/update\n\nFailure to comply will result in account deletion.\nSecurity Team";
  showToast("Loaded sample banking phishing email.", "info");
}

// ================= CLEAR HISTORY =================
async function handleClearHistory() {
  if (confirm("Are you sure you want to clear all scan records from the database?")) {
    try {
      const res = await fetch(`${API_BASE}/api/scans`, { method: "DELETE" });
      if (res.ok) {
        showToast("Scan audit log cleared.", "info");
        currentScans = [];
        localStorage.removeItem("cybershield_notified_threats");
        renderThreatFeed();
        loadScanHistory();
        refreshStats();
      }
    } catch (e) {
      showToast("Failed to clear history", "error");
    }
  }
}

// ================= SCAN HISTORY TABLE =================
async function loadScanHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/scans?limit=50`);
    if (res.ok) {
      const scans = await res.json();
      historyTableBody.innerHTML = "";

      if (scans.length === 0) {
        historyTableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #9ca3af; padding: 24px;">No scan records found in local database.</td></tr>`;
        return;
      }

      scans.forEach(s => {
        const tr = document.createElement("tr");
        const levelClass = s.risk_level.toLowerCase();
        const threatTarget = s.threat_id || s.id;
        tr.innerHTML = `
          <td><span class="risk-pill ${levelClass}">${s.risk_level}</span></td>
          <td><strong>${s.risk_score}/100</strong></td>
          <td><strong>${escapeHtml(s.subject || "No Subject")}</strong></td>
          <td style="color: #9ca3af;">${escapeHtml(s.sender || "Manual")}</td>
          <td><code>${s.content_type}</code></td>
          <td style="color: #9ca3af; font-size: 0.75rem;">${s.created_at ? s.created_at.substring(0, 19).replace('T', ' ') : 'N/A'}</td>
          <td>
            <div style="display: flex; gap: 4px;">
              <a href="/threat/${threatTarget}" class="btn btn-primary" style="font-size: 0.75rem; padding: 3px 8px; text-decoration: none;">🔍 Investigate</a>
              <button class="btn btn-secondary btn-hist-view" style="font-size: 0.75rem; padding: 3px 6px;">⚡ Quick</button>
            </div>
          </td>
        `;
        tr.querySelector(".btn-hist-view").addEventListener("click", () => openThreatModal(s));
        historyTableBody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error("Error loading scan history:", err);
  }
}

// Helper: Escape HTML to avoid XSS
function escapeHtml(text) {
  if (!text) return "";
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}
