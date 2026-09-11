/**
 * PhishGuard Enterprise Cybersecurity Platform
 * Frontend Controller (SPA)
 * 
 * Features:
 * - Real-time passive URL scanning with 0-100 risk scoring and component breakdown
 * - Explainable factor checklist (Pass / Fail / Warn)
 * - Email / SMS / Social media NLP message analysis
 * - Persistent scan history in SQLite with live search, status filtering, export, and deletion
 * - Interactive Chart.js threat distribution analytics
 * - Configurable hybrid engine weights (Rules / ML / Intel)
 * - False-positive / false-negative feedback reporting
 */

// Global State & Chart Instances
let riskChartInstance = null;
let statsChartInstance = null;
let lastUrlScanResult = null;
let searchDebounceTimeout = null;
let currentFilter = "";
let currentChecklistItems = [];
let currentChecklistFilter = "ALL";

document.addEventListener("DOMContentLoaded", () => {
  initShapeGridBackground();
  initNavigation();
  initDashboard();
  initUrlScanner();
  initMessageScanner();
  initHistory();
  initStatistics();
  initSettings();
  initFeedbackModal();
});

/* =========================================================================
   1. NAVIGATION & VIEW SWITCHING
   ========================================================================= */

const VIEW_TITLES = {
  "dashboard-view": {
    title: "Security Dashboard",
    subtitle: "Real-time threat monitoring, risk distribution, and attack prevention."
  },
  "url-scanner-view": {
    title: "Advanced URL Threat Scanner",
    subtitle: "Multi-factor passive inspection evaluating lexical tokens, brand spoofing, and TLD reputation."
  },
  "msg-scanner-view": {
    title: "Email & Text Threat Scanner",
    subtitle: "Psychological urgency analysis, credential trap detection, and embedded link inspection."
  },
  "history-view": {
    title: "Persistent Scan History",
    subtitle: "Search, filter, inspect, and export all historical security evaluations stored in SQLite."
  },
  "statistics-view": {
    title: "Security Statistics & Benchmarks",
    subtitle: "Empirical threat metrics, classification ratios, and zero-day model validation."
  },
  "settings-view": {
    title: "Detection Engine Configuration",
    subtitle: "Fine-tune hybrid weights balancing heuristic rules, machine learning inference, and threat intelligence."
  },
  "about-view": {
    title: "About PhishGuard",
    subtitle: "Defense-in-depth cybersecurity platform for academic research and enterprise defense."
  }
};

function initNavigation() {
  const navButtons = document.querySelectorAll(".sidebar-nav .nav-item");
  navButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const viewId = btn.getAttribute("data-view");
      switchView(viewId);
    });
  });

  // Quick scan button in header
  const btnQuickScan = document.getElementById("btn-header-quickscan");
  if (btnQuickScan) {
    btnQuickScan.addEventListener("click", () => {
      switchView("url-scanner-view");
      const input = document.getElementById("target-url-input");
      if (input) input.focus();
    });
  }

  // "View All History" from dashboard
  const btnViewAllHistory = document.getElementById("btn-view-all-history");
  if (btnViewAllHistory) {
    btnViewAllHistory.addEventListener("click", () => {
      switchView("history-view");
    });
  }

  // "Scan Another URL" button
  const btnScanAnother = document.getElementById("btn-scan-another-url");
  if (btnScanAnother) {
    btnScanAnother.addEventListener("click", () => {
      const input = document.getElementById("target-url-input");
      if (input) {
        input.value = "";
        input.focus();
      }
      const placeholder = document.getElementById("url-result-placeholder");
      const resultCard = document.getElementById("url-result-card");
      if (placeholder) placeholder.classList.remove("hidden");
      if (resultCard) resultCard.classList.add("hidden");
    });
  }
}

function switchView(viewId) {
  // Update sidebar active button
  document.querySelectorAll(".sidebar-nav .nav-item").forEach(btn => {
    if (btn.getAttribute("data-view") === viewId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  // Update visible panel
  document.querySelectorAll(".view-panel").forEach(panel => {
    if (panel.id === viewId) {
      panel.classList.add("active");
    } else {
      panel.classList.remove("active");
    }
  });

  // Update header title & subtitle
  const pageTitle = document.getElementById("page-title");
  const pageSubtitle = document.getElementById("page-subtitle");
  if (VIEW_TITLES[viewId]) {
    if (pageTitle) pageTitle.textContent = VIEW_TITLES[viewId].title;
    if (pageSubtitle) pageSubtitle.textContent = VIEW_TITLES[viewId].subtitle;
  }

  // Refresh view-specific data
  if (viewId === "dashboard-view") {
    loadDashboardStats();
  } else if (viewId === "history-view") {
    loadHistory();
  } else if (viewId === "statistics-view") {
    loadStatisticsView();
  } else if (viewId === "settings-view") {
    loadSettings();
  }
}

/* =========================================================================
   2. DASHBOARD CONTROLLER
   ========================================================================= */

function initDashboard() {
  loadDashboardStats();
}

async function loadDashboardStats() {
  try {
    const res = await fetch("/api/statistics");
    if (!res.ok) return;
    const stats = await res.json();

    const total = stats.total_scans || 0;
    const safe = stats.safe_count || 0;
    const suspicious = stats.suspicious_count || 0;
    const phishing = stats.phishing_count || 0;

    // Update stat numbers
    const totalEl = document.getElementById("dash-total-scans");
    const safeEl = document.getElementById("dash-safe-count");
    const suspEl = document.getElementById("dash-suspicious-count");
    const phishEl = document.getElementById("dash-phishing-count");

    if (totalEl) totalEl.textContent = total.toLocaleString();
    if (safeEl) safeEl.textContent = safe.toLocaleString();
    if (suspEl) suspEl.textContent = suspicious.toLocaleString();
    if (phishEl) phishEl.textContent = phishing.toLocaleString();

    // Percentages
    const safePct = total > 0 ? Math.round((safe / total) * 100) : 0;
    const suspPct = total > 0 ? Math.round((suspicious / total) * 100) : 0;
    const phishPct = total > 0 ? Math.round((phishing / total) * 100) : 0;

    const safePctEl = document.getElementById("dash-safe-pct");
    const suspPctEl = document.getElementById("dash-suspicious-pct");
    const phishPctEl = document.getElementById("dash-phishing-pct");

    if (safePctEl) safePctEl.textContent = `${safePct}% of total`;
    if (suspPctEl) suspPctEl.textContent = `${suspPct}% of total`;
    if (phishPctEl) phishPctEl.textContent = `${phishPct}% of total`;

    // Render / update chart
    renderDashboardChart(safe, suspicious, phishing);

    // Load recent scans
    loadRecentScansTable();
  } catch (err) {
    console.error("Failed to load dashboard statistics:", err);
  }
}

function renderDashboardChart(safe, suspicious, phishing) {
  const canvas = document.getElementById("riskDistributionChart");
  if (!canvas) return;

  if (riskChartInstance) {
    riskChartInstance.destroy();
  }

  const ctx = canvas.getContext("2d");
  riskChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Safe (0-30)", "Suspicious (31-60)", "Phishing (61-100)"],
      datasets: [{
        data: [safe, suspicious, phishing],
        backgroundColor: [
          "#10b981", // Emerald Green
          "#f59e0b", // Amber
          "#ef4444"  // Red
        ],
        borderColor: "#182234",
        borderWidth: 3,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#94a3b8",
            font: { family: "'Plus Jakarta Sans', sans-serif", size: 12 },
            padding: 18
          }
        },
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.95)",
          titleColor: "#f8fafc",
          bodyColor: "#cbd5e1",
          borderColor: "#334155",
          borderWidth: 1,
          padding: 12,
          boxPadding: 6
        }
      },
      cutout: "70%"
    }
  });
}

async function loadRecentScansTable() {
  const tbody = document.getElementById("recent-scans-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/history?limit=5");
    if (!res.ok) throw new Error("History fetch error");
    const data = await res.json();
    const scans = data.scans || [];

    if (scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No scans recorded yet. Enter a URL above to perform a scan!</td></tr>`;
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const statusBadge = getStatusBadge(s.status);
      const scoreBadge = getScoreBadge(s.risk_score);
      const dateFormatted = formatTimestamp(s.timestamp);
      const targetShort = escapeHtml(truncateText(s.target, 55));
      const scanType = s.scan_type === "url" ? `<span class="type-tag url-tag">URL</span>` : `<span class="type-tag msg-tag">MSG</span>`;

      return `
        <tr>
          <td>${scanType}</td>
          <td class="font-mono text-break" title="${escapeHtml(s.target)}">${targetShort}</td>
          <td>${statusBadge}</td>
          <td>${scoreBadge}</td>
          <td class="text-muted text-sm">${dateFormatted}</td>
          <td>
            <button class="btn-table-action" onclick="quickInspectScan(${s.id})">Inspect</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to load recent scans:", err);
    tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-danger">Failed to load recent scans.</td></tr>`;
  }
}

/* =========================================================================
   3. URL SCANNER CONTROLLER
   ========================================================================= */

function initUrlScanner() {
  loadPresets();

  const form = document.getElementById("url-scan-form");
  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      runUrlScan();
    });
  }

  // Copy report
  const btnCopy = document.getElementById("btn-copy-url-result");
  if (btnCopy) {
    btnCopy.addEventListener("click", copyUrlReport);
  }

  // Report false positive
  const btnReport = document.getElementById("btn-report-false-positive");
  if (btnReport) {
    btnReport.addEventListener("click", () => {
      if (lastUrlScanResult) {
        openFeedbackModal(lastUrlScanResult.url);
      }
    });
  }

  // Bind Checklist Criteria Filter Buttons
  const filterBtns = document.querySelectorAll("#url-checklist-filters .chk-filter");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentChecklistFilter = btn.getAttribute("data-filter") || "ALL";
      renderChecklist(currentChecklistItems, currentChecklistFilter);
    });
  });
}

async function loadPresets() {
  const select = document.getElementById("url-preset-select");
  if (!select) return;

  try {
    const res = await fetch("/api/presets");
    if (!res.ok) return;
    const presets = await res.json();

    presets.forEach((p, idx) => {
      const opt = document.createElement("option");
      opt.value = idx;
      opt.textContent = `[${p.category}] ${p.name}`;
      opt.dataset.url = p.url;
      opt.dataset.html = p.simulated_html || "";
      select.appendChild(opt);
    });

    select.addEventListener("change", () => {
      const opt = select.options[select.selectedIndex];
      if (opt && opt.dataset.url) {
        const urlInput = document.getElementById("target-url-input");
        const htmlInput = document.getElementById("custom-html-input");
        if (urlInput) urlInput.value = opt.dataset.url;
        if (htmlInput) htmlInput.value = opt.dataset.html || "";
        runUrlScan();
      }
    });
  } catch (err) {
    console.warn("Presets could not be loaded:", err);
  }
}

async function runUrlScan() {
  const urlInput = document.getElementById("target-url-input");
  const htmlInput = document.getElementById("custom-html-input");
  const btnSubmit = document.getElementById("btn-submit-url");
  const btnText = document.getElementById("url-btn-text");
  const btnSpinner = document.getElementById("url-btn-spinner");

  const url = urlInput.value.trim();
  if (!url) {
    showToast("Please enter a valid URL to analyze", "warning");
    return;
  }

  // UI Loading State
  if (btnText) btnText.textContent = "Analyzing Threat...";
  if (btnSpinner) btnSpinner.classList.remove("hidden");
  if (btnSubmit) btnSubmit.disabled = true;

  try {
    const res = await fetch("/api/scan-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: url,
        html_content: htmlInput ? (htmlInput.value.trim() || null) : null
      })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "URL scan failed");
    }

    const data = await res.json();
    lastUrlScanResult = data;
    renderUrlResult(data);
    showToast(`Scan complete: ${data.status} (Score: ${data.risk_score}/100)`, getToastType(data.status));
  } catch (err) {
    console.error("URL scan failed:", err);
    showToast(err.message || "Failed to scan URL. Please verify server connection.", "error");
  } finally {
    if (btnText) btnText.textContent = "Scan URL";
    if (btnSpinner) btnSpinner.classList.add("hidden");
    if (btnSubmit) btnSubmit.disabled = false;
  }
}

function renderUrlResult(data) {
  const placeholder = document.getElementById("url-result-placeholder");
  const card = document.getElementById("url-result-card");
  if (placeholder) placeholder.classList.add("hidden");
  if (card) card.classList.remove("hidden");

  // Banner & Status
  const banner = document.getElementById("url-verdict-banner");
  const badge = document.getElementById("url-verdict-badge");
  const target = document.getElementById("url-result-target");
  const meta = document.getElementById("url-result-meta");
  const riskVal = document.getElementById("url-risk-val");

  const status = data.status || "SAFE";
  if (banner) {
    banner.className = "verdict-banner " + (
      status === "SAFE" ? "safe-banner" :
      status === "SUSPICIOUS" ? "suspicious-banner" : "phishing-banner"
    );
  }

  if (badge) {
    badge.textContent = status === "PHISHING" ? "HIGH RISK / PHISHING" : status;
    badge.className = "verdict-badge " + (
      status === "SAFE" ? "badge-safe" :
      status === "SUSPICIOUS" ? "badge-suspicious" : "badge-phishing"
    );
  }

  // API returns 'target' field, not 'url'
  const scannedUrl = data.target || data.url || "";
  if (target) target.textContent = scannedUrl;
  if (meta) {
    const conf = Math.round((data.confidence || 0.95) * 100);
    const latency = data.latency_ms || data.analysis_latency_ms || 12;
    meta.textContent = `Confidence: ${conf}% | Latency: ${latency}ms | Model: Hybrid Fusion Engine`;
  }
  if (riskVal) riskVal.textContent = data.risk_score;

  // Component Scores (fallback safely to nested or top-level scores)
  const rulesVal = document.getElementById("comp-rules-val");
  const mlVal = document.getElementById("comp-ml-val");
  const intelVal = document.getElementById("comp-intel-val");

  const rScore = Math.round(data.rule_score ?? (data.components ? data.components.rule_score : 0) ?? 0);
  const mScore = Math.round(data.ml_score ?? (data.components ? data.components.ml_score : 0) ?? 0);
  const iScore = Math.round(data.threat_intel_score ?? (data.components ? data.components.threat_intel_score : 0) ?? 0);

  if (rulesVal) rulesVal.textContent = `${rScore} / 100`;
  if (mlVal) mlVal.textContent = `${mScore} / 100`;
  if (intelVal) intelVal.textContent = `${iScore} / 100`;

  // Recommendation
  const recBody = document.getElementById("url-rec-body");
  const recTitle = document.getElementById("url-rec-title");
  if (recTitle) {
    recTitle.textContent = status === "SAFE" ? "Safety Recommendation:" : "Defensive Security Action:";
  }
  if (recBody) {
    recBody.textContent = data.recommendation || "Maintain standard cybersecurity hygiene.";
  }

  // Populate Threat Anatomy (What is Phished in this URL?)
  const anatDiagBanner = document.getElementById("url-diagnosis-banner");
  const anatDiagIcon = document.getElementById("url-diag-icon");
  const anatDiagTitle = document.getElementById("url-diag-title");
  const anatDiagText = document.getElementById("url-diag-text");

  const anatBrand = document.getElementById("anat-brand");
  const anatDomain = document.getElementById("anat-domain");
  const anatSubdomain = document.getElementById("anat-subdomain");
  const anatProtocol = document.getElementById("anat-protocol");
  const anatTld = document.getElementById("anat-tld");
  const anatIp = document.getElementById("anat-ip");

  const b = data.url_breakdown || {};
  const metrics = data.metrics || {};
  const tIntel = data.threat_intel || {};

  const brandSpoofed = (b.spoofed_brand && b.spoofed_brand !== "None Detected") 
    ? b.spoofed_brand 
    : (tIntel.spoofed_brand ? tIntel.spoofed_brand.toUpperCase() : "None Detected");
  const trueDomain = b.domain || metrics.domain || "Unknown";
  const subDomain = b.subdomain || "None (Apex Domain)";
  const proto = b.protocol || (metrics.is_https ? "HTTPS (Encrypted TLS)" : "HTTP (Unencrypted / Insecure)");
  const tldVal = b.tld || ("." + (metrics.tld || ""));
  const isIp = b.is_raw_ip || metrics.is_raw_ip;

  if (anatBrand) {
    if (brandSpoofed !== "None Detected") {
      anatBrand.innerHTML = `<span class="badge badge.phishing text-red">🚨 SPOOFED: ${escapeHtml(brandSpoofed)}</span>`;
    } else if (tIntel.is_trusted) {
      anatBrand.innerHTML = `<span class="text-green font-bold">✓ Verified Authentic Authority</span>`;
    } else {
      anatBrand.innerHTML = `<span class="text-muted">Standard / Unbranded</span>`;
    }
  }

  if (anatDomain) {
    anatDomain.innerHTML = escapeHtml(trueDomain) + (tIntel.is_trusted ? ` <span class="text-green text-sm">(Official Domain)</span>` : ` <span class="text-amber text-sm">(Unranked Third-Party)</span>`);
  }

  if (anatSubdomain) {
    if (subDomain !== "None (Apex Domain)" && (subDomain.toLowerCase().includes("chase") || subDomain.toLowerCase().includes("paypal") || subDomain.toLowerCase().includes("login") || subDomain.toLowerCase().includes("verify") || subDomain.toLowerCase().includes("auth") || subDomain.split(".").length > 2)) {
      anatSubdomain.innerHTML = `<span class="text-red font-mono">${escapeHtml(subDomain)}</span> <span class="badge badge.phishing text-sm">⚠️ CLOAKING</span>`;
    } else {
      anatSubdomain.textContent = subDomain;
    }
  }

  if (anatProtocol) {
    if (proto.includes("HTTPS")) {
      anatProtocol.innerHTML = `<span class="text-green">🔒 ${escapeHtml(proto)}</span>`;
    } else {
      anatProtocol.innerHTML = `<span class="text-red font-bold">⚠️ ${escapeHtml(proto)}</span>`;
    }
  }

  if (anatTld) {
    if (tIntel.is_high_risk_tld || b.is_high_risk_tld) {
      anatTld.innerHTML = `<span class="text-red font-bold">${escapeHtml(tldVal)}</span> <span class="badge badge.phishing text-sm">HIGH-ABUSE TLD</span>`;
    } else {
      anatTld.innerHTML = `<span class="text-green">${escapeHtml(tldVal)}</span> <span class="text-muted text-sm">(Standard)</span>`;
    }
  }

  if (anatIp) {
    anatIp.innerHTML = isIp 
      ? `<span class="text-red font-bold">⚠️ Direct Numeric IP (${escapeHtml(metrics.hostname || "Bypass")})</span>` 
      : `<span class="text-green">Standard DNS Host</span>`;
  }

  // Threat Diagnosis Banner
  if (anatDiagBanner) {
    anatDiagBanner.className = "threat-diagnosis-banner " + (
      status === "SAFE" ? "safe" : (status === "SUSPICIOUS" ? "suspicious" : "phishing")
    );
  }
  if (anatDiagIcon) {
    anatDiagIcon.textContent = status === "SAFE" ? "🛡️" : (status === "SUSPICIOUS" ? "⚠️" : "🚨");
  }
  if (anatDiagTitle) {
    anatDiagTitle.textContent = status === "SAFE" 
      ? "Legitimate Infrastructure Verified:" 
      : (status === "SUSPICIOUS" ? "Potential Threat / Anomaly Detected:" : "High-Confidence Phishing Attack Identified:");
  }
  if (anatDiagText) {
    // Strip any garbled emoji prefix bytes if present, use clean text
    let diagText = b.threat_diagnosis || (data.reasons ? data.reasons.join(" ") : "Evaluated multi-signal threat criteria.");
    // Remove garbled bytes at start if any
    diagText = diagText.replace(/^[^A-Za-z\u2600-\u26FF\u{1F000}-\u{1FFFF}🛡⚠🚨✅]*/u, "").trim();
    anatDiagText.textContent = diagText;
  }

  // Render Visual URL Anatomy Bar (highlight suspicious segments)
  renderUrlAnatomyBar(scannedUrl, data);

  // Render Matched Keywords as Badges
  renderMatchedKeywords(data);

  // Populate Checklist Counters & Items
  currentChecklistItems = data.checklist || [];
  const allCnt = currentChecklistItems.length;
  const failCnt = currentChecklistItems.filter(i => i.status === "FAIL").length;
  const warnCnt = currentChecklistItems.filter(i => i.status === "WARN").length;
  const passCnt = currentChecklistItems.filter(i => i.status === "PASS").length;

  const cntAllEl = document.getElementById("cnt-all");
  const cntFailEl = document.getElementById("cnt-fail");
  const cntWarnEl = document.getElementById("cnt-warn");
  const cntPassEl = document.getElementById("cnt-pass");

  if (cntAllEl) cntAllEl.textContent = allCnt;
  if (cntFailEl) cntFailEl.textContent = failCnt;
  if (cntWarnEl) cntWarnEl.textContent = warnCnt;
  if (cntPassEl) cntPassEl.textContent = passCnt;

  // Render checklist with current filter
  renderChecklist(currentChecklistItems, currentChecklistFilter);

  // Scroll to result smoothly
  card.scrollIntoView({ behavior: "smooth", block: "start" });
}

/**
 * Renders a visual color-coded URL anatomy bar that highlights suspicious segments.
 */
function renderUrlAnatomyBar(rawUrl, data) {
  const container = document.getElementById("url-visual-anatomy");
  if (!container || !rawUrl) return;

  const b = data.url_breakdown || {};
  const metrics = data.metrics || {};
  const tIntel = data.threat_intel || {};
  const status = data.status || "SAFE";

  // Determine threat classifications for each segment
  const isHttps = rawUrl.startsWith("https://");
  const proto = isHttps ? "https://" : (rawUrl.startsWith("http://") ? "http://" : "");
  const rest = rawUrl.slice(proto.length);
  const slashIdx = rest.indexOf("/");
  const hostPart = slashIdx >= 0 ? rest.slice(0, slashIdx) : rest;
  const pathPart = slashIdx >= 0 ? rest.slice(slashIdx) : "";

  // Score each part
  const protoClass = isHttps ? "anat-safe" : "anat-danger";
  const protoTip = isHttps ? "✅ HTTPS — Encrypted" : "❌ HTTP — No Encryption (Credential Risk)";

  const hostClass = (tIntel.spoofed_brand || b.is_raw_ip) ? "anat-danger" :
                    tIntel.is_high_risk_tld ? "anat-warning" :
                    tIntel.is_trusted ? "anat-safe" : "anat-neutral";
  const hostTip = tIntel.spoofed_brand ? `❌ Spoofed Brand: ${tIntel.spoofed_brand.toUpperCase()} — Fake Domain!` :
                  b.is_raw_ip ? "❌ Raw IP — No DNS" :
                  tIntel.is_high_risk_tld ? `⚠️ High-Abuse TLD — Common in Phishing` :
                  tIntel.is_trusted ? "✅ Trusted Domain" : "ℹ️ Unverified Domain";

  const pathClass = (metrics.matched_keywords && metrics.matched_keywords.length > 0 && !tIntel.is_trusted)
    ? "anat-warning" : "anat-neutral";
  const pathTip = (metrics.matched_keywords && metrics.matched_keywords.length > 0 && !tIntel.is_trusted)
    ? `⚠️ Suspicious Keywords: ${metrics.matched_keywords.slice(0, 3).join(", ")}` : "ℹ️ URL Path";

  container.innerHTML = `
    <div class="url-bar-title">URL Anatomy Breakdown</div>
    <div class="url-bar-wrap">
      ${proto ? `<span class="url-seg ${protoClass}" title="${protoTip}">${escapeHtml(proto)}<span class="url-seg-label">${isHttps ? "SECURE" : "INSECURE"}</span></span>` : ""}
      <span class="url-seg ${hostClass}" title="${hostTip}">${escapeHtml(hostPart)}<span class="url-seg-label">${tIntel.spoofed_brand ? "SPOOFED" : tIntel.is_trusted ? "TRUSTED" : tIntel.is_high_risk_tld ? "HIGH-RISK TLD" : "DOMAIN"}</span></span>
      ${pathPart ? `<span class="url-seg ${pathClass}" title="${pathTip}">${escapeHtml(pathPart)}<span class="url-seg-label">${metrics.matched_keywords && metrics.matched_keywords.length > 0 && !tIntel.is_trusted ? "SUSPICIOUS PATH" : "PATH"}</span></span>` : ""}
    </div>
    <div class="url-bar-legend">
      <span class="legend-item"><span class="legend-dot safe"></span>Safe</span>
      <span class="legend-item"><span class="legend-dot warning"></span>Suspicious</span>
      <span class="legend-item"><span class="legend-dot danger"></span>Dangerous</span>
      <span class="legend-item"><span class="legend-dot neutral"></span>Neutral</span>
    </div>
  `;
}

/**
 * Renders matched phishing keywords as visual badges.
 */
function renderMatchedKeywords(data) {
  const container = document.getElementById("anat-keywords-container");
  if (!container) return;

  const metrics = data.metrics || {};
  const tIntel = data.threat_intel || {};
  const keywords = metrics.matched_keywords || [];

  if (keywords.length === 0) {
    container.innerHTML = `<span class="kw-badge safe-kw">None detected</span>`;
    return;
  }

  const isTrusted = tIntel.is_trusted;
  container.innerHTML = keywords.map(kw =>
    `<span class="kw-badge ${isTrusted ? 'safe-kw' : 'danger-kw'}" title="Found in URL: &quot;${escapeHtml(kw)}&quot;">${escapeHtml(kw)}</span>`
  ).join("");
}

function renderChecklist(items, filter) {
  filter = filter || "ALL";
  const grid = document.getElementById("url-checklist-grid");
  if (!grid) return;

  const filtered = filter === "ALL" ? items : items.filter(i => i.status === filter);

  if (filtered.length === 0) {
    grid.innerHTML = '<div style="padding:20px;text-align:center;color:#64748b">No criteria items matching the "' + filter + '" filter.</div>';
    return;
  }

  // Known penalty weights for each indicator (mirrors url_analyzer.py)
  const PENALTY_MAP = {
    "Insecure HTTP Protocol": 15,
    "Raw IP Address in Hostname": 35,
    "Non-Standard Port": 20,
    "Brand Impersonation / Typosquatting": 45,
    "High-Abuse TLD": 22,
    "URL Shortener Redirection Proxy": 20,
    "Excessive Subdomain Levels": 18,
    "Excessive URL Length": 12,
    "Moderate URL Length": 5,
    "@ Symbol in URL Authority": 30,
    "Double Slash": 20,
    "Credential & Security Keywords": 25,
    "Hyphenated Root Domain": 8,
    "High Digit Ratio": 12,
    "High Shannon Entropy": 10,
    "Redirect / Auth Query Parameter": 10,
    "Heavy Hex / Percent Encoding": 12
  };

  grid.innerHTML = filtered.map(item => {
    const status = (item.status || "PASS").toUpperCase();
    const stateClass = status === "FAIL" ? "fail" : (status === "WARN" ? "warn" : "pass");
    const icon = status === "PASS" ? "\u2713" : (status === "FAIL" ? "\u2717" : "\u26a0");
    const title = item.indicator || item.factor || item.name || "Security Indicator";
    const details = item.details || item.detail || item.description || "Evaluated against security baseline.";

    // Find penalty for this indicator
    const penaltyKey = Object.keys(PENALTY_MAP).find(k => title.startsWith(k));
    const penalty = penaltyKey ? PENALTY_MAP[penaltyKey] : null;

    let penaltyHtml = "";
    if (status !== "PASS" && penalty) {
      penaltyHtml = '<span class="chk-penalty ' + stateClass + '">+' + penalty + ' risk pts</span>';
    } else if (status === "PASS") {
      penaltyHtml = '<span class="chk-penalty pass-pts">\u2713 No penalty</span>';
    }

    return '<div class="check-item ' + stateClass + '">' +
      '<div class="check-icon ' + stateClass + '">' + icon + '</div>' +
      '<div class="check-info">' +
        '<div class="check-header">' +
          '<span class="check-indicator">' + escapeHtml(title) + '</span>' +
          '<div class="chk-badges">' + penaltyHtml +
            '<span class="check-status-badge ' + stateClass + '">' + status + '</span>' +
          '</div>' +
        '</div>' +
        '<p class="check-details">' + escapeHtml(details) + '</p>' +
      '</div>' +
    '</div>';
  }).join("");
}

function copyUrlReport() {
  if (!lastUrlScanResult) {
    showToast("No scan report available to copy", "warning");
    return;
  }
  const r = lastUrlScanResult;
  const report = [
    `========================================`,
    `PHISHGUARD CYBERSECURITY THREAT REPORT`,
    `========================================`,
    `Target: ${r.url}`,
    `Verdict: ${r.status}`,
    `Risk Score: ${r.risk_score} / 100`,
    `Confidence: ${Math.round((r.confidence || 0.95) * 100)}%`,
    `----------------------------------------`,
    `Component Scores:`,
    `- Heuristic Rules: ${r.rule_score} / 100`,
    `- ML Model:        ${r.ml_score} / 100`,
    `- Threat Intel:    ${r.threat_intel_score} / 100`,
    `----------------------------------------`,
    `Recommendation:`,
    `${r.recommendation}`,
    `========================================`
  ].join("\n");

  navigator.clipboard.writeText(report).then(() => {
    showToast("Security report copied to clipboard!", "success");
  }).catch(() => {
    showToast("Could not copy report automatically", "warning");
  });
}

/* =========================================================================
   4. MESSAGE & EMAIL SCANNER CONTROLLER
   ========================================================================= */

const MSG_PRESETS = {
  bank: "URGENT SECURITY ALERT: Your JPMorgan Chase online banking access has been suspended due to unusual login attempts. Verify your account immediately at http://chase-security-update.com.banking-auth-portal.tk to avoid permanent termination. Do not share your OTP.",
  lottery: "CONGRATULATIONS! You have won the $1,500,000 Coca-Cola International Annual Lottery Prize! To claim your cash prize, click here immediately and submit your social security number and processing fee.",
  delivery: "DHL Express: Your international package #US992014 cannot be delivered due to an unpaid customs fee of $3.50. Click http://bit.ly/dhl-customs-fee to pay and confirm your address within 24 hours.",
  safe: "Hi Team, please find attached the meeting notes and presentation slide deck from yesterday's product sync. Let me know if anyone has feedback before we finalize the sprint roadmap on Friday."
};

function initMessageScanner() {
  const form = document.getElementById("msg-scan-form");
  const select = document.getElementById("msg-preset-select");
  const btnClear = document.getElementById("btn-clear-msg");

  if (select) {
    select.addEventListener("change", () => {
      const val = select.value;
      const textarea = document.getElementById("target-msg-input");
      if (textarea && MSG_PRESETS[val]) {
        textarea.value = MSG_PRESETS[val];
      }
    });
  }

  if (btnClear) {
    btnClear.addEventListener("click", () => {
      const textarea = document.getElementById("target-msg-input");
      if (textarea) textarea.value = "";
      const card = document.getElementById("msg-result-card");
      if (card) card.classList.add("hidden");
    });
  }

  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      runMessageScan();
    });
  }
}

async function runMessageScan() {
  const textarea = document.getElementById("target-msg-input");
  const btnSubmit = document.getElementById("btn-submit-msg");
  const btnText = document.getElementById("msg-btn-text");
  const btnSpinner = document.getElementById("msg-btn-spinner");

  const message = textarea.value.trim();
  if (!message) {
    showToast("Please enter or paste communication text to analyze", "warning");
    return;
  }

  if (btnText) btnText.textContent = "Analyzing Patterns...";
  if (btnSpinner) btnSpinner.classList.remove("hidden");
  if (btnSubmit) btnSubmit.disabled = true;

  try {
    const res = await fetch("/api/scan-message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: message })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Message scan failed");
    }

    const data = await res.json();
    renderMessageResult(data);
    showToast(`Analysis complete: ${data.status} (Score: ${data.risk_score}/100)`, getToastType(data.status));
  } catch (err) {
    console.error("Message scan failed:", err);
    showToast(err.message || "Failed to analyze message.", "error");
  } finally {
    if (btnText) btnText.textContent = "Analyze Message";
    if (btnSpinner) btnSpinner.classList.add("hidden");
    if (btnSubmit) btnSubmit.disabled = false;
  }
}

function renderMessageResult(data) {
  const card = document.getElementById("msg-result-card");
  if (!card) return;
  card.classList.remove("hidden");

  // Banner
  const banner = document.getElementById("msg-verdict-banner");
  const badge = document.getElementById("msg-verdict-badge");
  const meta = document.getElementById("msg-result-meta");
  const riskVal = document.getElementById("msg-risk-val");

  const status = data.status || "SAFE";
  if (banner) {
    banner.className = "verdict-banner " + (
      status === "SAFE" ? "safe-banner" :
      status === "SUSPICIOUS" ? "suspicious-banner" : "phishing-banner"
    );
  }

  if (badge) {
    badge.textContent = status === "PHISHING" ? "HIGH RISK / PHISHING" : status;
    badge.className = "verdict-badge " + (
      status === "SAFE" ? "badge-safe" :
      status === "SUSPICIOUS" ? "badge-suspicious" : "badge-phishing"
    );
  }

  const conf = Math.round((data.confidence || 0.9) * 100);
  const catCount = (data.flagged_categories || []).length;
  if (meta) meta.textContent = `Confidence: ${conf}% | Threat Categories: ${catCount}`;
  if (riskVal) riskVal.textContent = data.risk_score;

  // Categories Tags
  const tagsContainer = document.getElementById("msg-categories-tags");
  if (tagsContainer) {
    const cats = data.flagged_categories || [];
    if (cats.length === 0) {
      tagsContainer.innerHTML = `<span class="tag tag-clean">✓ No Social Engineering Patterns Detected</span>`;
    } else {
      tagsContainer.innerHTML = cats.map(c => `
        <span class="tag tag-threat">⚠ ${escapeHtml(c)}</span>
      `).join("");
    }
  }

  // Checklist Grid
  const grid = document.getElementById("msg-checklist-grid");
  if (grid) {
    const checklist = data.checklist || [];
    grid.innerHTML = checklist.map(item => {
      const status = (item.status || "PASS").toUpperCase();
      const stateClass = status === "FAIL" ? "fail" : (status === "WARN" ? "warn" : "pass");
      const icon = status === "PASS" ? "✓" : (status === "FAIL" ? "✗" : "⚠");
      const title = item.indicator || item.factor || item.name || "Communication Factor";
      const details = item.details || item.detail || item.description || "Checked against social engineering patterns.";

      return `
        <div class="check-item ${stateClass}">
          <div class="check-icon ${stateClass}">${icon}</div>
          <div class="check-info">
            <div class="check-header">
              <span class="check-indicator">${escapeHtml(title)}</span>
              <span class="check-status-badge ${stateClass}">${status}</span>
            </div>
            <p class="check-details">${escapeHtml(details)}</p>
          </div>
        </div>
      `;
    }).join("");
  }

  // Embedded Links
  const linksCard = document.getElementById("msg-links-card");
  const linksList = document.getElementById("msg-embedded-links-list");
  const embeddedLinks = data.embedded_links || [];

  if (linksCard && linksList) {
    if (embeddedLinks.length === 0) {
      linksCard.classList.add("hidden");
    } else {
      linksCard.classList.remove("hidden");
      linksList.innerHTML = embeddedLinks.map(l => `
        <div class="embedded-link-row">
          <span class="link-url font-mono">${escapeHtml(l.url)}</span>
          <span class="link-badge ${l.status.toLowerCase()}">${l.status} (${l.risk_score}/100)</span>
        </div>
      `).join("");
    }
  }

  card.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* =========================================================================
   5. SCAN HISTORY CONTROLLER
   ========================================================================= */

function initHistory() {
  const searchInput = document.getElementById("history-search-input");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      clearTimeout(searchDebounceTimeout);
      searchDebounceTimeout = setTimeout(() => {
        loadHistory();
      }, 300);
    });
  }

  // Filter pills
  const pills = document.querySelectorAll(".filter-pills .pill");
  pills.forEach(pill => {
    pill.addEventListener("click", () => {
      pills.forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      currentFilter = pill.getAttribute("data-filter") || "";
      loadHistory();
    });
  });

  // Export buttons
  const btnCsv = document.getElementById("btn-export-csv");
  const btnJson = document.getElementById("btn-export-json");
  if (btnCsv) {
    btnCsv.addEventListener("click", () => {
      window.open("/api/history/export?format=csv", "_blank");
      showToast("Downloading CSV export...", "info");
    });
  }
  if (btnJson) {
    btnJson.addEventListener("click", () => {
      window.open("/api/history/export?format=json", "_blank");
      showToast("Downloading JSON export...", "info");
    });
  }

  // Clear all button
  const btnClearAll = document.getElementById("btn-clear-history");
  if (btnClearAll) {
    btnClearAll.addEventListener("click", clearAllHistory);
  }
}

async function loadHistory() {
  const tbody = document.getElementById("history-table-tbody");
  if (!tbody) return;

  const searchInput = document.getElementById("history-search-input");
  const search = searchInput ? searchInput.value.trim() : "";

  let url = `/api/history?limit=100`;
  if (search) url += `&search=${encodeURIComponent(search)}`;
  if (currentFilter) url += `&status_filter=${encodeURIComponent(currentFilter)}`;

  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error("Could not retrieve scan history");
    const data = await res.json();
    const scans = data.scans || [];

    if (scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-muted">No scan history matches your filter.</td></tr>`;
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const statusBadge = getStatusBadge(s.status);
      const scoreBadge = getScoreBadge(s.risk_score);
      const dateFormatted = formatTimestamp(s.timestamp);
      const targetShort = escapeHtml(truncateText(s.target, 48));
      const scanType = s.scan_type === "url" ? `<span class="type-tag url-tag">URL</span>` : `<span class="type-tag msg-tag">MSG</span>`;
      const reasonsShort = escapeHtml(truncateText(s.reasons || "Standard pattern check", 40));
      const confPct = Math.round((s.confidence || 0.95) * 100);

      return `
        <tr>
          <td class="text-muted text-sm">#${s.id}</td>
          <td>${scanType}</td>
          <td class="font-mono text-break" title="${escapeHtml(s.target)}">${targetShort}</td>
          <td>${statusBadge}</td>
          <td>${scoreBadge}</td>
          <td class="text-sm">${confPct}%</td>
          <td class="text-muted text-sm" title="${escapeHtml(s.reasons || '')}">${reasonsShort}</td>
          <td class="text-muted text-sm">${dateFormatted}</td>
          <td>
            <button class="btn-delete-icon" onclick="deleteHistoryItem(${s.id})" title="Delete entry">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
            </button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to load history:", err);
    tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-danger">Failed to load history records.</td></tr>`;
  }
}

async function deleteHistoryItem(id) {
  try {
    const res = await fetch(`/api/history/${id}`, { method: "DELETE" });
    if (!res.ok) throw new Error("Delete failed");
    showToast(`Scan record #${id} deleted`, "info");
    loadHistory();
    loadDashboardStats();
  } catch (err) {
    showToast("Failed to delete record: " + err.message, "error");
  }
}

async function clearAllHistory() {
  if (!confirm("Are you sure you want to clear all scan history records from the database?")) {
    return;
  }

  try {
    const res = await fetch("/api/history", { method: "DELETE" });
    if (!res.ok) throw new Error("Clear failed");
    showToast("Scan history cleared successfully", "success");
    loadHistory();
    loadDashboardStats();
  } catch (err) {
    showToast("Failed to clear history: " + err.message, "error");
  }
}

window.deleteHistoryItem = deleteHistoryItem;
window.quickInspectScan = function(id) {
  // Switch to URL scanner and fetch details if URL
  fetch(`/api/history/${id}`).then(res => res.json()).then(scan => {
    if (scan.scan_type === "url") {
      switchView("url-scanner-view");
      const urlInput = document.getElementById("target-url-input");
      if (urlInput) {
        urlInput.value = scan.target;
        runUrlScan();
      }
    } else {
      switchView("msg-scanner-view");
      const msgInput = document.getElementById("target-msg-input");
      if (msgInput) {
        msgInput.value = scan.target;
        runMessageScan();
      }
    }
  }).catch(err => {
    console.error("Inspect failed:", err);
  });
};

/* =========================================================================
   6. SECURITY STATISTICS CONTROLLER
   ========================================================================= */

function initStatistics() {
  // Initialized on switchView
}

async function loadStatisticsView() {
  try {
    const res = await fetch("/api/statistics");
    if (!res.ok) return;
    const stats = await res.json();

    const total = stats.total_scans || 0;
    const safe = stats.safe_count || 0;
    const suspicious = stats.suspicious_count || 0;
    const phishing = stats.phishing_count || 0;

    const totalEl = document.getElementById("stats-total-count");
    const avgScoreEl = document.getElementById("stats-avg-score");
    const ratioEl = document.getElementById("stats-phish-ratio");

    if (totalEl) totalEl.textContent = total.toLocaleString();

    // Average score estimation
    const avgScore = total > 0 ? Math.round(((safe * 15) + (suspicious * 45) + (phishing * 85)) / total) : 0;
    if (avgScoreEl) avgScoreEl.textContent = `${avgScore} / 100`;

    const phishRatio = total > 0 ? Math.round((phishing / total) * 100) : 0;
    if (ratioEl) ratioEl.textContent = `${phishRatio}%`;

    // Render Doughnut Chart
    renderStatsDoughnut(safe, suspicious, phishing);
  } catch (err) {
    console.error("Failed to load statistics view:", err);
  }
}

function renderStatsDoughnut(safe, suspicious, phishing) {
  const canvas = document.getElementById("statsDoughnutChart");
  if (!canvas) return;

  if (statsChartInstance) {
    statsChartInstance.destroy();
  }

  const ctx = canvas.getContext("2d");
  statsChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Safe Hits", "Suspicious Anomalies", "Phishing Threats"],
      datasets: [{
        data: [safe, suspicious, phishing],
        backgroundColor: ["#10b981", "#f59e0b", "#ef4444"],
        borderColor: "#182234",
        borderWidth: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#94a3b8", font: { family: "'Plus Jakarta Sans', sans-serif" }, padding: 16 }
        }
      },
      cutout: "65%"
    }
  });
}

/* =========================================================================
   7. SETTINGS CONTROLLER
   ========================================================================= */

function initSettings() {
  const sliderRules = document.getElementById("slider-weight-rules");
  const sliderMl = document.getElementById("slider-weight-ml");
  const sliderIntel = document.getElementById("slider-weight-intel");

  const dispRules = document.getElementById("weight-rules-disp");
  const dispMl = document.getElementById("weight-ml-disp");
  const dispIntel = document.getElementById("weight-intel-disp");

  if (sliderRules && dispRules) {
    sliderRules.addEventListener("input", () => {
      dispRules.textContent = `${sliderRules.value}%`;
    });
  }
  if (sliderMl && dispMl) {
    sliderMl.addEventListener("input", () => {
      dispMl.textContent = `${sliderMl.value}%`;
    });
  }
  if (sliderIntel && dispIntel) {
    sliderIntel.addEventListener("input", () => {
      dispIntel.textContent = `${sliderIntel.value}%`;
    });
  }

  const btnReset = document.getElementById("btn-reset-weights");
  if (btnReset) {
    btnReset.addEventListener("click", () => {
      if (sliderRules) sliderRules.value = 35;
      if (sliderMl) sliderMl.value = 45;
      if (sliderIntel) sliderIntel.value = 20;
      if (dispRules) dispRules.textContent = "35%";
      if (dispMl) dispMl.textContent = "45%";
      if (dispIntel) dispIntel.textContent = "20%";
      showToast("Reset weights to defaults (35/45/20)", "info");
    });
  }

  const form = document.getElementById("settings-form");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const payload = {
          weight_rules: parseFloat(sliderRules.value) / 100,
          weight_ml: parseFloat(sliderMl.value) / 100,
          weight_intel: parseFloat(sliderIntel.value) / 100
        };

        const res = await fetch("/api/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error("Save settings failed");
        showToast("Engine configuration saved successfully!", "success");
      } catch (err) {
        showToast("Could not save settings: " + err.message, "error");
      }
    });
  }
}

async function loadSettings() {
  try {
    const res = await fetch("/api/settings");
    if (!res.ok) return;
    const s = await res.json();

    const sliderRules = document.getElementById("slider-weight-rules");
    const sliderMl = document.getElementById("slider-weight-ml");
    const sliderIntel = document.getElementById("slider-weight-intel");

    const dispRules = document.getElementById("weight-rules-disp");
    const dispMl = document.getElementById("weight-ml-disp");
    const dispIntel = document.getElementById("weight-intel-disp");

    const rVal = Math.round((s.weight_rules || 0.35) * 100);
    const mVal = Math.round((s.weight_ml || 0.45) * 100);
    const iVal = Math.round((s.weight_intel || 0.20) * 100);

    if (sliderRules) sliderRules.value = rVal;
    if (sliderMl) sliderMl.value = mVal;
    if (sliderIntel) sliderIntel.value = iVal;

    if (dispRules) dispRules.textContent = `${rVal}%`;
    if (dispMl) dispMl.textContent = `${mVal}%`;
    if (dispIntel) dispIntel.textContent = `${iVal}%`;
  } catch (err) {
    console.warn("Failed to load settings:", err);
  }
}

/* =========================================================================
   8. FEEDBACK / FALSE POSITIVE MODAL
   ========================================================================= */

function initFeedbackModal() {
  const modal = document.getElementById("feedback-modal");
  const btnClose = document.getElementById("btn-close-modal");
  const btnCancel = document.getElementById("btn-cancel-feedback");
  const form = document.getElementById("feedback-form");

  function closeModal() {
    if (modal) modal.classList.add("hidden");
  }

  if (btnClose) btnClose.addEventListener("click", closeModal);
  if (btnCancel) btnCancel.addEventListener("click", closeModal);

  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeModal();
    });
  }

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const target = document.getElementById("feedback-target-input").value;
      const type = document.getElementById("feedback-type-select").value;
      const comments = document.getElementById("feedback-comments-input").value;

      try {
        const res = await fetch("/api/feedback", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target: target,
            feedback_type: type,
            comments: comments
          })
        });

        if (!res.ok) throw new Error("Feedback submission failed");
        showToast("Feedback submitted! Thank you for improving detection accuracy.", "success");
        closeModal();
      } catch (err) {
        showToast("Error submitting feedback: " + err.message, "error");
      }
    });
  }
}

function openFeedbackModal(target) {
  const modal = document.getElementById("feedback-modal");
  const input = document.getElementById("feedback-target-input");
  if (input) input.value = target || "";
  if (modal) modal.classList.remove("hidden");
}

/* =========================================================================
   9. UTILITIES & HELPERS
   ========================================================================= */

function getStatusBadge(status) {
  const s = (status || "SAFE").toUpperCase();
  if (s === "SAFE") {
    return `<span class="badge-status badge-safe">SAFE</span>`;
  } else if (s === "SUSPICIOUS") {
    return `<span class="badge-status badge-suspicious">SUSPICIOUS</span>`;
  } else {
    return `<span class="badge-status badge-phishing">PHISHING</span>`;
  }
}

function getScoreBadge(score) {
  const num = Math.round(score || 0);
  let color = "text-green";
  if (num > 30 && num <= 60) color = "text-amber";
  if (num > 60) color = "text-red";
  return `<span class="score-pill ${color}"><strong>${num}</strong> / 100</span>`;
}

function getToastType(status) {
  if (status === "SAFE") return "success";
  if (status === "SUSPICIOUS") return "warning";
  return "error";
}

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <div class="toast-content">
      <span>${escapeHtml(message)}</span>
    </div>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add("fade-out");
    setTimeout(() => toast.remove(), 400);
  }, 3500);
}

function formatTimestamp(isoString) {
  if (!isoString) return "--";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });
  } catch {
    return isoString;
  }
}

function truncateText(str, maxLen = 45) {
  if (!str) return "";
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + "…";
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* =========================================================================
   SHAPEGRID BACKGROUND ENGINE
   Hexagonal grid that scrolls diagonally with hover-fill + decay trail
   ========================================================================= */
function initShapeGridBackground() {
  const canvas = document.getElementById('shapegrid-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  // ── Config (mirrors ShapeGrid props) ─────────────────────────────────────
  const SPEED          = 0.5;
  const S              = 40;                     // circumradius (squareSize)
  const BORDER_COLOR   = 'rgba(255,255,255,0.15)';
  const HOVER_FILL     = '#1a2035';
  const MAX_TRAIL      = 5;
  const DECAY          = 1 / 55;                 // fade out over ~0.9 s at 60 fps

  // ── Flat-top hexagon layout constants ────────────────────────────────────
  const SQRT3        = Math.sqrt(3);
  const COL_W        = S * 1.5;                  // horizontal step
  const ROW_H        = S * SQRT3;                // vertical step
  const HEX_INRADIUS = S * SQRT3 / 2;

  // ── State ─────────────────────────────────────────────────────────────────
  let W = 0, H = 0;
  let totalX = 0, totalY = 0;
  const mouse = { x: -99999, y: -99999 };
  let lastKey = null;
  const trail = [];

  // ── Resize ────────────────────────────────────────────────────────────────
  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  // ── Mouse tracking ────────────────────────────────────────────────────────
  window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });
  window.addEventListener('mouseleave', () => { mouse.x = -99999; mouse.y = -99999; });

  // ── Draw hexagon path (flat-top, vertices at 0°, 60°, 120°…) ─────────────
  function hexPath(cx, cy) {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 3) * i;
      const x = cx + S * Math.cos(a);
      const y = cy + S * Math.sin(a);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.closePath();
  }

  // ── O(1) point-in-flat-top-hex test ──────────────────────────────────────
  // Three half-plane conditions for circumradius S:
  //   |dx| ≤ S  AND  |dy| ≤ S√3/2  AND  |dx| + |dy|/√3 ≤ S
  function ptInHex(cx, cy, px, py) {
    const adx = Math.abs(px - cx);
    const ady = Math.abs(py - cy);
    if (adx > S)            return false;
    if (ady > HEX_INRADIUS) return false;
    return adx + ady / SQRT3 <= S;
  }

  // ── Build visible cell list ───────────────────────────────────────────────
  function buildCells() {
    const ox   = ((totalX % COL_W) + COL_W) % COL_W;
    const oy   = ((totalY % ROW_H) + ROW_H) % ROW_H;
    const cols = Math.ceil(W / COL_W) + 4;
    const rows = Math.ceil(H / ROW_H) + 4;
    const cells = [];
    for (let c = -2; c < cols; c++) {
      const cx      = c * COL_W - ox;
      const stagger = (c & 1) ? ROW_H / 2 : 0;
      for (let r = -2; r < rows; r++) {
        cells.push({ c, r, cx, cy: r * ROW_H - oy + stagger });
      }
    }
    return cells;
  }

  // ── Stable cell identity (survives wrapping) ──────────────────────────────
  function cellKey(c, r) {
    return `${c + Math.floor(totalX / COL_W)},${r + Math.floor(totalY / ROW_H)}`;
  }

  // ── Main render loop ──────────────────────────────────────────────────────
  function render() {
    totalX += SPEED;
    totalY += SPEED;

    ctx.clearRect(0, 0, W, H);

    const cells = buildCells();

    // Detect hovered cell
    let hoveredKey = null;
    for (const { c, r, cx, cy } of cells) {
      if (ptInHex(cx, cy, mouse.x, mouse.y)) {
        hoveredKey = cellKey(c, r);
        break;
      }
    }

    // Push to trail on cell change
    if (hoveredKey && hoveredKey !== lastKey) {
      trail.unshift({ key: hoveredKey, alpha: 1 });
      if (trail.length > MAX_TRAIL) trail.pop();
      lastKey = hoveredKey;
    }

    // Decay trail
    for (let i = trail.length - 1; i >= 0; i--) {
      trail[i].alpha -= DECAY;
      if (trail[i].alpha <= 0) trail.splice(i, 1);
    }

    // Lookup map for O(1) per-cell check
    const trailMap = new Map();
    for (const t of trail) {
      if (!trailMap.has(t.key) || trailMap.get(t.key) < t.alpha) {
        trailMap.set(t.key, t.alpha);
      }
    }

    // Render each cell
    for (const { c, r, cx, cy } of cells) {
      const key = cellKey(c, r);
      const ta  = trailMap.get(key) || 0;

      hexPath(cx, cy);

      if (ta > 0) {
        ctx.globalAlpha = ta * 0.88;
        ctx.fillStyle   = HOVER_FILL;
        ctx.fill();
      }

      ctx.globalAlpha = 0.20;
      ctx.strokeStyle = BORDER_COLOR;
      ctx.lineWidth   = 1;
      ctx.stroke();
    }

    ctx.globalAlpha = 1;
    requestAnimationFrame(render);
  }

  requestAnimationFrame(render);
}
