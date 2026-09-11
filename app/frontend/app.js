/**
 * AegisPhish Frontend Controller
 * Handles interactive scanning, preset threats, explainable AI rendering,
 * and scientific benchmark visualization.
 */

let rocChartInstance = null;
let genChartInstance = null;

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  loadPresets();
  loadBenchmarks();
  initFormHandler();
});

// Tab Navigation
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");

      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add("active");
      }
    });
  });
}

// Load Attack Presets
async function loadPresets() {
  const selector = document.getElementById("preset-selector");
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
      selector.appendChild(opt);
    });

    selector.addEventListener("change", (e) => {
      const selected = selector.options[selector.selectedIndex];
      if (selected && selected.dataset.url) {
        document.getElementById("url-input").value = selected.dataset.url;
        document.getElementById("html-input").value = selected.dataset.html || "";
        // Automatically submit scan on preset select
        triggerScan();
      }
    });
  } catch (err) {
    console.warn("Presets fetch skipped:", err);
  }
}

// Form Handler
function initFormHandler() {
  const form = document.getElementById("scan-form");
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    triggerScan();
  });
}

async function triggerScan() {
  const urlInput = document.getElementById("url-input");
  const htmlInput = document.getElementById("html-input");
  const btnText = document.getElementById("btn-text");
  const btnSpinner = document.getElementById("btn-spinner");
  const submitBtn = document.getElementById("submit-scan-btn");

  const url = urlInput.value.trim();
  if (!url) return;

  // Set loading state
  btnText.textContent = "Analyzing...";
  btnSpinner.classList.remove("hidden");
  submitBtn.disabled = true;

  try {
    const payload = {
      url: url,
      html_content: htmlInput.value.trim() || null
    };

    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || "Analysis request failed.");
    }

    const data = await res.json();
    renderAnalysisResults(data);
  } catch (err) {
    alert("Scan Error: " + err.message);
  } finally {
    btnText.textContent = "Analyze Target";
    btnSpinner.classList.add("hidden");
    submitBtn.disabled = false;
  }
}

// Render Analysis Results
function renderAnalysisResults(data) {
  document.getElementById("results-placeholder").classList.add("hidden");
  const resultsContainer = document.getElementById("results-container");
  resultsContainer.classList.remove("hidden");

  // 1. Master Verdict Banner
  const banner = document.getElementById("verdict-banner");
  const verdictIcon = document.getElementById("verdict-icon");
  const verdictTag = document.getElementById("verdict-tag");
  const verdictTitle = document.getElementById("verdict-title");
  const verdictSummary = document.getElementById("verdict-summary");
  const riskScoreVal = document.getElementById("risk-score-val");
  const riskBarFill = document.getElementById("risk-bar-fill");
  const latencyVal = document.getElementById("latency-val");
  const featLatencyVal = document.getElementById("feat-latency-val");

  banner.className = "verdict-banner";
  const phishProb = data.proposed_system.phishing_probability;
  const riskPercent = (phishProb * 100).toFixed(1);

  riskScoreVal.textContent = `${riskPercent}%`;
  riskBarFill.style.width = `${riskPercent}%`;
  latencyVal.textContent = `${data.timing.total_latency_ms} ms`;
  featLatencyVal.textContent = `Extraction: ${data.timing.feature_extraction_ms}ms | Model: ${data.proposed_system.inference_latency_ms}ms`;

  if (phishProb >= 0.70) {
    banner.classList.add("danger");
    verdictIcon.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    verdictTag.textContent = "CRITICAL PHISHING DETECTED";
    verdictTitle.textContent = "High-Risk Malicious Phishing Attack";
  } else if (phishProb >= 0.35) {
    banner.classList.add("warning");
    verdictIcon.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    verdictTag.textContent = "SUSPICIOUS / ELEVATED RISK";
    verdictTitle.textContent = "Ambiguous Website: Caution Recommended";
  } else {
    banner.classList.add("safe");
    verdictIcon.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;
    verdictTag.textContent = "LEGITIMATE WEBSITE VERIFIED";
    verdictTitle.textContent = "Authentic & Safe Web Infrastructure";
  }

  verdictSummary.textContent = data.explanation.summary || "";

  // 2. Proposed vs Baseline Model Cards
  const propPredTag = document.getElementById("prop-pred-tag");
  const propPhishProb = document.getElementById("prop-phish-prob");
  const propLegitProb = document.getElementById("prop-legit-prob");

  propPredTag.textContent = data.proposed_system.prediction_label;
  propPredTag.className = `pred-tag ${data.proposed_system.prediction === 1 ? 'phish' : 'legit'}`;
  propPhishProb.textContent = `${(data.proposed_system.phishing_probability * 100).toFixed(2)}%`;
  propLegitProb.textContent = `${(data.proposed_system.legitimate_probability * 100).toFixed(2)}%`;

  const basePredTag = document.getElementById("base-pred-tag");
  const basePhishProb = document.getElementById("base-phish-prob");
  const baseLegitProb = document.getElementById("base-legit-prob");

  basePredTag.textContent = data.baseline_system.prediction_label;
  basePredTag.className = `pred-tag ${data.baseline_system.prediction === 1 ? 'phish' : 'legit'}`;
  basePhishProb.textContent = `${(data.baseline_system.phishing_probability * 100).toFixed(2)}%`;
  baseLegitProb.textContent = `${(data.baseline_system.legitimate_probability * 100).toFixed(2)}%`;

  // 3. Explainability / Security Attribution
  const riskList = document.getElementById("risk-factors-list");
  const safeList = document.getElementById("safe-factors-list");
  riskList.innerHTML = "";
  safeList.innerHTML = "";

  const riskFactors = data.explanation.critical_risk_factors || [];
  if (riskFactors.length === 0) {
    riskList.innerHTML = `<div class="factor-item"><div class="factor-desc">No anomalous threat vectors flagged.</div></div>`;
  } else {
    riskFactors.forEach(rf => {
      const el = document.createElement("div");
      el.className = "factor-item danger-border";
      el.innerHTML = `
        <div class="factor-title-row">
          <span class="factor-title">${rf.title}</span>
          <span class="severity-pill ${rf.severity.toLowerCase()}">${rf.severity}</span>
        </div>
        <div class="factor-desc">${rf.description}</div>
      `;
      riskList.appendChild(el);
    });
  }

  const safeFactors = data.explanation.mitigating_factors || [];
  if (safeFactors.length === 0) {
    safeList.innerHTML = `<div class="factor-item"><div class="factor-desc">No authentic baseline trust signals detected.</div></div>`;
  } else {
    safeFactors.forEach(sf => {
      const el = document.createElement("div");
      el.className = "factor-item safe-border";
      el.innerHTML = `
        <div class="factor-title-row">
          <span class="factor-title">${sf.title}</span>
          <span class="severity-pill safe">Safe</span>
        </div>
        <div class="factor-desc">${sf.description}</div>
      `;
      safeList.appendChild(el);
    });
  }

  // 4. Feature Vector Grid
  const featuresGrid = document.getElementById("features-grid");
  const continuousBadge = document.getElementById("continuous-stats-badge");
  featuresGrid.innerHTML = "";

  const stats = data.continuous_stats;
  continuousBadge.textContent = `Host: ${stats.hostname} | Entropy: ${stats.entropy} | Len: ${stats.url_length} | Digits: ${stats.digit_count}`;

  Object.entries(data.features).forEach(([featName, featVal]) => {
    const tile = document.createElement("div");
    tile.className = "feature-tile";
    
    let valClass = "val-good";
    let valText = "1 (Legit)";
    if (featVal === -1) {
      valClass = "val-bad";
      valText = "-1 (Phish)";
    } else if (featVal === 0) {
      valClass = "val-warn";
      valText = "0 (Suspicious)";
    }

    tile.innerHTML = `
      <span class="feat-name" title="${featName}">${featName}</span>
      <span class="feat-val ${valClass}">${valText}</span>
    `;
    featuresGrid.appendChild(tile);
  });
}

// Load Benchmarks and Render Charts
async function loadBenchmarks() {
  try {
    const res = await fetch("/api/benchmark");
    if (!res.ok) return;
    const data = await res.json();

    // Highlights
    const findings = data.research_findings;
    document.getElementById("fnr-reduction-stat").textContent = `${findings.fnr_reduction_percentage}%`;
    document.getElementById("cv-accuracy-stat").textContent = `${(data.grouped_cv_generalization.proposed_champion.accuracy_mean * 100).toFixed(2)}%`;
    document.getElementById("brier-stat").textContent = `${data.holdout_evaluation.proposed_models.proposed_lightgbm.brier_score}`;

    // Populate Comparison Table
    const tbody = document.getElementById("benchmark-table-body");
    tbody.innerHTML = "";

    const allModels = [
      { name: "Proposed Champion (Calibrated LightGBM)", modal: "Full Multi-Modal (URL+Domain+HTML+SSL)", isChamp: true, data: data.holdout_evaluation.proposed_models.proposed_lightgbm },
      { name: "Proposed Multi-Modal Stacking Ensemble", modal: "Full Multi-Modal (LGBM+XGB+RF)", isChamp: false, data: data.holdout_evaluation.proposed_models.proposed_stacking },
      { name: "Proposed Multi-Modal XGBoost", modal: "Full Multi-Modal (URL+Domain+HTML+SSL)", isChamp: false, data: data.holdout_evaluation.proposed_models.proposed_xgboost },
      { name: "Baseline Random Forest (Reference Paper)", modal: "URL & Domain Only (14 features)", isChamp: false, data: data.holdout_evaluation.baseline_models.random_forest },
      { name: "Baseline Logistic Regression", modal: "URL & Domain Only (14 features)", isChamp: false, data: data.holdout_evaluation.baseline_models.logistic_regression },
      { name: "Baseline Decision Tree", modal: "URL & Domain Only (14 features)", isChamp: false, data: data.holdout_evaluation.baseline_models.decision_tree },
      { name: "Baseline Naïve Bayes", modal: "URL & Domain Only (14 features)", isChamp: false, data: data.holdout_evaluation.baseline_models.naive_bayes },
      { name: "Baseline K-NN", modal: "URL & Domain Only (14 features)", isChamp: false, data: data.holdout_evaluation.baseline_models.knn },
    ];

    allModels.forEach(m => {
      const row = document.createElement("tr");
      if (m.isChamp) row.className = "champion-row";
      row.innerHTML = `
        <td>${m.name}</td>
        <td>${m.modal}</td>
        <td>${(m.data.accuracy * 100).toFixed(2)}%</td>
        <td>${(m.data.recall * 100).toFixed(2)}%</td>
        <td class="${m.data.false_negative_rate <= 0.005 ? 'safe-text' : 'danger-text'}"><strong>${(m.data.false_negative_rate * 100).toFixed(2)}%</strong></td>
        <td>${m.data.roc_auc.toFixed(4)}</td>
        <td>${m.data.brier_score !== undefined ? m.data.brier_score.toFixed(4) : 'N/A'}</td>
        <td>${m.data.latency_ms.toFixed(2)} ms</td>
      `;
      tbody.appendChild(row);
    });

    // Render Charts
    renderROCChart(data);
    renderGeneralizationChart(data);

  } catch (err) {
    console.warn("Benchmark data loading failed:", err);
  }
}

function renderROCChart(data) {
  const ctx = document.getElementById("roc-chart");
  if (!ctx) return;

  const bRoc = data.holdout_evaluation.baseline_models.random_forest.roc_curve;
  const pRoc = data.holdout_evaluation.proposed_models.proposed_lightgbm.roc_curve;

  const baselineData = bRoc.fpr.map((x, i) => ({ x: x, y: bRoc.tpr[i] }));
  const proposedData = pRoc.fpr.map((x, i) => ({ x: x, y: pRoc.tpr[i] }));

  if (rocChartInstance) rocChartInstance.destroy();

  rocChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      datasets: [
        {
          label: `Proposed Multi-Modal (AUC = ${data.holdout_evaluation.proposed_models.proposed_lightgbm.roc_auc.toFixed(3)})`,
          data: proposedData,
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          borderWidth: 3,
          fill: true,
          tension: 0.1
        },
        {
          label: `Baseline RF (AUC = ${data.holdout_evaluation.baseline_models.random_forest.roc_auc.toFixed(3)})`,
          data: baselineData,
          borderColor: '#f43f5e',
          borderWidth: 2,
          borderDash: [5, 5],
          fill: false,
          tension: 0.1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          type: 'linear',
          title: { display: true, text: 'False Positive Rate (FPR)', color: '#94a3b8' },
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#94a3b8' }
        },
        y: {
          title: { display: true, text: 'True Positive Rate (Recall)', color: '#94a3b8' },
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#94a3b8' },
          min: 0.8,
          max: 1.0
        }
      },
      plugins: {
        legend: { labels: { color: '#f8fafc', font: { family: 'Plus Jakarta Sans' } } }
      }
    }
  });
}

function renderGeneralizationChart(data) {
  const ctx = document.getElementById("generalization-chart");
  if (!ctx) return;

  const baseCv = data.grouped_cv_generalization.baseline_rf;
  const propCv = data.grouped_cv_generalization.proposed_champion;

  if (genChartInstance) genChartInstance.destroy();

  genChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Accuracy', 'Recall (Detection Rate)', 'F1-Score', '1 - FNR (Safety)'],
      datasets: [
        {
          label: 'Baseline (URL/Domain Only)',
          data: [
            baseCv.accuracy_mean * 100,
            baseCv.recall_mean * 100,
            baseCv.f1_score_mean * 100,
            (1 - baseCv.false_negative_rate_mean) * 100
          ],
          backgroundColor: 'rgba(148, 163, 184, 0.6)',
          borderColor: '#94a3b8',
          borderWidth: 1
        },
        {
          label: 'Proposed (Multi-Modal Calibrated)',
          data: [
            propCv.accuracy_mean * 100,
            propCv.recall_mean * 100,
            propCv.f1_score_mean * 100,
            (1 - propCv.false_negative_rate_mean) * 100
          ],
          backgroundColor: 'rgba(6, 182, 212, 0.75)',
          borderColor: '#06b6d4',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          min: 90,
          max: 100,
          title: { display: true, text: 'Score (%)', color: '#94a3b8' },
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#94a3b8' }
        },
        x: {
          grid: { display: false },
          ticks: { color: '#94a3b8' }
        }
      },
      plugins: {
        legend: { labels: { color: '#f8fafc', font: { family: 'Plus Jakarta Sans' } } }
      }
    }
  });
}
