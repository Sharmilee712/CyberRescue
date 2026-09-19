/**
 * HIDS Security Console — Frontend Script
 * ─────────────────────────────────────────────────────────────────────────
 * Responsibilities:
 *   1. Poll /api/dashboard every POLL_INTERVAL seconds
 *   2. Update all KPI cards, attack feed, alerts table
 *   3. Update Chart.js charts with live data
 *   4. Fire simulation requests when demo buttons are clicked
 * ─────────────────────────────────────────────────────────────────────────
 */

const POLL_INTERVAL = 4000;   // milliseconds between dashboard refreshes
const API_BASE      = "";     // same origin — Flask serves both UI and API

// ── Chart instances (created once, updated each poll) ─────────────────────
let typeChart = null;
let sevChart  = null;

// ── Previous counts — used to detect new alerts so we can flash the row ───
let prevAlertCount = 0;

// ═════════════════════════════════════════════════════════════════════════
// INITIALISE CHARTS
// Called once on page load.
// ═════════════════════════════════════════════════════════════════════════
function initCharts() {
  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: "#5d8aaa",
          font: { family: "'Exo 2', sans-serif", size: 11 },
          boxWidth: 12,
          padding: 10
        }
      }
    }
  };

  // ── Doughnut: attack type distribution ─────────────────────────────────
  const typeCtx = document.getElementById("typeChart").getContext("2d");
  typeChart = new Chart(typeCtx, {
    type: "doughnut",
    data: {
      labels: ["No Data"],
      datasets: [{
        data: [1],
        backgroundColor: ["#0d2035"],
        borderColor: ["#0f3352"],
        borderWidth: 1
      }]
    },
    options: {
      ...chartDefaults,
      cutout: "65%",
      plugins: {
        ...chartDefaults.plugins,
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed}` } }
      }
    }
  });

  // ── Bar: severity breakdown ─────────────────────────────────────────────
  const sevCtx = document.getElementById("sevChart").getContext("2d");
  sevChart = new Chart(sevCtx, {
    type: "bar",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        label: "Alerts",
        data: [0, 0, 0, 0],
        backgroundColor: [
          "rgba(255,58,58,0.7)",
          "rgba(255,140,0,0.7)",
          "rgba(255,214,0,0.7)",
          "rgba(0,230,118,0.7)"
        ],
        borderColor: [
          "#ff3a3a", "#ff8c00", "#ffd600", "#00e676"
        ],
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      ...chartDefaults,
      scales: {
        x: { ticks: { color: "#5d8aaa" }, grid: { color: "#0f3352" } },
        y: {
          ticks: { color: "#5d8aaa", stepSize: 1 },
          grid: { color: "#0f3352" },
          beginAtZero: true
        }
      },
      plugins: { ...chartDefaults.plugins, legend: { display: false } }
    }
  });
}

// ═════════════════════════════════════════════════════════════════════════
// UPDATE CHARTS with fresh data
// ═════════════════════════════════════════════════════════════════════════
function updateCharts(data) {
  // ── Type doughnut ────────────────────────────────────────────────────
  const typeDist  = data.type_dist || {};
  const typeKeys  = Object.keys(typeDist);
  const typeVals  = Object.values(typeDist);
  const COLORS    = [
    "#ff3a3a","#ff8c00","#ffd600","#00e676",
    "#00b4ff","#b44fff","#ff4fb4","#4ffff8"
  ];

  if (typeKeys.length > 0) {
    typeChart.data.labels   = typeKeys;
    typeChart.data.datasets[0].data            = typeVals;
    typeChart.data.datasets[0].backgroundColor = typeKeys.map((_, i) => COLORS[i % COLORS.length]);
    typeChart.data.datasets[0].borderColor     = typeKeys.map((_, i) => COLORS[i % COLORS.length]);
  } else {
    typeChart.data.labels = ["No Data"];
    typeChart.data.datasets[0].data = [1];
    typeChart.data.datasets[0].backgroundColor = ["#0d2035"];
    typeChart.data.datasets[0].borderColor = ["#0f3352"];
  }
  typeChart.update("none");

  // ── Severity bar ────────────────────────────────────────────────────
  const sev = data.severity_dist || {};
  sevChart.data.datasets[0].data = [
    sev.Critical || 0,
    sev.High     || 0,
    sev.Medium   || 0,
    sev.Low      || 0
  ];
  sevChart.update("none");
}

// ═════════════════════════════════════════════════════════════════════════
// UPDATE KPI CARDS
// ═════════════════════════════════════════════════════════════════════════
function updateCards(data) {
  setText("totalLogs",    data.total_logs   || 0);
  setText("totalAlerts",  data.total_alerts || 0);

  const sev = data.severity_dist || {};
  setText("sevCritical", sev.Critical || 0);
  setText("sevHigh",     sev.High     || 0);
  setText("sevMedium",   sev.Medium   || 0);
  setText("sevLow",      sev.Low      || 0);

  // Threat badge
  const badge = document.getElementById("threatBadge");
  badge.textContent = data.threat_level || "NORMAL";
  badge.className   = "threat-badge " + (data.threat_level || "NORMAL");

  // Last updated
  if (data.last_updated) {
    const t = new Date(data.last_updated);
    setText("lastUpdated", "Updated: " + t.toLocaleTimeString());
  }
}

// ═════════════════════════════════════════════════════════════════════════
// UPDATE LIVE ATTACK FEED
// ═════════════════════════════════════════════════════════════════════════
function updateFeed(feedItems) {
  const list = document.getElementById("feedList");
  const countEl = document.getElementById("feedCount");

  if (!feedItems || feedItems.length === 0) {
    list.innerHTML = '<li class="feed-empty">Waiting for events…</li>';
    countEl.textContent = "0 events";
    return;
  }

  countEl.textContent = feedItems.length + " events";

  list.innerHTML = feedItems.map(item => {
    const t = formatTime(item.time);
    const sev = item.severity || "Low";
    return `<li class="feed-item">
      <span class="feed-dot ${sev}"></span>
      <span class="feed-time">${t}</span>
      <span class="feed-msg">${escHtml(item.message)}</span>
    </li>`;
  }).join("");
}

// ═════════════════════════════════════════════════════════════════════════
// UPDATE ALERTS TABLE
// ═════════════════════════════════════════════════════════════════════════
function updateAlertsTable(alerts) {
  const tbody = document.getElementById("alertsBody");

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No alerts yet</td></tr>';
    prevAlertCount = 0;
    return;
  }

  const isNew = alerts.length > prevAlertCount;
  prevAlertCount = alerts.length;

  tbody.innerHTML = alerts.map((a, i) => {
    const rowClass = (i === 0 && isNew) ? " class='new-row'" : "";
    const sev      = a.severity || "Low";
    return `<tr${rowClass}>
      <td><span style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-dim)">${formatTime(a.timestamp)}</span></td>
      <td>${escHtml(a.type || "—")}</td>
      <td><span class="sev-tag ${sev}">${sev}</span></td>
      <td>${escHtml(a.username || "—")}</td>
      <td>${escHtml(a.description || "—")}</td>
    </tr>`;
  }).join("");
}

// ═════════════════════════════════════════════════════════════════════════
// MAIN POLL — fetch /api/dashboard and update everything
// ═════════════════════════════════════════════════════════════════════════
async function pollDashboard() {
  try {
    const resp = await fetch(API_BASE + "/api/dashboard");
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();

    updateCards(data);
    updateCharts(data);
    updateFeed(data.attack_feed || []);
    updateAlertsTable(data.recent_alerts || []);

  } catch (err) {
    console.warn("[HIDS] Poll error:", err.message);
  }
}

// ═════════════════════════════════════════════════════════════════════════
// SIMULATION — called by demo buttons in the HTML
// ═════════════════════════════════════════════════════════════════════════
async function simulate(scenario) {
  const statusEl = document.getElementById("simStatus");
  statusEl.className = "sim-status";
  statusEl.textContent = "⟳ Triggering simulation…";
  // Reset animation
  statusEl.style.animation = "none";
  void statusEl.offsetWidth;
  statusEl.style.animation = "";

  try {
    const resp = await fetch(API_BASE + "/api/simulate/" + scenario, { method: "POST" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();

    statusEl.textContent = "✓ " + (data.alert?.type || scenario) + " simulated";
    // Immediately refresh dashboard to show the new alert
    await pollDashboard();

  } catch (err) {
    statusEl.className = "sim-status error";
    statusEl.textContent = "✗ Simulation failed: " + err.message;
    console.error("[HIDS] Simulation error:", err);
  }
}

// ═════════════════════════════════════════════════════════════════════════
// CLEAR ALL DATA
// ═════════════════════════════════════════════════════════════════════════
async function clearAll() {
  if (!confirm("Clear all logs and alerts? This cannot be undone.")) return;
  try {
    await fetch(API_BASE + "/api/clear", { method: "POST" });
    prevAlertCount = 0;
    await pollDashboard();
    const statusEl = document.getElementById("simStatus");
    statusEl.className = "sim-status";
    statusEl.textContent = "✓ All data cleared";
  } catch (err) {
    console.error(err);
  }
}

// ═════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═════════════════════════════════════════════════════════════════════════
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function formatTime(isoStr) {
  if (!isoStr) return "—";
  try {
    return new Date(isoStr).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch { return isoStr; }
}

// ═════════════════════════════════════════════════════════════════════════
// BOOT
// ═════════════════════════════════════════════════════════════════════════
document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  pollDashboard();                            // immediate first load
  setInterval(pollDashboard, POLL_INTERVAL);  // then auto-refresh
});
