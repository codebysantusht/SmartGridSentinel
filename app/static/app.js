
const $ = (id) => document.getElementById(id);
let metersCache = [];
let toastTimer;

function toast(message, error = false) {
  const el = $("toast");
  el.textContent = message;
  el.style.borderColor = error ? "#6a343b" : "#2b5147";
  el.style.background = error ? "#321d22" : "#132a25";
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3400);
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || body.message || `Request failed (${res.status})`);
  return body;
}

function fmt(n) {
  return Number(n || 0).toLocaleString("en-IN");
}

function shortTime(s) {
  if (!s) return "—";
  try {
    return new Date(s).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch {
    return s;
  }
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function selectedMeter() {
  return $("meterSelect").value;
}

async function loadStats() {
  const d = await api("/api/dashboard");

  $("kMeters").textContent = fmt(d.meters);
  $("kReadings").textContent = fmt(d.readings);
  $("kEnergy").innerHTML = `${fmt(d.total_wh)} <small>Wh</small>`;
  $("kAlerts").textContent = fmt(d.high_alerts);
  $("kEvents").textContent = `${fmt(d.events)} total events`;

  const chart = $("chart");

  if (!d.chart.length) {
    chart.innerHTML = '<div class="empty">Submit readings to populate the chart.</div>';
    $("chartCount").textContent = "Waiting for data";
    return;
  }

  const max = Math.max(...d.chart.map(x => x.wh), 1);

  chart.innerHTML = d.chart.map(p => {
    const height = Math.max(4, Math.round((p.wh / max) * 145));
    return `<div class="bar-group" title="${fmt(p.wh)} Wh">
      <div class="bar" style="height:${height}px"></div>
      <label>${escapeHtml(p.label)}</label>
    </div>`;
  }).join("");

  $("chartCount").textContent = `${d.chart.length} recent readings`;
}

async function loadMeters() {
  const d = await api("/api/meters");
  metersCache = d.meters;

  const current = selectedMeter();

  $("meterSelect").innerHTML = metersCache.length
    ? metersCache.map(m => `<option value="${escapeHtml(m.meter_id)}">${escapeHtml(m.meter_id)} · ${escapeHtml(m.label)}</option>`).join("")
    : '<option value="">No meters registered</option>';

  if (metersCache.some(m => m.meter_id === current)) {
    $("meterSelect").value = current;
  }

  $("meterRows").innerHTML = metersCache.length
    ? metersCache.map(m => `
      <tr>
        <td>
          <div class="meter-name">
            <div class="meter-icon">ϟ</div>
            <div>
              <b>${escapeHtml(m.meter_id)}</b>
              <small>${escapeHtml(m.label)}</small>
            </div>
          </div>
        </td>
        <td><span class="status-badge">${escapeHtml(m.status)}</span></td>
        <td>${fmt(m.reading_count)}</td>
        <td>${fmt(m.total_wh)} Wh</td>
        <td><button class="view-btn" title="Select meter" data-select="${escapeHtml(m.meter_id)}">↗</button></td>
      </tr>`).join("")
    : '<tr><td colspan="5" class="empty-cell">No meters yet. Register one or load demo data.</td></tr>';

  document.querySelectorAll("[data-select]").forEach(btn => {
    btn.addEventListener("click", () => {
      $("meterSelect").value = btn.dataset.select;
      $("readingMeter").value = btn.dataset.select;
      loadReadingHistory();
      toast(`Selected ${btn.dataset.select}`);
    });
  });
}

async function loadEvents() {
  const d = await api("/api/events?limit=12");

  $("eventsList").innerHTML = d.events.length
    ? d.events.map(e => {
      const high = ["HIGH", "CRITICAL"].includes(e.severity);
      const icon = high ? "!" : e.event_type.includes("VERIFIED") ? "✓" : "⌁";

      return `<div class="event-row">
        <div class="event-icon ${high ? "high" : ""}">${icon}</div>
        <div class="event-main">
          <b>${escapeHtml(e.event_type.replaceAll("_", " "))}</b>
          <span>${escapeHtml(e.message)} · ${escapeHtml(e.meter_id || "System")}</span>
        </div>
        <div class="event-meta">
          <span class="severity ${escapeHtml(e.severity)}">${escapeHtml(e.severity)}</span>
          ${shortTime(e.timestamp)}
        </div>
      </div>`;
    }).join("")
    : '<div class="empty-cell">No events recorded yet.</div>';
}

async function refreshAll() {
  try {
    await Promise.all([loadStats(), loadMeters(), loadEvents()]);
    await syncReadingMeterOptions();
  } catch (e) {
    toast(e.message, true);
  }
}

async function runAction(button, fn) {
  button.disabled = true;
  const old = button.textContent;
  button.textContent = "Working…";

  try {
    await fn();
  } catch (e) {
    toast(e.message, true);
  } finally {
    button.disabled = false;
    button.textContent = old;
  }
}

function showIntegrity(result) {
  const el = $("integrityResult");
  el.className = `integrity-result ${result.integrity_valid ? "good" : "bad"}`;

  const baseline = result.baseline_valid === null
    ? "No baseline created yet"
    : `Merkle baseline: ${result.baseline_valid ? "match" : "MISMATCH"}`;

  el.innerHTML = `
    <div class="result-symbol">${result.integrity_valid ? "✓" : "!"}</div>
    <div>
      <b>${result.integrity_valid ? "Integrity verified" : "Integrity check failed"}</b>
      <span>
        ${escapeHtml(result.message)}<br>
        HMAC: ${result.hmac_valid ? "valid" : "failed"} ·
        Hash chain: ${result.hash_chain_valid ? "valid" : "failed"} ·
        ${escapeHtml(baseline)}
      </span>
    </div>`;
}

async function verifyIntegrity() {
  const id = selectedMeter();
  if (!id) throw new Error("Register or seed a meter first.");

  const result = await api(`/api/meters/${encodeURIComponent(id)}/verify`, {
    method: "POST",
    body: "{}"
  });

  showIntegrity(result);
  toast(result.integrity_valid ? "Integrity check passed." : "Integrity mismatch detected.", !result.integrity_valid);
  await refreshAll();
}

async function createBaseline() {
  const id = selectedMeter();
  if (!id) throw new Error("Select a meter first.");

  const result = await api(`/api/meters/${encodeURIComponent(id)}/baseline`, {
    method: "POST",
    body: "{}"
  });

  toast(`Baseline created for ${result.reading_count} readings.`);
  await refreshAll();
}

async function aggregate() {
  const id = selectedMeter();
  if (!id) throw new Error("Select a meter first.");

  const result = await api(`/api/meters/${encodeURIComponent(id)}/aggregate`);

  $("aggregateValue").innerHTML = `${fmt(result.total_consumption_wh)} <small>Wh</small>`;
  $("aggregateSub").textContent = `${result.reading_count} readings included · ${id}`;

  toast("Aggregate calculated. Individual readings were not returned.");
  await refreshAll();
}

async function replay() {
  const id = selectedMeter();
  if (!id) throw new Error("Select a meter first.");

  const result = await api(`/api/demo/replay/${encodeURIComponent(id)}`, {
    method: "POST",
    body: "{}"
  });

  toast(`${result.attack} blocked: ${result.reason}`);
  await refreshAll();
}

async function tamper() {
  const id = selectedMeter();
  if (!id) throw new Error("Select a meter first.");

  const result = await api(`/api/demo/tamper/${encodeURIComponent(id)}`, {
    method: "POST",
    body: "{}"
  });

  toast(`Demo tampering applied to ${result.meter_id}. Now run Verify integrity.`, true);
  await refreshAll();
}

// Secure meter-reading dropdown
async function syncReadingMeterOptions() {
  const select = $("readingMeter");
  const current = select.value;
  const target = selectedMeter();

  select.innerHTML = metersCache.length
    ? metersCache.map(m => `<option value="${escapeHtml(m.meter_id)}">${escapeHtml(m.meter_id)} · ${escapeHtml(m.label)}</option>`).join("")
    : '<option value="">No meters registered</option>';

  if (metersCache.some(m => m.meter_id === current)) {
    select.value = current;
  } else if (metersCache.some(m => m.meter_id === target)) {
    select.value = target;
  }

  await loadReadingHistory();
}

// Readings history table
async function loadReadingHistory() {
  const id = $("readingMeter").value || selectedMeter();
  const target = $("readingHistoryRows");

  if (!id) {
    target.innerHTML = '<tr><td colspan="5" class="empty-cell">Register or select a meter first.</td></tr>';
    return;
  }

  try {
    const data = await api(`/api/meters/${encodeURIComponent(id)}/readings`);

    target.innerHTML = data.readings.length
      ? data.readings.slice().reverse().map(r => `
        <tr>
          <td>#${fmt(r.sequence_no)}</td>
          <td>${escapeHtml(shortTime(r.timestamp))}</td>
          <td>${fmt(r.consumption_wh)} Wh</td>
          <td class="hash-cell mac-ok" title="${escapeHtml(r.mac)}">${escapeHtml(r.mac.slice(0, 12))}…</td>
          <td class="hash-cell" title="${escapeHtml(r.chain_hash)}">${escapeHtml(r.chain_hash.slice(0, 12))}…</td>
        </tr>`).join("")
      : '<tr><td colspan="5" class="empty-cell">No readings for this meter yet.</td></tr>';
  } catch (e) {
    target.innerHTML = `<tr><td colspan="5" class="empty-cell">${escapeHtml(e.message)}</td></tr>`;
  }
}

// Submit and authenticate a reading
$("readingForm").addEventListener("submit", async e => {
  e.preventDefault();

  const button = $("submitReadingBtn");
  const meter_id = $("readingMeter").value;
  const consumption_wh = Number($("readingWh").value);

  if (!meter_id) return toast("Select a meter first.", true);
  if (!Number.isInteger(consumption_wh) || consumption_wh <= 0) {
    return toast("Enter a positive whole number of Wh.", true);
  }

  button.disabled = true;
  const old = button.textContent;
  button.textContent = "Authenticating…";

  try {
    const result = await api("/api/readings", {
      method: "POST",
      body: JSON.stringify({ meter_id, consumption_wh })
    });

    const panel = $("readingResult");
    panel.className = "integrity-result good";
    panel.innerHTML = `
      <div class="result-symbol">✓</div>
      <div>
        <b>Reading authenticated and stored</b>
        <span>
          Meter ${escapeHtml(result.meter_id)} · sequence #${fmt(result.sequence_no)}<br>
          HMAC-SHA256 generated and verified · hash chain appended.
        </span>
      </div>`;

    toast(`Reading accepted for ${meter_id} (${consumption_wh} Wh).`);
    $("readingWh").value = "";
    $("meterSelect").value = meter_id;

    await refreshAll();
    $("readingMeter").value = meter_id;
    await loadReadingHistory();
  } catch (err) {
    const panel = $("readingResult");
    panel.className = "integrity-result bad";
    panel.innerHTML = `
      <div class="result-symbol">!</div>
      <div><b>Reading rejected</b><span>${escapeHtml(err.message)}</span></div>`;
    toast(err.message, true);
  } finally {
    button.disabled = false;
    button.textContent = old;
  }
});

// Button wiring
$("refreshBtn").addEventListener("click", () => runAction($("refreshBtn"), refreshAll));
$("eventsRefresh").addEventListener("click", () => runAction($("eventsRefresh"), loadEvents));
$("verifyBtn").addEventListener("click", () => runAction($("verifyBtn"), verifyIntegrity));
$("baselineBtn").addEventListener("click", () => runAction($("baselineBtn"), createBaseline));
$("aggregateBtn").addEventListener("click", () => runAction($("aggregateBtn"), aggregate));
$("replayBtn").addEventListener("click", () => runAction($("replayBtn"), replay));
$("tamperBtn").addEventListener("click", () => runAction($("tamperBtn"), tamper));
$("historyRefresh").addEventListener("click", () => runAction($("historyRefresh"), loadReadingHistory));

$("openRegister").addEventListener("click", () => $("registerDialog").showModal());
$("dismissNotice").addEventListener("click", () => document.querySelector(".notice").remove());

$("registerForm").addEventListener("submit", async e => {
  e.preventDefault();

  const button = $("registerSubmit");
  button.disabled = true;

  try {
    const result = await api("/api/meters", {
      method: "POST",
      body: JSON.stringify({
        meter_id: $("newMeterId").value.trim(),
        label: $("newMeterLabel").value.trim()
      })
    });

    $("registerDialog").close();
    $("registerForm").reset();
    toast(`Meter ${result.meter_id} registered.`);
    await refreshAll();
  } catch (err) {
    toast(err.message, true);
  } finally {
    button.disabled = false;
  }
});

$("meterSelect").addEventListener("change", async () => {
  $("aggregateValue").innerHTML = '— <small>Wh</small>';
  $("aggregateSub").textContent = "Click Calculate aggregate to query this meter.";
  $("readingMeter").value = selectedMeter();
  await loadReadingHistory();
});

$("readingMeter").addEventListener("change", loadReadingHistory);

function updateClock() {
  $("clock").textContent = new Date().toLocaleString([], {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
  });
}

updateClock();
setInterval(updateClock, 30000);

(async function init() {
  try {
    await api("/api/health");
    await refreshAll();

    if (!metersCache.length) {
      const seed = await api("/api/demo/seed", {
        method: "POST",
        body: "{}"
      });

      if (seed.status === "seeded") {
        toast("Demo environment initialized with sample meters.");
        await refreshAll();
      }
    }
  } catch (e) {
    toast(`Backend connection failed: ${e.message}`, true);
  }
})();
