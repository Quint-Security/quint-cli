export function dashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quint Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=DM+Sans:wght@400;500;600;700&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg-root: #0a0b0e;
    --bg-surface: #111318;
    --bg-elevated: #181a20;
    --bg-hover: #1e2028;
    --border: #252830;
    --border-subtle: #1c1e24;
    --text-primary: #e4e5e9;
    --text-secondary: #8b8d98;
    --text-muted: #5c5e6a;
    --accent: #6ee7b7;
    --accent-dim: rgba(110, 231, 183, 0.12);
    --allow: #34d399;
    --allow-bg: rgba(52, 211, 153, 0.10);
    --deny: #f87171;
    --deny-bg: rgba(248, 113, 113, 0.10);
    --rate-limited: #fbbf24;
    --rate-limited-bg: rgba(251, 191, 36, 0.10);
    --passthrough: #6b7280;
    --passthrough-bg: rgba(107, 114, 128, 0.10);
    --risk-low: #34d399;
    --risk-medium: #fb923c;
    --risk-high: #f87171;
    --risk-critical: #dc2626;
    --font-mono: 'IBM Plex Mono', 'SF Mono', 'Fira Code', monospace;
    --font-sans: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    --radius: 8px;
    --radius-sm: 5px;
  }

  body {
    font-family: var(--font-sans);
    background: var(--bg-root);
    color: var(--text-primary);
    line-height: 1.5;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
  }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

  /* ── Layout ── */
  .shell {
    max-width: 1440px;
    margin: 0 auto;
    padding: 24px 32px;
  }

  /* ── Header ── */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 28px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border-subtle);
  }
  .header-left { display: flex; align-items: center; gap: 14px; }
  .logo {
    font-family: var(--font-mono);
    font-size: 20px;
    font-weight: 600;
    color: var(--accent);
    letter-spacing: -0.5px;
  }
  .logo span { color: var(--text-muted); font-weight: 400; }
  .header-meta {
    display: flex;
    align-items: center;
    gap: 16px;
    font-size: 12px;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }
  .live-dot {
    width: 7px; height: 7px;
    background: var(--accent);
    border-radius: 50%;
    display: inline-block;
    animation: pulse 2s ease-in-out infinite;
    box-shadow: 0 0 6px rgba(110, 231, 183, 0.4);
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  /* ── Status Cards ── */
  .cards {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 24px;
  }
  .card {
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius);
    padding: 18px 20px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }
  .card:hover { border-color: var(--border); }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }
  .card:nth-child(1)::before { background: var(--accent); }
  .card:nth-child(2)::before { background: var(--allow); }
  .card:nth-child(3)::before { background: var(--deny); }
  .card:nth-child(4)::before { background: var(--risk-high); }
  .card-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    font-weight: 500;
    margin-bottom: 8px;
  }
  .card-value {
    font-family: var(--font-mono);
    font-size: 28px;
    font-weight: 600;
    letter-spacing: -1px;
  }
  .card:nth-child(1) .card-value { color: var(--accent); }
  .card:nth-child(2) .card-value { color: var(--allow); }
  .card:nth-child(3) .card-value { color: var(--deny); }
  .card:nth-child(4) .card-value { color: var(--risk-high); }

  /* ── Main Grid ── */
  .main {
    display: grid;
    grid-template-columns: 1fr 360px;
    gap: 20px;
    align-items: start;
  }

  /* ── Panel ── */
  .panel {
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .panel-header {
    padding: 14px 18px;
    border-bottom: 1px solid var(--border-subtle);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .panel-title {
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--text-secondary);
  }
  .panel-body { padding: 0; }

  /* ── Filters ── */
  .filters {
    display: flex;
    gap: 8px;
    padding: 12px 18px;
    border-bottom: 1px solid var(--border-subtle);
    flex-wrap: wrap;
  }
  .filter-select {
    background: var(--bg-elevated);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 6px 10px;
    font-size: 12px;
    font-family: var(--font-mono);
    cursor: pointer;
    outline: none;
    transition: border-color 0.15s;
  }
  .filter-select:hover, .filter-select:focus { border-color: var(--accent); }
  .filter-select option { background: var(--bg-elevated); }

  /* ── Log Table ── */
  .log-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .log-table th {
    text-align: left;
    padding: 10px 14px;
    font-weight: 500;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    background: var(--bg-elevated);
    border-bottom: 1px solid var(--border-subtle);
    position: sticky;
    top: 0;
    z-index: 1;
  }
  .log-table td {
    padding: 9px 14px;
    border-bottom: 1px solid var(--border-subtle);
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-secondary);
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .log-table tr { transition: background 0.1s; }
  .log-table tbody tr:hover { background: var(--bg-hover); }
  .log-table tbody tr.new-entry {
    animation: slideIn 0.3s ease-out;
  }
  @keyframes slideIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .log-scroll {
    max-height: calc(100vh - 310px);
    overflow-y: auto;
  }

  /* ── Verdict Badge ── */
  .verdict {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .verdict-allow { color: var(--allow); background: var(--allow-bg); }
  .verdict-deny { color: var(--deny); background: var(--deny-bg); }
  .verdict-rate_limited { color: var(--rate-limited); background: var(--rate-limited-bg); }
  .verdict-passthrough { color: var(--passthrough); background: var(--passthrough-bg); }

  /* ── Risk Badge ── */
  .risk {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.5px;
  }
  .risk-low { color: var(--risk-low); background: rgba(52,211,153,0.10); }
  .risk-medium { color: var(--risk-medium); background: rgba(251,146,60,0.10); }
  .risk-high { color: var(--risk-high); background: rgba(248,113,113,0.10); }
  .risk-critical { color: var(--risk-critical); background: rgba(220,38,38,0.12); }

  /* ── Sidebar Sections ── */
  .sidebar-stack { display: flex; flex-direction: column; gap: 16px; }

  .section-block {
    padding: 14px 18px;
    border-bottom: 1px solid var(--border-subtle);
  }
  .section-block:last-child { border-bottom: none; }
  .section-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    font-weight: 500;
    margin-bottom: 10px;
  }

  /* ── Bar Charts ── */
  .bar-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }
  .bar-label {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
    width: 80px;
    flex-shrink: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .bar-track {
    flex: 1;
    height: 6px;
    background: var(--bg-root);
    border-radius: 3px;
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.5s ease-out;
  }
  .bar-count {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
    width: 36px;
    text-align: right;
    flex-shrink: 0;
  }

  /* ── Server/Tool List ── */
  .server-item {
    padding: 8px 0;
    border-bottom: 1px solid var(--border-subtle);
  }
  .server-item:last-child { border-bottom: none; }
  .server-name {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 500;
    color: var(--text-primary);
    margin-bottom: 4px;
  }
  .server-meta {
    font-size: 11px;
    color: var(--text-muted);
  }
  .tool-rule {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-family: var(--font-mono);
    font-size: 10px;
    padding: 2px 6px;
    background: var(--bg-root);
    border-radius: 3px;
    margin: 2px 2px 2px 0;
  }
  .tool-rule-allow { color: var(--allow); }
  .tool-rule-deny { color: var(--deny); }

  /* ── Detail Modal ── */
  .modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.65);
    z-index: 100;
    align-items: center;
    justify-content: center;
  }
  .modal-overlay.open { display: flex; }
  .modal {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    width: 640px;
    max-height: 80vh;
    overflow-y: auto;
    padding: 24px;
  }
  .modal-close {
    float: right;
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 18px;
    padding: 4px;
  }
  .modal-close:hover { color: var(--text-primary); }
  .modal h3 {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 16px;
    color: var(--text-primary);
  }
  .detail-grid {
    display: grid;
    grid-template-columns: 120px 1fr;
    gap: 6px 12px;
    font-size: 12px;
  }
  .detail-key {
    color: var(--text-muted);
    font-weight: 500;
  }
  .detail-val {
    font-family: var(--font-mono);
    color: var(--text-secondary);
    word-break: break-all;
  }
  .detail-json {
    margin-top: 12px;
    background: var(--bg-root);
    border-radius: var(--radius-sm);
    padding: 12px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
  }

  /* ── Empty state ── */
  .empty {
    padding: 40px 20px;
    text-align: center;
    color: var(--text-muted);
    font-size: 13px;
  }

  /* ── Timestamp ── */
  .ts {
    color: var(--text-muted);
    font-size: 11px;
  }

  /* ── Fingerprint ── */
  .fingerprint {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
    background: var(--bg-elevated);
    padding: 2px 6px;
    border-radius: 3px;
  }

  @media (max-width: 1024px) {
    .main { grid-template-columns: 1fr; }
    .cards { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<div class="shell">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <div class="logo">quint<span>.dashboard</span></div>
    </div>
    <div class="header-meta">
      <span class="fingerprint" id="fp">loading...</span>
      <span><span class="live-dot"></span> live</span>
    </div>
  </div>

  <!-- Status Cards -->
  <div class="cards">
    <div class="card">
      <div class="card-label">Total Entries</div>
      <div class="card-value" id="stat-total">—</div>
    </div>
    <div class="card">
      <div class="card-label">Allowed</div>
      <div class="card-value" id="stat-allow">—</div>
    </div>
    <div class="card">
      <div class="card-label">Denied</div>
      <div class="card-value" id="stat-deny">—</div>
    </div>
    <div class="card">
      <div class="card-label">Risk Alerts</div>
      <div class="card-value" id="stat-risk">—</div>
    </div>
  </div>

  <!-- Main Grid -->
  <div class="main">

    <!-- Left: Audit Log -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Audit Log</span>
        <span id="log-count" style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);"></span>
      </div>
      <div class="filters">
        <select class="filter-select" id="filter-server"><option value="">All Servers</option></select>
        <select class="filter-select" id="filter-tool"><option value="">All Tools</option></select>
        <select class="filter-select" id="filter-verdict">
          <option value="">All Verdicts</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
          <option value="passthrough">Passthrough</option>
          <option value="rate_limited">Rate Limited</option>
        </select>
      </div>
      <div class="log-scroll">
        <table class="log-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Server</th>
              <th>Tool</th>
              <th>Method</th>
              <th>Verdict</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody id="log-body"></tbody>
        </table>
        <div class="empty" id="log-empty" style="display:none;">No audit entries yet. Start the proxy to see activity.</div>
      </div>
    </div>

    <!-- Right: Sidebar -->
    <div class="sidebar-stack">

      <!-- Policy -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Policy</span>
        </div>
        <div class="panel-body" id="policy-body">
          <div class="empty">Loading policy...</div>
        </div>
      </div>

      <!-- Risk Distribution -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Risk Distribution</span>
        </div>
        <div class="panel-body">
          <div class="section-block" id="risk-bars">
            <div class="empty">No data</div>
          </div>
        </div>
      </div>

      <!-- Top Tools -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Top Tools</span>
        </div>
        <div class="panel-body">
          <div class="section-block" id="top-tools">
            <div class="empty">No data</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Detail Modal -->
<div class="modal-overlay" id="modal">
  <div class="modal">
    <button class="modal-close" onclick="closeModal()">&times;</button>
    <h3>Entry Detail</h3>
    <div id="modal-content"></div>
  </div>
</div>

<script>
(function() {
  // ── State ──
  let allEntries = [];
  let knownServers = new Set();
  let knownTools = new Set();

  // ── Helpers ──
  function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  function fmtTime(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return iso; }
  }

  function verdictBadge(v) {
    return '<span class="verdict verdict-' + esc(v) + '">' + esc(v) + '</span>';
  }

  function riskBadge(level) {
    if (!level) return '<span style="color:var(--text-muted)">—</span>';
    return '<span class="risk risk-' + esc(level) + '">' + esc(level) + '</span>';
  }

  function prettyJson(s) {
    if (!s) return '';
    try { return JSON.stringify(JSON.parse(s), null, 2); }
    catch { return s; }
  }

  // ── Render Log Row ──
  function logRow(e, isNew) {
    const tr = document.createElement('tr');
    if (isNew) tr.className = 'new-entry';
    tr.style.cursor = 'pointer';
    tr.onclick = function() { showDetail(e.id); };
    tr.innerHTML =
      '<td class="ts">' + fmtTime(e.timestamp) + '</td>' +
      '<td>' + esc(e.server_name) + '</td>' +
      '<td>' + esc(e.tool_name || '—') + '</td>' +
      '<td>' + esc(e.method) + '</td>' +
      '<td>' + verdictBadge(e.verdict) + '</td>' +
      '<td>' + riskBadge(e.risk_level) + '</td>';
    return tr;
  }

  // ── Load Status ──
  function loadStatus() {
    fetch('/api/status').then(r => r.json()).then(d => {
      document.getElementById('fp').textContent = d.fingerprint + (d.encrypted ? ' (encrypted)' : '');
    }).catch(() => {});
  }

  // ── Load Stats ──
  function loadStats() {
    fetch('/api/stats').then(r => r.json()).then(d => {
      document.getElementById('stat-total').textContent = d.total.toLocaleString();
      document.getElementById('stat-allow').textContent = (d.verdicts.allow || 0).toLocaleString();
      document.getElementById('stat-deny').textContent = (d.verdicts.deny || 0).toLocaleString();
      const riskAlerts = (d.riskLevels.high || 0) + (d.riskLevels.critical || 0);
      document.getElementById('stat-risk').textContent = riskAlerts.toLocaleString();

      // Risk bars
      renderRiskBars(d.riskLevels);
      // Top tools
      renderTopTools(d.topTools);
    }).catch(() => {});
  }

  function renderRiskBars(levels) {
    const container = document.getElementById('risk-bars');
    const total = Object.values(levels).reduce((a, b) => a + b, 0);
    if (total === 0) { container.innerHTML = '<div class="empty">No risk data</div>'; return; }

    const order = ['low', 'medium', 'high', 'critical'];
    const colors = { low: 'var(--risk-low)', medium: 'var(--risk-medium)', high: 'var(--risk-high)', critical: 'var(--risk-critical)' };
    let html = '';
    for (const level of order) {
      const count = levels[level] || 0;
      const pct = total > 0 ? (count / total * 100) : 0;
      html += '<div class="bar-row">' +
        '<span class="bar-label">' + level + '</span>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + colors[level] + '"></div></div>' +
        '<span class="bar-count">' + count + '</span></div>';
    }
    container.innerHTML = html;
  }

  function renderTopTools(tools) {
    const container = document.getElementById('top-tools');
    if (!tools || tools.length === 0) { container.innerHTML = '<div class="empty">No tool data</div>'; return; }
    const max = tools[0].count;
    let html = '';
    for (const t of tools) {
      const pct = max > 0 ? (t.count / max * 100) : 0;
      html += '<div class="bar-row">' +
        '<span class="bar-label" title="' + esc(t.name) + '">' + esc(t.name) + '</span>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:var(--accent)"></div></div>' +
        '<span class="bar-count">' + t.count + '</span></div>';
    }
    container.innerHTML = html;
  }

  // ── Load Policy ──
  function loadPolicy() {
    fetch('/api/policy').then(r => r.json()).then(policy => {
      const container = document.getElementById('policy-body');
      if (!policy.servers || policy.servers.length === 0) {
        container.innerHTML = '<div class="empty">No server rules</div>';
        return;
      }
      let html = '';
      for (const srv of policy.servers) {
        html += '<div class="section-block"><div class="server-item" style="border:none;padding:0">' +
          '<div class="server-name">' + esc(srv.server) + '</div>' +
          '<div class="server-meta">default: <span class="verdict verdict-' + esc(srv.default_action) + '">' + esc(srv.default_action) + '</span></div>';
        if (srv.tools && srv.tools.length > 0) {
          html += '<div style="margin-top:6px">';
          for (const rule of srv.tools) {
            html += '<span class="tool-rule tool-rule-' + esc(rule.action) + '">' +
              esc(rule.tool) + ' → ' + esc(rule.action) + '</span>';
          }
          html += '</div>';
        }
        html += '</div></div>';
      }
      container.innerHTML = html;
    }).catch(() => {});
  }

  // ── Load Logs ──
  function loadLogs() {
    const server = document.getElementById('filter-server').value;
    const tool = document.getElementById('filter-tool').value;
    const verdict = document.getElementById('filter-verdict').value;

    const params = new URLSearchParams();
    if (server) params.set('server', server);
    if (tool) params.set('tool', tool);
    if (verdict) params.set('verdict', verdict);
    params.set('limit', '200');

    fetch('/api/logs?' + params).then(r => r.json()).then(d => {
      allEntries = d.entries;
      document.getElementById('log-count').textContent = d.total + ' total';
      renderLogs(false);
      updateFilterOptions(d.entries);
    }).catch(() => {});
  }

  function renderLogs(onlyNew) {
    const body = document.getElementById('log-body');
    const empty = document.getElementById('log-empty');

    if (allEntries.length === 0) {
      body.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';

    if (!onlyNew) {
      body.innerHTML = '';
      for (const e of allEntries) {
        body.appendChild(logRow(e, false));
      }
    }
  }

  function updateFilterOptions(entries) {
    for (const e of entries) {
      if (e.server_name) knownServers.add(e.server_name);
      if (e.tool_name) knownTools.add(e.tool_name);
    }

    const serverSel = document.getElementById('filter-server');
    const currentServer = serverSel.value;
    serverSel.innerHTML = '<option value="">All Servers</option>';
    for (const s of [...knownServers].sort()) {
      serverSel.innerHTML += '<option value="' + esc(s) + '"' + (s === currentServer ? ' selected' : '') + '>' + esc(s) + '</option>';
    }

    const toolSel = document.getElementById('filter-tool');
    const currentTool = toolSel.value;
    toolSel.innerHTML = '<option value="">All Tools</option>';
    for (const t of [...knownTools].sort()) {
      toolSel.innerHTML += '<option value="' + esc(t) + '"' + (t === currentTool ? ' selected' : '') + '>' + esc(t) + '</option>';
    }
  }

  // ── Detail Modal ──
  window.showDetail = function(id) {
    fetch('/api/logs/' + id).then(r => r.json()).then(e => {
      if (e.error) return;
      let html = '<div class="detail-grid">' +
        '<span class="detail-key">ID</span><span class="detail-val">' + e.id + '</span>' +
        '<span class="detail-key">Timestamp</span><span class="detail-val">' + esc(e.timestamp) + '</span>' +
        '<span class="detail-key">Server</span><span class="detail-val">' + esc(e.server_name) + '</span>' +
        '<span class="detail-key">Direction</span><span class="detail-val">' + esc(e.direction) + '</span>' +
        '<span class="detail-key">Method</span><span class="detail-val">' + esc(e.method) + '</span>' +
        '<span class="detail-key">Tool</span><span class="detail-val">' + esc(e.tool_name || '—') + '</span>' +
        '<span class="detail-key">Verdict</span><span class="detail-val">' + verdictBadge(e.verdict) + '</span>' +
        '<span class="detail-key">Risk Score</span><span class="detail-val">' + (e.risk_score != null ? e.risk_score : '—') + '</span>' +
        '<span class="detail-key">Risk Level</span><span class="detail-val">' + riskBadge(e.risk_level) + '</span>' +
        '<span class="detail-key">Signature</span><span class="detail-val" style="font-size:10px">' + esc(e.signature) + '</span>' +
        '</div>';

      if (e.arguments_json) {
        html += '<div style="margin-top:14px"><div class="section-label">Arguments</div><div class="detail-json">' + esc(prettyJson(e.arguments_json)) + '</div></div>';
      }
      if (e.response_json) {
        html += '<div style="margin-top:10px"><div class="section-label">Response</div><div class="detail-json">' + esc(prettyJson(e.response_json)) + '</div></div>';
      }

      document.getElementById('modal-content').innerHTML = html;
      document.getElementById('modal').classList.add('open');
    }).catch(() => {});
  };

  window.closeModal = function() {
    document.getElementById('modal').classList.remove('open');
  };

  document.getElementById('modal').addEventListener('click', function(ev) {
    if (ev.target === this) closeModal();
  });

  document.addEventListener('keydown', function(ev) {
    if (ev.key === 'Escape') closeModal();
  });

  // ── Filter Listeners ──
  document.getElementById('filter-server').addEventListener('change', loadLogs);
  document.getElementById('filter-tool').addEventListener('change', loadLogs);
  document.getElementById('filter-verdict').addEventListener('change', loadLogs);

  // ── SSE ──
  function connectSSE() {
    const es = new EventSource('/api/events');

    es.onmessage = function(ev) {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'new_entries' && msg.entries) {
          // Check if filters are active
          const server = document.getElementById('filter-server').value;
          const tool = document.getElementById('filter-tool').value;
          const verdict = document.getElementById('filter-verdict').value;

          const body = document.getElementById('log-body');
          const empty = document.getElementById('log-empty');
          empty.style.display = 'none';

          for (const e of msg.entries) {
            // Track for filters
            if (e.server_name) knownServers.add(e.server_name);
            if (e.tool_name) knownTools.add(e.tool_name);

            // Apply client-side filters
            if (server && e.server_name !== server) continue;
            if (tool && e.tool_name !== tool) continue;
            if (verdict && e.verdict !== verdict) continue;

            allEntries.unshift(e);
            body.insertBefore(logRow(e, true), body.firstChild);
          }

          // Update stats
          loadStats();
          updateFilterOptions(msg.entries);
          document.getElementById('log-count').textContent = msg.total + ' total';
        }
      } catch {}
    };

    es.onerror = function() {
      es.close();
      setTimeout(connectSSE, 3000);
    };
  }

  // ── Init ──
  loadStatus();
  loadStats();
  loadPolicy();
  loadLogs();
  connectSSE();
})();
</script>
</body>
</html>`;
}
