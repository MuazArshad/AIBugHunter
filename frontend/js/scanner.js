/**
 * scanner.js — WebSocket connection, real-time event handling, terminal logging
 */

const Scanner = (() => {
  let ws = null;
  const PHASES = ['init', 'recon', 'probing', 'scanning', 'ai_triage', 'done'];
  const phaseProgress = { init: 10, recon: 30, probing: 50, scanning: 80, ai_triage: 92, done: 100 };
  let currentPhaseIdx = -1;

  // ── Connect WebSocket ──────────────────────────────────────────────────────
  async function connect(scanId, payload) {
    reset();

    const apiBase = (window.API_BASE_URL || localStorage.getItem('API_BASE_URL') || window.location.origin).replace(/\/$/, '');
    const proto = apiBase.startsWith('https') ? 'wss' : 'ws';
    const host = apiBase.replace(/^https?:\/\//, '');
    const wsUrl = `${proto}://${host}/ws/scan/${scanId}`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      ws.send(JSON.stringify(payload));
      log('cyan', `WebSocket connected — scan ${scanId.slice(0, 8)}...`);
    };

    ws.onmessage = (evt) => {
      try {
        const event = JSON.parse(evt.data);
        handleEvent(event);
      } catch (e) {
        log('muted', `[raw] ${evt.data}`);
      }
    };

    ws.onerror = () => {
      log('red', '❌ WebSocket error. Is the backend running?');
      App.setStatus('error', 'Error');
    };

    ws.onclose = () => {
      log('muted', '— Connection closed —');
      App.onScanEnd();
    };
  }

  // ── Disconnect ─────────────────────────────────────────────────────────────
  function disconnect() {
    if (ws) {
      ws.close();
      ws = null;
    }
  }

  // ── Event Router ───────────────────────────────────────────────────────────
  function handleEvent(event) {
    switch (event.type) {
      case 'status':
        handleStatus(event);
        break;
      case 'recon':
        handleRecon(event);
        break;
      case 'recon_summary':
        handleReconSummary(event);
        break;
      case 'live_found':
        log('green', `🌐 Live: ${event.url} [${event.status}]`);
        break;
      case 'scanner_start':
        log('cyan', `🔬 [${event.scanner}] → ${event.url}`);
        break;
      case 'scanner_error':
        log('muted', `⚠ [${event.scanner}] Error on ${event.url}: ${event.error}`);
        break;
      case 'finding':
        handleFinding(event);
        break;
      case 'ai_triage':
        log('purple', `🤖 AI triage complete for finding ${event.finding_id.slice(0, 8)}`);
        break;
      case 'ai_summary':
        handleAISummary(event);
        break;
      case 'ai_error':
        log('red', `🤖 AI error: ${event.error}`);
        break;
      case 'complete':
        handleComplete(event);
        break;
      case 'error':
        log('red', `❌ ${event.message}`);
        App.setStatus('error', 'Error');
        break;
      default:
        // silently ignore unknown events
    }
  }

  // ── Status / Phase ─────────────────────────────────────────────────────────
  function handleStatus(event) {
    log('white', event.message);
    if (event.phase) setPhase(event.phase);
  }

  function setPhase(phase) {
    const idx = PHASES.indexOf(phase);
    if (idx < 0) return;

    // Mark previous phases as done
    PHASES.slice(0, idx).forEach(p => {
      const el = document.getElementById(`phase-${p}`);
      if (el) { el.classList.remove('active'); el.classList.add('done'); }
    });

    // Mark current as active
    const current = document.getElementById(`phase-${phase}`);
    if (current) { current.classList.remove('done'); current.classList.add('active'); }

    // Progress bar
    setProgress(phaseProgress[phase] || 0, phase.toUpperCase());
    currentPhaseIdx = idx;
  }

  function setProgress(pct, label) {
    const bar = document.getElementById('progress-bar');
    const lbl = document.getElementById('progress-label');
    if (bar) bar.style.width = `${pct}%`;
    if (lbl) lbl.textContent = label;
  }

  // ── Recon Events ───────────────────────────────────────────────────────────
  function handleRecon(event) {
    const reconSummary = document.getElementById('recon-summary');
    switch (event.event) {
      case 'start':
        log('cyan', `🛰 ${event.message}`);
        if (reconSummary) reconSummary.style.display = 'flex';
        break;
      case 'passive_start':
      case 'brute_start':
        log('cyan', `⟳ ${event.message}`);
        break;
      case 'subdomain_found':
        log('green', `⬡ ${event.subdomain} [${event.source}]`);
        // Update subdomain count
        const subEl = document.getElementById('stat-subdomains');
        if (subEl) subEl.textContent = parseInt(subEl.textContent || '0') + 1;
        break;
      case 'live_found':
        const liveEl = document.getElementById('stat-live');
        if (liveEl) liveEl.textContent = parseInt(liveEl.textContent || '0') + 1;
        break;
      case 'dangling_cname':
        log('orange', `⚠ Dangling CNAME: ${event.domain} → ${event.cname}`);
        const cnameEl = document.getElementById('stat-cnames');
        if (cnameEl) cnameEl.textContent = parseInt(cnameEl.textContent || '0') + 1;
        break;
      case 'complete':
        log('green', `✓ ${event.message}`);
        break;
    }
  }

  function handleReconSummary(event) {
    const subEl = document.getElementById('stat-subdomains');
    const liveEl = document.getElementById('stat-live');
    const cnameEl = document.getElementById('stat-cnames');
    if (subEl) subEl.textContent = event.subdomains;
    if (liveEl) liveEl.textContent = event.live;
    if (cnameEl) cnameEl.textContent = event.dangling_cnames;

    log('cyan',
      `📊 Recon summary: ${event.subdomains} subdomains, ` +
      `${event.live} live, ${event.dangling_cnames} dangling CNAMEs`
    );
  }

  // ── Findings ───────────────────────────────────────────────────────────────
  function handleFinding(event) {
    const sevColors = {
      critical: 'red', high: 'orange', medium: 'yellow', low: 'cyan', info: 'muted'
    };
    const color = sevColors[event.severity] || 'white';
    const emoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[event.severity] || '●';

    log(color,
      `${emoji} [${event.severity.toUpperCase()}] ${event.title}\n` +
      `   ${event.url}`
    );

    // We'll get full finding data from the report panel
    App.addFinding({
      id: event.finding_id,
      scanner: event.scanner,
      severity: event.severity,
      title: event.title,
      url: event.url,
      description: '',
      evidence: null,
      remediation: null,
      ai_analysis: null,
    });
  }

  // ── AI Summary ─────────────────────────────────────────────────────────────
  function handleAISummary(event) {
    log('purple', '🤖 AI executive summary generated');
    const box = document.getElementById('ai-summary-box');
    const content = document.getElementById('ai-summary-content');
    if (box) box.style.display = 'block';
    if (content) {
      // Basic markdown → HTML (bold, code)
      content.innerHTML = event.summary
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/`(.+?)`/g, '<code style="font-family:var(--font-mono);color:var(--accent-cyan)">$1</code>')
        .replace(/\n/g, '<br>');
    }
  }

  // ── Scan Complete ──────────────────────────────────────────────────────────
  function handleComplete(event) {
    setPhase('done');
    setProgress(100, 'COMPLETE');
    log('green', `✅ Scan complete! Total findings: ${event.total_findings}`);
    App.setStatus('', 'Scan Complete');
    loadFullFindings(event.scan_id);
  }

  async function loadFullFindings(scanId) {
    try {
      const res = await fetch(`/api/scan/${scanId}/report`);
      const data = await res.json();
      // Update report panel with full finding details
      Report.refreshFromFindings(data.findings);
    } catch (e) {
      console.warn('Could not load full findings:', e);
    }
  }

  // ── Terminal Logging ───────────────────────────────────────────────────────
  function log(color, message) {
    const body = document.getElementById('terminal-body');
    if (!body) return;

    const now = new Date();
    const time = now.toTimeString().slice(0, 8);

    const line = document.createElement('div');
    line.className = 'log-line';

    const lines = message.split('\n');
    line.innerHTML =
      `<span class="log-time t-muted">${time}</span>` +
      `<span class="t-${color}">${escapeHtml(lines[0])}</span>`;

    body.appendChild(line);

    // Sub-lines (indented)
    lines.slice(1).forEach(l => {
      const sub = document.createElement('div');
      sub.className = 'log-line';
      sub.innerHTML = `<span class="log-time t-muted">       </span><span class="t-muted">${escapeHtml(l)}</span>`;
      body.appendChild(sub);
    });

    body.scrollTop = body.scrollHeight;
  }

  function logError(msg) { log('red', msg); }

  // ── Reset ──────────────────────────────────────────────────────────────────
  function reset() {
    const body = document.getElementById('terminal-body');
    if (body) body.innerHTML = '';

    // Reset phases
    PHASES.forEach(p => {
      const el = document.getElementById(`phase-${p}`);
      if (el) { el.classList.remove('active', 'done'); }
    });

    // Reset progress
    setProgress(0, 'Starting...');

    // Reset recon stats
    ['stat-subdomains', 'stat-live', 'stat-cnames'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '0';
    });

    currentPhaseIdx = -1;
    document.getElementById('btn-export-md').disabled = true;
    document.getElementById('btn-export-json').disabled = true;
    document.getElementById('ai-summary-box').style.display = 'none';
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  return { connect, disconnect, log, logError };
})();
