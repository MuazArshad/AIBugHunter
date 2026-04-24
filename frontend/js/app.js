/**
 * app.js — State management, provider selection, scanner toggles
 */

const App = (() => {
  // ── State ────────────────────────────────────────────────────────────────
  const state = {
    selectedProvider: 'gemini',
    reconMode: 'passive',
    scanId: null,
    isScanning: false,
    findings: [],
    providers: [],
  };

  // ── DOM References ────────────────────────────────────────────────────────
  const el = {
    authConfirm: document.getElementById('auth-confirm'),
    targetInput: document.getElementById('target-input'),
    scopeInput: document.getElementById('scope-input'),
    btnStart: document.getElementById('btn-start'),
    btnStop: document.getElementById('btn-stop'),
    statusDot: document.getElementById('status-dot'),
    statusText: document.getElementById('status-text'),
    providerGrid: document.getElementById('provider-grid'),
  };

  // ── Init ──────────────────────────────────────────────────────────────────
  async function init() {
    setupProviderButtons();
    setupModeButtons();
    setupAuthToggle();
    setupActionButtons();
    await loadProviderStatus();
  }

  // ── Load Provider Status ──────────────────────────────────────────────────
  async function loadProviderStatus() {
    try {
      const res = await fetch('/api/providers');
      const data = await res.json();
      state.providers = data.providers;
      data.providers.forEach(p => {
        const badge = document.getElementById(`badge-${p.id}`);
        if (badge) {
          badge.classList.toggle('configured', p.configured);
          badge.title = p.configured ? 'API key configured' : 'API key not set';
        }
      });
    } catch (e) {
      console.warn('Could not load provider status:', e);
    }
  }

  // ── Provider Selection ────────────────────────────────────────────────────
  function setupProviderButtons() {
    document.querySelectorAll('.provider-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.provider-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.selectedProvider = btn.dataset.provider;
      });
    });
  }

  // ── Recon Mode ────────────────────────────────────────────────────────────
  function setupModeButtons() {
    document.querySelectorAll('.toggle-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.reconMode = btn.dataset.mode;
      });
    });
  }

  // ── Authorization Checkbox ────────────────────────────────────────────────
  function setupAuthToggle() {
    el.authConfirm.addEventListener('change', () => {
      updateStartButton();
    });
    el.targetInput.addEventListener('input', updateStartButton);
  }

  function updateStartButton() {
    const authorized = el.authConfirm.checked;
    const hasTarget = el.targetInput.value.trim().length > 0;
    el.btnStart.disabled = !(authorized && hasTarget) || state.isScanning;
  }

  // ── Action Buttons ────────────────────────────────────────────────────────
  function setupActionButtons() {
    el.btnStart.addEventListener('click', startScan);
    el.btnStop.addEventListener('click', stopScan);
  }

  async function startScan() {
    const target = el.targetInput.value.trim();
    if (!target) return;

    // Collect enabled scanners
    const scanners = Array.from(
      document.querySelectorAll('.scanner-check input[type=checkbox]:checked')
    ).map(cb => cb.value);

    // Parse scope
    const scopeText = el.scopeInput.value.trim();

    // Create session on backend
    try {
      const res = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, provider: state.selectedProvider }),
      });
      const data = await res.json();
      state.scanId = data.scan_id;
    } catch (e) {
      Scanner.logError('Failed to create scan session: ' + e.message);
      return;
    }

    state.isScanning = true;
    state.findings = [];
    updateStartButton();
    el.btnStop.disabled = false;

    setStatus('active', 'Scanning...');

    const payload = {
      target,
      provider: state.selectedProvider,
      recon_mode: state.reconMode,
      scanners,
      scope_domains: scopeText ? scopeText.split('\n').map(s => s.trim()).filter(Boolean) : [],
      authorized: true,
    };

    // Delegate to Scanner module
    await Scanner.connect(state.scanId, payload);
  }

  async function stopScan() {
    if (!state.scanId) return;
    try {
      await fetch(`/api/scan/${state.scanId}/stop`, { method: 'POST' });
    } catch (e) { /* ignore */ }
    Scanner.disconnect();
    onScanEnd();
  }

  // ── Status Updates ────────────────────────────────────────────────────────
  function setStatus(state_, text) {
    el.statusDot.className = `status-dot ${state_}`;
    el.statusText.textContent = text;
  }

  function onScanEnd() {
    state.isScanning = false;
    el.btnStop.disabled = true;
    updateStartButton();
    setStatus('', 'Ready');
  }

  function addFinding(finding) {
    state.findings.push(finding);
    Report.addFinding(finding);
    // Update counter
    const counter = document.getElementById('finding-counter');
    counter.textContent = `${state.findings.length} finding${state.findings.length !== 1 ? 's' : ''}`;
  }

  function getState() { return state; }

  return { init, onScanEnd, addFinding, setStatus, getState, loadProviderStatus };
})();

// ── Bootstrap ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => App.init());
