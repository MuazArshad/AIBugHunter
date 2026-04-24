/**
 * report.js — Findings rendering, severity counters, modal, export
 */

const Report = (() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let allFindings = [];

  // ── Add Single Finding ─────────────────────────────────────────────────────
  function addFinding(finding) {
    // Deduplicate by id
    if (allFindings.find(f => f.id === finding.id)) return;
    allFindings.push(finding);

    // Remove empty state
    const empty = document.getElementById('findings-empty');
    if (empty) empty.style.display = 'none';

    // Update severity count
    const sev = finding.severity;
    if (counts[sev] !== undefined) {
      counts[sev]++;
      updateSeverityCount(sev);
    }

    // Render card
    renderCard(finding);
  }

  // ── Refresh from Full Data ─────────────────────────────────────────────────
  function refreshFromFindings(findings) {
    findings.forEach(f => {
      const existing = allFindings.find(e => e.id === f.id);
      if (existing) {
        // Update with full details
        Object.assign(existing, f);
      } else {
        addFinding(f);
      }
    });

    // Enable export buttons
    document.getElementById('btn-export-md').disabled = false;
    document.getElementById('btn-export-json').disabled = false;
  }

  // ── Render Card ────────────────────────────────────────────────────────────
  function renderCard(finding) {
    const list = document.getElementById('findings-list');
    if (!list) return;

    const card = document.createElement('div');
    card.className = 'finding-card';
    card.dataset.severity = finding.severity;
    card.dataset.id = finding.id;

    const badgeText = finding.severity.toUpperCase();

    card.innerHTML = `
      <div class="finding-top">
        <span class="finding-badge ${finding.severity}">${badgeText}</span>
        <span class="finding-title">${escapeHtml(finding.title)}</span>
        <span class="finding-scanner">${escapeHtml(finding.scanner)}</span>
      </div>
      <div class="finding-url">${escapeHtml(finding.url)}</div>
    `;

    card.addEventListener('click', () => openModal(finding.id));
    list.appendChild(card);
  }

  // ── Severity Counter ───────────────────────────────────────────────────────
  function updateSeverityCount(sev) {
    const el = document.getElementById(`cnt-${sev}`);
    if (el) {
      el.textContent = counts[sev];
      if (counts[sev] > 0) el.classList.add('has-findings');
    }
  }

  // ── Modal ─────────────────────────────────────────────────────────────────
  function openModal(findingId) {
    const finding = allFindings.find(f => f.id === findingId);
    if (!finding) return;

    const overlay = document.getElementById('modal-overlay');
    const titleEl = document.getElementById('modal-title');
    const sevBadge = document.getElementById('modal-severity-badge');
    const body = document.getElementById('modal-body');

    titleEl.textContent = finding.title;
    sevBadge.textContent = finding.severity.toUpperCase();
    sevBadge.className = `modal-severity finding-badge ${finding.severity}`;

    body.innerHTML = '';

    // Description
    if (finding.description) {
      const sec = modalSection('Description', `<p class="modal-text">${escapeHtml(finding.description)}</p>`);
      body.appendChild(sec);
    }

    // URL
    const urlSec = modalSection('URL',
      `<p class="modal-code">${escapeHtml(finding.url)}</p>`
    );
    body.appendChild(urlSec);

    // Scanner
    const scanSec = modalSection('Scanner',
      `<p class="modal-text">Detected by: <code style="font-family:var(--font-mono);color:var(--accent-cyan)">${escapeHtml(finding.scanner)}</code></p>`
    );
    body.appendChild(scanSec);

    // Evidence
    if (finding.evidence) {
      const evSec = modalSection('Evidence',
        `<div class="modal-code">${escapeHtml(finding.evidence)}</div>`
      );
      body.appendChild(evSec);
    }

    // Remediation
    if (finding.remediation) {
      const remSec = modalSection('Remediation',
        `<div class="modal-remediation">🛡 ${escapeHtml(finding.remediation)}</div>`
      );
      body.appendChild(remSec);
    }

    // AI Analysis
    if (finding.ai_analysis) {
      const aiSec = modalSection('AI Analysis',
        `<div class="modal-ai">🤖 ${escapeHtml(finding.ai_analysis)}</div>`
      );
      body.appendChild(aiSec);
    }

    overlay.style.display = 'flex';
  }

  function modalSection(title, content) {
    const div = document.createElement('div');
    div.innerHTML = `<div class="modal-section-title">${title}</div>${content}`;
    return div;
  }

  function closeModal() {
    document.getElementById('modal-overlay').style.display = 'none';
  }

  // ── Export ─────────────────────────────────────────────────────────────────
  function exportMarkdown() {
    if (!allFindings.length) return;
    const state = App.getState();
    const target = document.getElementById('target-input').value || 'unknown';

    let md = `# Bug Hunting Report — ${target}\n\n`;
    md += `**Provider:** ${state.selectedProvider}\n\n`;
    md += `## Summary\n\n`;
    md += `| Severity | Count |\n|----------|-------|\n`;
    Object.entries(counts).forEach(([s, c]) => {
      const emoji = { critical:'🔴', high:'🟠', medium:'🟡', low:'🔵', info:'⚪' }[s] || '';
      md += `| ${emoji} ${s.toUpperCase()} | ${c} |\n`;
    });
    md += `\n## Findings\n\n`;
    allFindings.forEach((f, i) => {
      md += `### ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
      md += `**URL:** \`${f.url}\`\n\n`;
      if (f.description) md += `${f.description}\n\n`;
      if (f.evidence) md += `**Evidence:**\n\`\`\`\n${f.evidence}\n\`\`\`\n\n`;
      if (f.remediation) md += `**Remediation:** ${f.remediation}\n\n`;
      if (f.ai_analysis) md += `**AI Analysis:** _${f.ai_analysis}_\n\n`;
      md += `---\n\n`;
    });

    download(`bugReport_${target.replace(/\./g,'_')}.md`, md, 'text/markdown');
  }

  function exportJSON() {
    const state = App.getState();
    const data = {
      target: document.getElementById('target-input').value,
      provider: state.selectedProvider,
      findings: allFindings,
      counts,
    };
    download(
      `bugReport_${data.target.replace(/\./g,'_')}.json`,
      JSON.stringify(data, null, 2),
      'application/json'
    );
  }

  function download(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Event Listeners ───────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('modal-close').addEventListener('click', closeModal);
    document.getElementById('modal-overlay').addEventListener('click', (e) => {
      if (e.target === document.getElementById('modal-overlay')) closeModal();
    });
    document.getElementById('btn-export-md').addEventListener('click', exportMarkdown);
    document.getElementById('btn-export-json').addEventListener('click', exportJSON);
    document.getElementById('btn-clear-log').addEventListener('click', () => {
      document.getElementById('terminal-body').innerHTML = '';
    });
  });

  return { addFinding, refreshFromFindings };
})();
