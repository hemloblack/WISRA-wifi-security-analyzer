const scanBtn = document.getElementById('scanBtn');
const tableBody = document.getElementById('networkTableBody');
const tableSection = document.getElementById('tableSection');
const summarySection = document.getElementById('summary');
const emptySection = document.getElementById('empty');
const errorBox = document.getElementById('errorBox');
const detailPanel = document.getElementById('detailPanel');
const closeDetailBtn = document.getElementById('closeDetail');
const currentConnectionSection = document.getElementById('currentConnection');
const currentConnectionBody = document.getElementById('currentConnectionBody');

scanBtn.addEventListener('click', runScan);
closeDetailBtn.addEventListener('click', () => detailPanel.classList.add('hidden'));

loadCurrentConnection();

async function loadCurrentConnection() {
  try {
    const res = await fetch('/api/current-connection');
    if (!res.ok) return;
    const data = await res.json();
    renderCurrentConnection(data);
  } catch (err) {
    // Non-fatal: current connection panel just stays hidden.
  }
}

function renderCurrentConnection(data) {
  if (!data.connected) {
    currentConnectionSection.classList.add('hidden');
    return;
  }
  const n = data.network;
  currentConnectionBody.innerHTML = `
    <div class="cc-row">
      <div><span class="label">SSID</span>${escapeHtml(n.ssid)}</div>
      <div><span class="label">Authentication</span>${escapeHtml(n.authentication ?? 'N/A')}</div>
      <div><span class="label">Signal</span>${n.signal_percent ?? '-'}%</div>
      <div><span class="label">Band</span>${escapeHtml(n.band ?? 'N/A')}</div>
      <div><span class="label">Channel</span>${n.channel ?? 'N/A'}</div>
    </div>
  `;
  currentConnectionSection.classList.remove('hidden');
}

async function runScan() {
  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning...';
  errorBox.classList.add('hidden');
  try {
    const res = await fetch('/api/scan', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Scan request failed');
    }
    renderResults(data.networks);
    loadCurrentConnection();
  } catch (err) {
    showError(err.message);
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan Networks';
  }
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove('hidden');
}

function renderResults(networks) {
  if (!networks.length) {
    emptySection.classList.remove('hidden');
    tableSection.classList.add('hidden');
    summarySection.classList.add('hidden');
    return;
  }

  emptySection.classList.add('hidden');
  tableSection.classList.remove('hidden');
  summarySection.classList.remove('hidden');

  const counts = { VERY_LOW: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  tableBody.innerHTML = '';

  networks.forEach(net => {
    counts[net.risk_level] = (counts[net.risk_level] || 0) + 1;

    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${escapeHtml(net.ssid)}${net.connected ? ' 🔗' : ''}${net.anomaly ? ' ⚠️' : ''}</td>
      <td>${escapeHtml(net.authentication || 'N/A')}</td>
      <td>${net.signal_percent ?? '-'}%</td>
      <td>${net.band ?? 'N/A'}</td>
      <td>${net.risk_score.toFixed(1)} / 100</td>
      <td><span class="badge badge-${net.risk_level}">${net.risk_level.replace('_',' ')}</span></td>
    `;
    row.addEventListener('click', () => showDetail(net));
    tableBody.appendChild(row);
  });

  document.getElementById('statTotal').textContent = networks.length;
  document.getElementById('statVeryLow').textContent = counts.VERY_LOW;
  document.getElementById('statLow').textContent = counts.LOW;
  document.getElementById('statMedium').textContent = counts.MEDIUM;
  document.getElementById('statHigh').textContent = counts.HIGH;
  document.getElementById('statCritical').textContent = counts.CRITICAL;
}

function showDetail(net) {
  document.getElementById('detailSsid').textContent = net.ssid;
  document.getElementById('detailBssid').textContent = net.bssid;
  const scoreEl = document.getElementById('detailScore');
  scoreEl.textContent = `${net.risk_score.toFixed(1)} / 100 — ${net.risk_level.replace('_',' ')}`;
  scoreEl.style.color = colorForLevel(net.risk_level);

  const list = document.getElementById('detailReasons');
  list.innerHTML = '';
  (net.reasons || []).forEach(reason => {
    const li = document.createElement('li');
    li.textContent = reason;
    list.appendChild(li);
  });

  detailPanel.classList.remove('hidden');
}

function colorForLevel(level) {
  return {
    VERY_LOW: '#38c172',
    LOW: '#7ed957',
    MEDIUM: '#f6c343',
    HIGH: '#ef5b5b',
    CRITICAL: '#c34fd6',
  }[level] || '#e6ecf5';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}
