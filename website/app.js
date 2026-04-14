/* =====================================================
   DIGITAL SIGNATURE SYSTEM — app.js
   ===================================================== */

// ============================================================
//  STATE
// ============================================================
const State = {
  generatedKeys: { private: null, public: null, algo: null, label: null },
  signatureData:  null,
  signedFileName: null,
  files:  {},        // key → File object
  pems:   {},        // key → PEM string
  sigJson: null,     // loaded .sig JSON
  auditLog: [],
  stats: { ops: 0, signs: 0, valid: 0, invalid: 0 }
};


// ============================================================
//  NAVIGATION
// ============================================================
document.querySelectorAll('nav a').forEach(link => {
  link.addEventListener('click', () => {
    const tab = link.dataset.tab;
    document.querySelectorAll('nav a').forEach(l => l.classList.remove('active'));
    link.classList.add('active');
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById('tab-' + tab).classList.add('active');
  });
});


// ============================================================
//  PEM HELPERS
// ============================================================
function arrayBufferToPEM(buffer, type) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = btoa(binary);
  const lines = base64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
}

function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace(/-----BEGIN[^-]+-----/, '')
    .replace(/-----END[^-]+-----/, '')
    .replace(/\s+/g, '');
  const binary = atob(base64);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}


// ============================================================
//  HASH HELPER
// ============================================================
async function hashFileBuffer(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}


// ============================================================
//  FILE / PEM / SIG HANDLERS
// ============================================================
function handleFileSelect(key, input) {
  const file = input.files[0];
  if (!file) return;
  State.files[key] = file;
  document.getElementById(key + '-name').textContent = `📄 ${file.name} (${formatBytes(file.size)})`;

  if (key === 'sign-file') {
    const info = document.getElementById('sign-file-info');
    info.style.display = 'block';
    info.textContent = `File: ${file.name} | Size: ${formatBytes(file.size)} | Type: ${file.type || 'unknown'}`;
  }
}

function handlePEMSelect(key, input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    const pem = e.target.result;
    State.pems[key] = pem;
    document.getElementById(key + '-name').textContent = `🔑 ${file.name}`;
    const pasteEl = document.getElementById(key + '-paste');
    if (pasteEl) pasteEl.value = pem;
  };
  reader.readAsText(file);
}

function handleSigSelect(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    try {
      State.sigJson = JSON.parse(e.target.result);
      document.getElementById('ver-sig-name').textContent = `🔏 ${file.name} — loaded OK`;
    } catch {
      document.getElementById('ver-sig-name').textContent = `❌ Invalid JSON`;
    }
  };
  reader.readAsText(file);
}


// ============================================================
//  TAB 1 — KEY GENERATION
// ============================================================
function toggleKeySize() {
  const algo = document.querySelector('input[name="kg-algo"]:checked').value;
  document.getElementById('rsa-size-row').style.display = algo === 'RSA' ? '' : 'none';
}

async function generateKeys() {
  const algo  = document.querySelector('input[name="kg-algo"]:checked').value;
  const label = document.getElementById('kg-label').value || 'my-key';
  const btn   = document.getElementById('kg-btn');

  btn.disabled = true;
  document.getElementById('kg-btn-icon').innerHTML =
    '<span class="spinner" style="width:14px;height:14px;border-width:2px"></span>';

  hideEl('kg-empty');
  hideEl('kg-priv-section');
  hideEl('kg-pub-section');
  hideEl('kg-sep');

  try {
    let keyPair;

    if (algo === 'RSA') {
      const keySize = parseInt(document.querySelector('input[name="rsa-size"]:checked').value);
      keyPair = await crypto.subtle.generateKey(
        { name: 'RSA-PSS', modulusLength: keySize, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
        true, ['sign', 'verify']
      );
    } else {
      keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, ['sign', 'verify']
      );
    }

    const privBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const pubBuffer  = await crypto.subtle.exportKey('spki',  keyPair.publicKey);
    const privPEM    = arrayBufferToPEM(privBuffer, 'PRIVATE KEY');
    const pubPEM     = arrayBufferToPEM(pubBuffer,  'PUBLIC KEY');

    State.generatedKeys = { private: privPEM, public: pubPEM, algo, label };

    // Show previews
    const privPrev = document.getElementById('kg-priv-preview');
    const pubPrev  = document.getElementById('kg-pub-preview');
    privPrev.textContent = privPEM;
    pubPrev.textContent  = pubPEM;
    privPrev.style.display = 'block';
    pubPrev.style.display  = 'block';

    showEl('kg-priv-section');
    showEl('kg-sep');
    showEl('kg-pub-section');

    const sizeLabel = algo === 'RSA'
      ? `RSA-PSS ${document.querySelector('input[name="rsa-size"]:checked').value}-bit`
      : 'ECDSA P-256';

    setResult('kg-result',
      `✅ ${sizeLabel} key pair generated!\nLabel: ${label}\nPrivate: ${label}_private.pem\nPublic:  ${label}_public.pem`,
      'success'
    );

    addAuditEntry('Key Generation', `${label}_keypair`, 'Success', `Algorithm: ${algo}`);
    showToast(`✅ ${algo} key pair generated`, 'success');

  } catch (err) {
    setResult('kg-result', `❌ Key generation failed:\n${err.message}`, 'error');
    showEl('kg-empty');
    addAuditEntry('Key Generation', 'keypair', 'Failed', err.message);
  }

  btn.disabled = false;
  document.getElementById('kg-btn-icon').textContent = '⚡';
}

function downloadKey(type) {
  if (!State.generatedKeys[type]) return;
  const label = State.generatedKeys.label;
  downloadText(State.generatedKeys[type], `${label}_${type}.pem`, 'application/x-pem-file');
}

function copyKey(type) {
  if (!State.generatedKeys[type]) return;
  navigator.clipboard.writeText(State.generatedKeys[type]);
  showToast('Copied to clipboard!', 'success');
}


// ============================================================
//  TAB 2 — SIGN DOCUMENT
// ============================================================
async function doSign() {
  const fileObj = State.files['sign-file'];
  const algo    = document.querySelector('input[name="sign-algo"]:checked').value;
  const signer  = document.getElementById('sign-signer').value || 'Unknown';
  const privPEM = document.getElementById('sign-key-paste').value.trim()
                  || State.pems['sign-key'];

  if (!fileObj) { showToast('Please select a file to sign', 'error'); return; }
  if (!privPEM) { showToast('Please provide a private key', 'error'); return; }

  const btn = document.getElementById('sign-btn');
  btn.disabled = true;
  document.getElementById('sign-btn-icon').innerHTML =
    '<span class="spinner" style="width:14px;height:14px;border-width:2px"></span>';
  hideEl('sign-download');

  try {
    const fileBuffer  = await fileObj.arrayBuffer();
    const fileHash    = await hashFileBuffer(fileBuffer);
    const privBuffer  = pemToArrayBuffer(privPEM);

    let privateKey, signature;

    if (algo === 'RSA') {
      privateKey = await crypto.subtle.importKey(
        'pkcs8', privBuffer,
        { name: 'RSA-PSS', hash: 'SHA-256' },
        false, ['sign']
      );
      signature = await crypto.subtle.sign(
        { name: 'RSA-PSS', saltLength: 32 },
        privateKey, fileBuffer
      );
    } else {
      privateKey = await crypto.subtle.importKey(
        'pkcs8', privBuffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, ['sign']
      );
      signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey, fileBuffer
      );
    }

    const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

    State.signatureData = {
      signer,
      file:      fileObj.name,
      file_hash: fileHash,
      algorithm: algo,
      timestamp: new Date().toISOString(),
      signature: sigBase64
    };
    State.signedFileName = fileObj.name;

    setResult('sign-result',
      `✅ File signed successfully!\n\nSigner:    ${signer}\nAlgorithm: ${algo}\nFile Hash: ${fileHash.substring(0, 20)}...\nTimestamp: ${State.signatureData.timestamp}\nSig size:  ${Math.round(signature.byteLength / 1.33)} bytes (base64)`,
      'success'
    );

    showEl('sign-download');
    addAuditEntry('Sign File', fileObj.name, 'Success', `Algorithm: ${algo}, Signer: ${signer}`);
    showToast(`✅ ${fileObj.name} signed`, 'success');

  } catch (err) {
    setResult('sign-result',
      `❌ Signing failed:\n${err.message}\n\nMake sure the key matches the selected algorithm.`,
      'error'
    );
    addAuditEntry('Sign File', fileObj?.name || 'unknown', 'Failed', err.message);
  }

  btn.disabled = false;
  document.getElementById('sign-btn-icon').textContent = '✍️';
}

function downloadSig() {
  if (!State.signatureData) return;
  downloadText(
    JSON.stringify(State.signatureData, null, 2),
    `${State.signedFileName}.sig`,
    'application/json'
  );
}


// ============================================================
//  TAB 3 — VERIFY DOCUMENT
// ============================================================
async function doVerify(tamperDemo) {
  const fileObj = State.files['ver-file'];
  const sigJson = State.sigJson;
  const pubPEM  = document.getElementById('ver-key-paste').value.trim()
                  || State.pems['ver-key'];

  if (!fileObj) { showToast('Please select the original file', 'error'); return; }
  if (!sigJson)  { showToast('Please upload a .sig file', 'error'); return; }
  if (!pubPEM)   { showToast('Please provide a public key', 'error'); return; }

  const verBtn  = document.getElementById('ver-btn');
  const tamBtn  = document.getElementById('tamper-btn');
  verBtn.disabled = tamBtn.disabled = true;

  hideEl('ver-placeholder');
  const statusBox = document.getElementById('ver-status-box');
  statusBox.style.display = 'block';
  statusBox.style.borderColor = 'var(--border)';
  document.getElementById('ver-icon').textContent  = '⏳';
  document.getElementById('ver-label').textContent = 'VERIFYING...';
  document.getElementById('ver-label').style.color = 'var(--muted)';
  document.getElementById('ver-msg').textContent   = '';
  document.getElementById('ver-details').innerHTML = '';

  try {
    let fileBuffer = await fileObj.arrayBuffer();

    if (tamperDemo) {
      const original    = new Uint8Array(fileBuffer);
      const tamperBytes = new TextEncoder().encode(' [TAMPERED]');
      const combined    = new Uint8Array(original.length + tamperBytes.length);
      combined.set(original);
      combined.set(tamperBytes, original.length);
      fileBuffer = combined.buffer;
    }

    const currentHash  = await hashFileBuffer(fileBuffer);
    const originalHash = sigJson.file_hash;
    const hashMatch    = currentHash === originalHash;
    const algo         = sigJson.algorithm;
    const pubBuffer    = pemToArrayBuffer(pubPEM);
    const sigBytes     = Uint8Array.from(atob(sigJson.signature), c => c.charCodeAt(0));

    let cryptoValid = false;

    try {
      // Always verify against original data (sig was created on original)
      const origBuffer = tamperDemo ? await fileObj.arrayBuffer() : fileBuffer;

      if (algo === 'RSA') {
        const pubKey = await crypto.subtle.importKey(
          'spki', pubBuffer,
          { name: 'RSA-PSS', hash: 'SHA-256' },
          false, ['verify']
        );
        cryptoValid = await crypto.subtle.verify(
          { name: 'RSA-PSS', saltLength: 32 },
          pubKey, sigBytes, origBuffer
        );
      } else {
        const pubKey = await crypto.subtle.importKey(
          'spki', pubBuffer,
          { name: 'ECDSA', namedCurve: 'P-256' },
          false, ['verify']
        );
        cryptoValid = await crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          pubKey, sigBytes, origBuffer
        );
      }
    } catch {
      cryptoValid = false;
    }

    const valid   = cryptoValid && hashMatch;
    const message = tamperDemo
      ? 'Tampered file detected — hash mismatch!'
      : valid
        ? 'Signature cryptographically valid'
        : cryptoValid
          ? 'Hash mismatch — file was modified after signing'
          : 'Cryptographic verification failed';

    if (valid) {
      document.getElementById('ver-icon').textContent  = '✅';
      document.getElementById('ver-label').textContent = 'SIGNATURE VALID';
      document.getElementById('ver-label').style.color = 'var(--success)';
      statusBox.style.borderColor = 'rgba(0,230,118,0.3)';
    } else {
      document.getElementById('ver-icon').textContent  = '❌';
      document.getElementById('ver-label').textContent = tamperDemo ? 'TAMPERING DETECTED' : 'SIGNATURE INVALID';
      document.getElementById('ver-label').style.color = tamperDemo ? 'var(--warning)' : 'var(--danger)';
      statusBox.style.borderColor = tamperDemo ? 'rgba(255,179,0,0.3)' : 'rgba(255,59,92,0.3)';
    }

    document.getElementById('ver-msg').textContent = message;
    document.getElementById('ver-details').innerHTML = `
      <div class="detail-row"><span class="detail-key">Signer:</span>
        <span class="detail-val">${sigJson.signer || 'N/A'}</span></div>
      <div class="detail-row"><span class="detail-key">Algorithm:</span>
        <span class="detail-val">${algo}</span></div>
      <div class="detail-row"><span class="detail-key">Signed On:</span>
        <span class="detail-val">${sigJson.timestamp || 'N/A'}</span></div>
      <div class="detail-row"><span class="detail-key">Original Hash:</span>
        <span class="detail-val">${originalHash}</span></div>
      <div class="detail-row"><span class="detail-key">Current Hash:</span>
        <span class="detail-val" style="color:${hashMatch ? 'var(--success)' : 'var(--danger)'}">
          ${currentHash}</span></div>
      <div class="detail-row"><span class="detail-key">Hash Match:</span>
        <span class="detail-val" style="color:${hashMatch ? 'var(--success)' : 'var(--danger)'}">
          ${hashMatch ? '✓ YES' : '✗ NO'}</span></div>
      <div class="detail-row"><span class="detail-key">Crypto Valid:</span>
        <span class="detail-val" style="color:${cryptoValid ? 'var(--success)' : 'var(--danger)'}">
          ${cryptoValid ? '✓ YES' : '✗ NO'}</span></div>
      ${tamperDemo ? '<div class="detail-row" style="margin-top:8px;color:var(--warning)">⚠ DEMO: A temp copy was tampered. Your original file was NOT changed.</div>' : ''}
    `;

    const logRes = valid ? 'Valid' : 'Invalid';
    addAuditEntry(
      tamperDemo ? 'Tamper Demo' : 'Verify File',
      fileObj.name, logRes,
      `Algorithm: ${algo}, Signer: ${sigJson.signer}`
    );

  } catch (err) {
    document.getElementById('ver-icon').textContent  = '💥';
    document.getElementById('ver-label').textContent = 'VERIFICATION ERROR';
    document.getElementById('ver-label').style.color = 'var(--danger)';
    document.getElementById('ver-msg').textContent   = err.message;
    addAuditEntry('Verify File', fileObj?.name || 'unknown', 'Error', err.message);
  }

  verBtn.disabled = tamBtn.disabled = false;
}


// ============================================================
//  TAB 4 — PERFORMANCE BENCHMARK
// ============================================================
async function runBenchmark() {
  const btn   = document.getElementById('perf-btn');
  const iters = parseInt(document.getElementById('perf-iters').value);

  btn.disabled = true;
  document.getElementById('perf-btn-icon').innerHTML =
    '<span class="spinner" style="width:14px;height:14px;border-width:2px"></span>';

  showEl('perf-progress');
  document.getElementById('perf-stats').style.display = 'none';

  // Use uploaded file or generate 32KB random data
  let testData;
  if (State.files['perf-file']) {
    testData = await State.files['perf-file'].arrayBuffer();
  } else {
    const buf = new Uint8Array(32768);
    crypto.getRandomValues(buf);
    testData = buf.buffer;
  }

  const avgMs = async (fn, n) => {
    const times = [];
    for (let i = 0; i < n; i++) {
      const t0 = performance.now();
      await fn();
      times.push(performance.now() - t0);
    }
    return times.reduce((a, b) => a + b, 0) / times.length;
  };

  const m = { RSA: {}, ECDSA: {} };

  const setProgress = text => {
    document.getElementById('perf-progress-text').textContent = text;
  };

  try {
    // RSA Key Generation
    setProgress('RSA — key generation...');
    let rsaKP;
    m.RSA.keygen = await avgMs(async () => {
      rsaKP = await crypto.subtle.generateKey(
        { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
        true, ['sign', 'verify']
      );
    }, iters);

    // RSA Sign
    setProgress('RSA — signing...');
    let rsaSig;
    m.RSA.sign = await avgMs(async () => {
      rsaSig = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, rsaKP.privateKey, testData);
    }, iters);

    // RSA Verify
    setProgress('RSA — verification...');
    m.RSA.verify = await avgMs(async () => {
      await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, rsaKP.publicKey, rsaSig, testData);
    }, iters);

    const rsaPrivBuf = await crypto.subtle.exportKey('pkcs8', rsaKP.privateKey);
    const rsaPubBuf  = await crypto.subtle.exportKey('spki',  rsaKP.publicKey);
    m.RSA.privSize = rsaPrivBuf.byteLength;
    m.RSA.pubSize  = rsaPubBuf.byteLength;
    m.RSA.sigSize  = rsaSig.byteLength;

    // ECDSA Key Generation
    setProgress('ECDSA — key generation...');
    let ecKP;
    m.ECDSA.keygen = await avgMs(async () => {
      ecKP = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, ['sign', 'verify']
      );
    }, iters);

    // ECDSA Sign
    setProgress('ECDSA — signing...');
    let ecSig;
    m.ECDSA.sign = await avgMs(async () => {
      ecSig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, ecKP.privateKey, testData);
    }, iters);

    // ECDSA Verify
    setProgress('ECDSA — verification...');
    m.ECDSA.verify = await avgMs(async () => {
      await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, ecKP.publicKey, ecSig, testData);
    }, iters);

    const ecPrivBuf = await crypto.subtle.exportKey('pkcs8', ecKP.privateKey);
    const ecPubBuf  = await crypto.subtle.exportKey('spki',  ecKP.publicKey);
    m.ECDSA.privSize = ecPrivBuf.byteLength;
    m.ECDSA.pubSize  = ecPubBuf.byteLength;
    m.ECDSA.sigSize  = ecSig.byteLength;

    hideEl('perf-progress');
    renderBenchmarkTable(m);

    document.getElementById('stat-rsa-keygen').textContent   = m.RSA.keygen.toFixed(1);
    document.getElementById('stat-ecdsa-keygen').textContent = m.ECDSA.keygen.toFixed(1);
    document.getElementById('stat-rsa-sign').textContent     = m.RSA.sign.toFixed(1);
    document.getElementById('stat-ecdsa-sign').textContent   = m.ECDSA.sign.toFixed(1);
    document.getElementById('perf-stats').style.display = 'flex';
    showEl('perf-note');

    addAuditEntry('Benchmark', 'RSA vs ECDSA', 'Complete',
      `${iters} iteration(s), ${formatBytes(testData.byteLength)} test data`);
    showToast('✅ Benchmark complete', 'success');

  } catch (err) {
    hideEl('perf-progress');
    showToast('Benchmark failed: ' + err.message, 'error');
    console.error(err);
  }

  btn.disabled = false;
  document.getElementById('perf-btn-icon').textContent = '⚡';
}

function renderBenchmarkTable(m) {
  const tbody = document.getElementById('perf-tbody');

  const rows = [
    ['Key Generation Time', m.RSA.keygen.toFixed(2)+' ms', m.ECDSA.keygen.toFixed(2)+' ms', m.RSA.keygen,  m.ECDSA.keygen],
    ['Signing Time',        m.RSA.sign.toFixed(2)+' ms',   m.ECDSA.sign.toFixed(2)+' ms',   m.RSA.sign,    m.ECDSA.sign],
    ['Verification Time',   m.RSA.verify.toFixed(2)+' ms', m.ECDSA.verify.toFixed(2)+' ms', m.RSA.verify,  m.ECDSA.verify],
    ['Private Key Size',    formatBytes(m.RSA.privSize),   formatBytes(m.ECDSA.privSize),   m.RSA.privSize, m.ECDSA.privSize],
    ['Public Key Size',     formatBytes(m.RSA.pubSize),    formatBytes(m.ECDSA.pubSize),    m.RSA.pubSize,  m.ECDSA.pubSize],
    ['Signature Size',      formatBytes(m.RSA.sigSize),    formatBytes(m.ECDSA.sigSize),    m.RSA.sigSize,  m.ECDSA.sigSize],
  ];

  const maxVals = rows.map(r => Math.max(r[3], r[4]));

  tbody.innerHTML = rows.map((r, i) => {
    const max  = maxVals[i];
    const rsaW = max > 0 ? Math.round((r[3] / max) * 120) : 60;
    const ecW  = max > 0 ? Math.round((r[4] / max) * 120) : 60;
    const winner = r[4] < r[3] ? 'ECDSA' : 'RSA';
    const chip = winner === 'ECDSA'
      ? '<span class="chip chip-ecdsa">ECDSA</span>'
      : '<span class="chip chip-rsa">RSA</span>';

    return `<tr>
      <td class="metric-name">${r[0]}</td>
      <td class="rsa-val">
        <div class="bar-wrap">
          <span style="min-width:80px">${r[1]}</span>
          <div class="bar bar-rsa" style="width:${rsaW}px"></div>
        </div>
      </td>
      <td class="ecdsa-val">
        <div class="bar-wrap">
          <span style="min-width:80px">${r[2]}</span>
          <div class="bar bar-ecdsa" style="width:${ecW}px"></div>
        </div>
      </td>
      <td>${chip}</td>
    </tr>`;
  }).join('');
}


// ============================================================
//  TAB 5 — AUDIT LOG
// ============================================================
function addAuditEntry(action, filename, result, extra) {
  const now = new Date();
  const ts  = now.toLocaleTimeString('en-US', { hour12: false }) +
              '.' + String(now.getMilliseconds()).padStart(3, '0');

  State.auditLog.unshift({ ts, action, filename, result, extra });

  // Stats
  State.stats.ops++;
  if (action.includes('Sign'))                                       State.stats.signs++;
  if (['Valid','Success','Complete'].includes(result))               State.stats.valid++;
  if (['Invalid','Failed','Error'].includes(result))                 State.stats.invalid++;

  // Badge
  document.getElementById('log-count').textContent = State.auditLog.length;

  // Stat counters
  document.getElementById('total-ops').textContent     = State.stats.ops;
  document.getElementById('total-signs').textContent   = State.stats.signs;
  document.getElementById('total-valid').textContent   = State.stats.valid;
  document.getElementById('total-invalid').textContent = State.stats.invalid;

  renderAuditLog();
}

function renderAuditLog() {
  const terminal = document.getElementById('audit-terminal');
  const empty    = document.getElementById('audit-empty');

  if (State.auditLog.length === 0) {
    if (empty) empty.style.display = 'block';
    return;
  }
  if (empty) empty.style.display = 'none';

  terminal.innerHTML = State.auditLog.map(e => {
    const ok = ['Valid','Success','Complete'].includes(e.result);
    const resClass = ok ? 'log-res-success' : 'log-res-invalid';
    return `<div class="log-entry">
      <span class="log-ts">[${e.ts}]</span>
      <span class="log-action">${e.action.toUpperCase()}</span>
      <span class="log-file">${e.filename}</span>
      <span class="${resClass}">[ ${e.result} ]</span>
      <span class="log-extra">${e.extra}</span>
    </div>`;
  }).join('');
}

function clearLog() {
  State.auditLog = [];
  State.stats    = { ops: 0, signs: 0, valid: 0, invalid: 0 };
  document.getElementById('log-count').textContent     = '0';
  document.getElementById('total-ops').textContent     = '0';
  document.getElementById('total-signs').textContent   = '0';
  document.getElementById('total-valid').textContent   = '0';
  document.getElementById('total-invalid').textContent = '0';
  document.getElementById('audit-terminal').innerHTML  =
    '<div class="terminal-empty" id="audit-empty">[ Log cleared ]</div>';
  showToast('Log cleared', 'success');
}

function exportLog() {
  if (State.auditLog.length === 0) { showToast('No entries to export', 'error'); return; }
  downloadText(JSON.stringify(State.auditLog, null, 2), 'audit_log.json', 'application/json');
}


// ============================================================
//  UTILITY FUNCTIONS
// ============================================================
function formatBytes(bytes) {
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
  if (bytes >= 1024)    return (bytes / 1024).toFixed(2) + ' KB';
  return bytes + ' B';
}

function downloadText(text, filename, mime) {
  const blob = new Blob([text], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
}

function setResult(id, text, type) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className   = 'result-box visible ' + type;
}

function showEl(id) { document.getElementById(id).style.display = ''; }
function hideEl(id) { document.getElementById(id).style.display = 'none'; }

let toastTimer;
function showToast(msg, type) {
  const t    = document.getElementById('toast');
  t.textContent = msg;
  t.className   = 'show ' + (type || 'info');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3000);
}


// ============================================================
//  DRAG & DROP ENHANCEMENT
// ============================================================
document.querySelectorAll('.drop-zone').forEach(zone => {
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', ()  => zone.classList.remove('dragover'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('dragover');
    const fileInput = zone.querySelector('input[type="file"]');
    if (fileInput && e.dataTransfer.files[0]) {
      const dt = new DataTransfer();
      dt.items.add(e.dataTransfer.files[0]);
      fileInput.files = dt.files;
      fileInput.dispatchEvent(new Event('change'));
    }
  });
});


// ============================================================
//  INIT
// ============================================================
toggleKeySize();