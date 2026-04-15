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
  files:   {},
  pems:    {},
  sigJson: null,
  auditLog: [],
  stats: { ops: 0, signs: 0, valid: 0, invalid: 0 }
};


// ============================================================
//  SIDEBAR — Desktop collapse / Mobile drawer
// ============================================================
const sidebar    = document.getElementById('sidebar');
const mainEl     = document.getElementById('main');
const overlay    = document.getElementById('overlay');
const hamburger  = document.getElementById('hamburger');
const sideToggle = document.getElementById('sidebar-toggle');

const isMobile = () => window.innerWidth <= 768;

/* Desktop: collapse/expand */
function toggleSidebarDesktop() {
  sidebar.classList.toggle('collapsed');
  mainEl.classList.toggle('collapsed');
  saveSidebarPref();
}

/* Mobile: open/close drawer */
function openMobileDrawer() {
  sidebar.classList.add('mobile-open');
  overlay.classList.add('visible');
  hamburger.classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeMobileDrawer() {
  sidebar.classList.remove('mobile-open');
  overlay.classList.remove('visible');
  hamburger.classList.remove('open');
  document.body.style.overflow = '';
}

function saveSidebarPref() {
  try { localStorage.setItem('dss-sidebar-collapsed', sidebar.classList.contains('collapsed')); } catch {}
}
function loadSidebarPref() {
  try {
    const c = localStorage.getItem('dss-sidebar-collapsed');
    if (c === 'true' && !isMobile()) {
      sidebar.classList.add('collapsed');
      mainEl.classList.add('collapsed');
    }
  } catch {}
}

/* Toggle button inside sidebar (desktop) */
if (sideToggle) sideToggle.addEventListener('click', toggleSidebarDesktop);

/* Hamburger (mobile) */
hamburger.addEventListener('click', () => {
  if (isMobile()) {
    sidebar.classList.contains('mobile-open') ? closeMobileDrawer() : openMobileDrawer();
  } else {
    toggleSidebarDesktop();
  }
});

/* Overlay click = close drawer */
overlay.addEventListener('click', closeMobileDrawer);

/* Close drawer on nav click (mobile) */
document.querySelectorAll('nav a').forEach(link => {
  link.addEventListener('click', () => { if (isMobile()) closeMobileDrawer(); });
});

/* Re-apply on resize */
window.addEventListener('resize', () => {
  if (!isMobile()) {
    closeMobileDrawer();
    document.body.style.overflow = '';
  }
});

loadSidebarPref();


// ============================================================
//  NAVIGATION  (sidebar links + bottom nav)
// ============================================================
function switchTab(tab) {
  document.querySelectorAll('nav a').forEach(l => l.classList.remove('active'));
  document.querySelectorAll('.bn-item').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));

  const link = document.querySelector(`nav a[data-tab="${tab}"]`);
  if (link) link.classList.add('active');
  const bn = document.querySelector(`.bn-item[data-tab="${tab}"]`);
  if (bn) bn.classList.add('active');
  const sec = document.getElementById(`tab-${tab}`);
  if (sec) sec.classList.add('active');
}

document.querySelectorAll('nav a[data-tab]').forEach(link => {
  link.addEventListener('click', () => switchTab(link.dataset.tab));
});

document.querySelectorAll('.bn-item[data-tab]').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
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
  const h = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2,'0')).join('');
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
    if (info) { info.style.display = 'block'; info.textContent = `${file.name} · ${formatBytes(file.size)} · ${file.type || 'unknown'}`; }
  }
}

function handlePEMSelect(key, input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    State.pems[key] = e.target.result;
    document.getElementById(key + '-name').textContent = `🔑 ${file.name}`;
    const paste = document.getElementById(key + '-paste');
    if (paste) paste.value = e.target.result;
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
      document.getElementById('ver-sig-name').textContent = `🔏 ${file.name} ✓`;
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
  document.getElementById('kg-btn-icon').innerHTML = '<span class="spinner" style="width:13px;height:13px;border-width:2px"></span>';
  hideEl('kg-empty'); hideEl('kg-priv-section'); hideEl('kg-pub-section'); hideEl('kg-sep');

  try {
    let keyPair;
    if (algo === 'RSA') {
      const sz = parseInt(document.querySelector('input[name="rsa-size"]:checked').value);
      keyPair = await crypto.subtle.generateKey(
        { name:'RSA-PSS', modulusLength:sz, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' },
        true, ['sign','verify']
      );
    } else {
      keyPair = await crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']);
    }

    const privBuf = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const pubBuf  = await crypto.subtle.exportKey('spki',  keyPair.publicKey);
    const privPEM = arrayBufferToPEM(privBuf, 'PRIVATE KEY');
    const pubPEM  = arrayBufferToPEM(pubBuf,  'PUBLIC KEY');

    State.generatedKeys = { private: privPEM, public: pubPEM, algo, label };

    const pp = document.getElementById('kg-priv-preview');
    const qp = document.getElementById('kg-pub-preview');
    pp.textContent = privPEM; pp.style.display = 'block';
    qp.textContent = pubPEM;  qp.style.display = 'block';

    showEl('kg-priv-section'); showEl('kg-sep'); showEl('kg-pub-section');

    const lbl = algo === 'RSA'
      ? `RSA-PSS ${document.querySelector('input[name="rsa-size"]:checked').value}-bit`
      : 'ECDSA P-256';
    setResult('kg-result', `✅ ${lbl} key pair generated!\nLabel: ${label}\nPrivate: ${label}_private.pem\nPublic:  ${label}_public.pem`, 'success');
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
  downloadText(State.generatedKeys[type], `${State.generatedKeys.label}_${type}.pem`, 'application/x-pem-file');
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
  const privPEM = document.getElementById('sign-key-paste').value.trim() || State.pems['sign-key'];

  if (!fileObj) { showToast('Please select a file to sign', 'error'); return; }
  if (!privPEM) { showToast('Please provide a private key', 'error'); return; }

  const btn = document.getElementById('sign-btn');
  btn.disabled = true;
  document.getElementById('sign-btn-icon').innerHTML = '<span class="spinner" style="width:13px;height:13px;border-width:2px"></span>';
  hideEl('sign-download');

  try {
    const fileBuf  = await fileObj.arrayBuffer();
    const fileHash = await hashFileBuffer(fileBuf);
    const privBuf  = pemToArrayBuffer(privPEM);
    let privateKey, signature;

    if (algo === 'RSA') {
      privateKey = await crypto.subtle.importKey('pkcs8', privBuf, { name:'RSA-PSS', hash:'SHA-256' }, false, ['sign']);
      signature  = await crypto.subtle.sign({ name:'RSA-PSS', saltLength:32 }, privateKey, fileBuf);
    } else {
      privateKey = await crypto.subtle.importKey('pkcs8', privBuf, { name:'ECDSA', namedCurve:'P-256' }, false, ['sign']);
      signature  = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, privateKey, fileBuf);
    }

    const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
    State.signatureData = {
      signer, file: fileObj.name, file_hash: fileHash,
      algorithm: algo, timestamp: new Date().toISOString(), signature: sigBase64
    };
    State.signedFileName = fileObj.name;

    setResult('sign-result',
      `✅ Signed successfully!\n\nSigner:    ${signer}\nAlgorithm: ${algo}\nFile Hash: ${fileHash.substring(0,20)}...\nTimestamp: ${State.signatureData.timestamp}`,
      'success'
    );
    showEl('sign-download');
    addAuditEntry('Sign File', fileObj.name, 'Success', `Algorithm: ${algo}, Signer: ${signer}`);
    showToast(`✅ ${fileObj.name} signed`, 'success');

  } catch (err) {
    setResult('sign-result', `❌ Signing failed:\n${err.message}\n\nKey must match the selected algorithm.`, 'error');
    addAuditEntry('Sign File', fileObj?.name || 'unknown', 'Failed', err.message);
  }
  btn.disabled = false;
  document.getElementById('sign-btn-icon').textContent = '✍️';
}

function downloadSig() {
  if (!State.signatureData) return;
  downloadText(JSON.stringify(State.signatureData, null, 2), `${State.signedFileName}.sig`, 'application/json');
}


// ============================================================
//  TAB 3 — VERIFY DOCUMENT
// ============================================================
async function doVerify(tamperDemo) {
  const fileObj = State.files['ver-file'];
  const sigJson = State.sigJson;
  const pubPEM  = document.getElementById('ver-key-paste').value.trim() || State.pems['ver-key'];

  if (!fileObj) { showToast('Please select the original file', 'error'); return; }
  if (!sigJson)  { showToast('Please upload a .sig file', 'error'); return; }
  if (!pubPEM)   { showToast('Please provide a public key', 'error'); return; }

  const verBtn = document.getElementById('ver-btn');
  const tamBtn = document.getElementById('tamper-btn');
  verBtn.disabled = tamBtn.disabled = true;

  hideEl('ver-placeholder');
  const box = document.getElementById('ver-status-box');
  box.style.display = 'block'; box.style.borderColor = 'var(--border)';
  document.getElementById('ver-icon').textContent  = '⏳';
  document.getElementById('ver-label').textContent = 'VERIFYING...';
  document.getElementById('ver-label').style.color = 'var(--muted)';
  document.getElementById('ver-msg').textContent   = '';
  document.getElementById('ver-details').innerHTML = '';

  try {
    let fileBuf = await fileObj.arrayBuffer();
    if (tamperDemo) {
      const orig  = new Uint8Array(fileBuf);
      const extra = new TextEncoder().encode(' [TAMPERED]');
      const comb  = new Uint8Array(orig.length + extra.length);
      comb.set(orig); comb.set(extra, orig.length);
      fileBuf = comb.buffer;
    }

    const currentHash  = await hashFileBuffer(fileBuf);
    const originalHash = sigJson.file_hash;
    const hashMatch    = currentHash === originalHash;
    const algo         = sigJson.algorithm;
    const pubBuf       = pemToArrayBuffer(pubPEM);
    const sigBytes     = Uint8Array.from(atob(sigJson.signature), c => c.charCodeAt(0));
    const origBuf      = tamperDemo ? await fileObj.arrayBuffer() : fileBuf;
    let cryptoValid = false;

    try {
      if (algo === 'RSA') {
        const pk = await crypto.subtle.importKey('spki', pubBuf, { name:'RSA-PSS', hash:'SHA-256' }, false, ['verify']);
        cryptoValid = await crypto.subtle.verify({ name:'RSA-PSS', saltLength:32 }, pk, sigBytes, origBuf);
      } else {
        const pk = await crypto.subtle.importKey('spki', pubBuf, { name:'ECDSA', namedCurve:'P-256' }, false, ['verify']);
        cryptoValid = await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, pk, sigBytes, origBuf);
      }
    } catch { cryptoValid = false; }

    const valid   = cryptoValid && hashMatch;
    const message = tamperDemo ? 'Tampered file detected — hash mismatch!'
      : valid ? 'Signature cryptographically valid'
      : cryptoValid ? 'Hash mismatch — file was modified after signing'
      : 'Cryptographic verification failed';

    if (valid) {
      document.getElementById('ver-icon').textContent  = '✅';
      document.getElementById('ver-label').textContent = 'SIGNATURE VALID';
      document.getElementById('ver-label').style.color = 'var(--success)';
      box.style.borderColor = 'rgba(0,230,118,0.3)';
    } else {
      document.getElementById('ver-icon').textContent  = '❌';
      document.getElementById('ver-label').textContent = tamperDemo ? 'TAMPERING DETECTED' : 'SIGNATURE INVALID';
      document.getElementById('ver-label').style.color = tamperDemo ? 'var(--warning)' : 'var(--danger)';
      box.style.borderColor = tamperDemo ? 'rgba(255,179,0,0.3)' : 'rgba(255,59,92,0.3)';
    }
    document.getElementById('ver-msg').textContent = message;
    document.getElementById('ver-details').innerHTML = `
      <div class="detail-row"><span class="detail-key">Signer:</span><span class="detail-val">${sigJson.signer||'N/A'}</span></div>
      <div class="detail-row"><span class="detail-key">Algorithm:</span><span class="detail-val">${algo}</span></div>
      <div class="detail-row"><span class="detail-key">Signed On:</span><span class="detail-val">${sigJson.timestamp||'N/A'}</span></div>
      <div class="detail-row"><span class="detail-key">Original Hash:</span><span class="detail-val">${originalHash}</span></div>
      <div class="detail-row"><span class="detail-key">Current Hash:</span><span class="detail-val" style="color:${hashMatch?'var(--success)':'var(--danger)'}">${currentHash}</span></div>
      <div class="detail-row"><span class="detail-key">Hash Match:</span><span class="detail-val" style="color:${hashMatch?'var(--success)':'var(--danger)'}">${hashMatch?'✓ YES':'✗ NO'}</span></div>
      <div class="detail-row"><span class="detail-key">Crypto Valid:</span><span class="detail-val" style="color:${cryptoValid?'var(--success)':'var(--danger)'}">${cryptoValid?'✓ YES':'✗ NO'}</span></div>
      ${tamperDemo ? '<div style="margin-top:8px;color:var(--warning);font-size:11px">⚠ DEMO: Only a temp copy was tampered. Your original file is untouched.</div>' : ''}
    `;
    addAuditEntry(tamperDemo?'Tamper Demo':'Verify File', fileObj.name, valid?'Valid':'Invalid', `Algorithm: ${algo}, Signer: ${sigJson.signer}`);
  } catch (err) {
    document.getElementById('ver-icon').textContent  = '💥';
    document.getElementById('ver-label').textContent = 'VERIFICATION ERROR';
    document.getElementById('ver-label').style.color = 'var(--danger)';
    document.getElementById('ver-msg').textContent   = err.message;
    addAuditEntry('Verify File', fileObj?.name||'unknown', 'Error', err.message);
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
  document.getElementById('perf-btn-icon').innerHTML = '<span class="spinner" style="width:13px;height:13px;border-width:2px"></span>';
  showEl('perf-progress');
  document.getElementById('perf-stats').style.display = 'none';

  let testData;
  if (State.files['perf-file']) {
    testData = await State.files['perf-file'].arrayBuffer();
  } else {
    const buf = new Uint8Array(32768); crypto.getRandomValues(buf); testData = buf.buffer;
  }

  const avg = async (fn, n) => {
    const t = [];
    for (let i = 0; i < n; i++) { const t0 = performance.now(); await fn(); t.push(performance.now() - t0); }
    return t.reduce((a,b)=>a+b,0) / t.length;
  };
  const setP = txt => { document.getElementById('perf-progress-text').textContent = txt; };
  const m = { RSA:{}, ECDSA:{} };

  try {
    setP('RSA — key generation...');
    let rsaKP;
    m.RSA.keygen = await avg(async () => {
      rsaKP = await crypto.subtle.generateKey({ name:'RSA-PSS', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' }, true, ['sign','verify']);
    }, iters);

    setP('RSA — signing...');
    let rsaSig;
    m.RSA.sign = await avg(async () => { rsaSig = await crypto.subtle.sign({ name:'RSA-PSS', saltLength:32 }, rsaKP.privateKey, testData); }, iters);

    setP('RSA — verification...');
    m.RSA.verify = await avg(async () => { await crypto.subtle.verify({ name:'RSA-PSS', saltLength:32 }, rsaKP.publicKey, rsaSig, testData); }, iters);

    const rPr = await crypto.subtle.exportKey('pkcs8', rsaKP.privateKey);
    const rPu = await crypto.subtle.exportKey('spki',  rsaKP.publicKey);
    m.RSA.privSize = rPr.byteLength; m.RSA.pubSize = rPu.byteLength; m.RSA.sigSize = rsaSig.byteLength;

    setP('ECDSA — key generation...');
    let ecKP;
    m.ECDSA.keygen = await avg(async () => { ecKP = await crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']); }, iters);

    setP('ECDSA — signing...');
    let ecSig;
    m.ECDSA.sign = await avg(async () => { ecSig = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, ecKP.privateKey, testData); }, iters);

    setP('ECDSA — verification...');
    m.ECDSA.verify = await avg(async () => { await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, ecKP.publicKey, ecSig, testData); }, iters);

    const ePr = await crypto.subtle.exportKey('pkcs8', ecKP.privateKey);
    const ePu = await crypto.subtle.exportKey('spki',  ecKP.publicKey);
    m.ECDSA.privSize = ePr.byteLength; m.ECDSA.pubSize = ePu.byteLength; m.ECDSA.sigSize = ecSig.byteLength;

    hideEl('perf-progress');
    renderBenchmarkTable(m);

    document.getElementById('stat-rsa-keygen').textContent   = m.RSA.keygen.toFixed(1);
    document.getElementById('stat-ecdsa-keygen').textContent = m.ECDSA.keygen.toFixed(1);
    document.getElementById('stat-rsa-sign').textContent     = m.RSA.sign.toFixed(1);
    document.getElementById('stat-ecdsa-sign').textContent   = m.ECDSA.sign.toFixed(1);
    document.getElementById('perf-stats').style.display = 'flex';
    showEl('perf-note');

    addAuditEntry('Benchmark', 'RSA vs ECDSA', 'Complete', `${iters} iteration(s), ${formatBytes(testData.byteLength)} data`);
    showToast('✅ Benchmark complete', 'success');
  } catch (err) {
    hideEl('perf-progress');
    showToast('Benchmark failed: ' + err.message, 'error');
  }
  btn.disabled = false;
  document.getElementById('perf-btn-icon').textContent = '⚡';
}

function renderBenchmarkTable(m) {
  const rows = [
    ['Key Generation', m.RSA.keygen.toFixed(2)+' ms',  m.ECDSA.keygen.toFixed(2)+' ms', m.RSA.keygen,   m.ECDSA.keygen],
    ['Signing Time',   m.RSA.sign.toFixed(2)+' ms',    m.ECDSA.sign.toFixed(2)+' ms',   m.RSA.sign,     m.ECDSA.sign],
    ['Verify Time',    m.RSA.verify.toFixed(2)+' ms',  m.ECDSA.verify.toFixed(2)+' ms', m.RSA.verify,   m.ECDSA.verify],
    ['Private Key',    formatBytes(m.RSA.privSize),     formatBytes(m.ECDSA.privSize),   m.RSA.privSize, m.ECDSA.privSize],
    ['Public Key',     formatBytes(m.RSA.pubSize),      formatBytes(m.ECDSA.pubSize),    m.RSA.pubSize,  m.ECDSA.pubSize],
    ['Signature',      formatBytes(m.RSA.sigSize),      formatBytes(m.ECDSA.sigSize),    m.RSA.sigSize,  m.ECDSA.sigSize],
  ];
  const maxVals = rows.map(r => Math.max(r[3], r[4]));
  document.getElementById('perf-tbody').innerHTML = rows.map((r,i) => {
    const max = maxVals[i];
    const rW = max > 0 ? Math.round((r[3]/max)*110) : 55;
    const eW = max > 0 ? Math.round((r[4]/max)*110) : 55;
    const w  = r[4] < r[3] ? '<span class="chip chip-ecdsa">ECDSA</span>' : '<span class="chip chip-rsa">RSA</span>';
    return `<tr>
      <td class="metric-name">${r[0]}</td>
      <td class="rsa-val"><div class="bar-wrap"><span style="min-width:75px">${r[1]}</span><div class="bar bar-rsa" style="width:${rW}px"></div></div></td>
      <td class="ecdsa-val"><div class="bar-wrap"><span style="min-width:75px">${r[2]}</span><div class="bar bar-ecdsa" style="width:${eW}px"></div></div></td>
      <td>${w}</td>
    </tr>`;
  }).join('');
}


// ============================================================
//  TAB 5 — AUDIT LOG
// ============================================================
function addAuditEntry(action, filename, result, extra) {
  const now = new Date();
  const ts  = now.toLocaleTimeString('en-US',{hour12:false}) + '.' + String(now.getMilliseconds()).padStart(3,'0');
  State.auditLog.unshift({ ts, action, filename, result, extra });

  State.stats.ops++;
  if (action.includes('Sign'))                                  State.stats.signs++;
  if (['Valid','Success','Complete'].includes(result))          State.stats.valid++;
  if (['Invalid','Failed','Error'].includes(result))            State.stats.invalid++;

  document.getElementById('log-count').textContent   = State.auditLog.length;
  const bn = document.querySelector('.bn-item[data-tab="audit"] .bn-badge');
  if (bn) bn.textContent = State.auditLog.length;

  document.getElementById('total-ops').textContent     = State.stats.ops;
  document.getElementById('total-signs').textContent   = State.stats.signs;
  document.getElementById('total-valid').textContent   = State.stats.valid;
  document.getElementById('total-invalid').textContent = State.stats.invalid;

  renderAuditLog();
}

function renderAuditLog() {
  const terminal = document.getElementById('audit-terminal');
  const empty    = document.getElementById('audit-empty');
  if (State.auditLog.length === 0) { if (empty) empty.style.display='block'; return; }
  if (empty) empty.style.display = 'none';
  terminal.innerHTML = State.auditLog.map(e => {
    const ok = ['Valid','Success','Complete'].includes(e.result);
    return `<div class="log-entry">
      <span class="log-ts">[${e.ts}]</span>
      <span class="log-action">${e.action.toUpperCase()}</span>
      <span class="log-file">${e.filename}</span>
      <span class="${ok?'log-res-success':'log-res-invalid'}">[ ${e.result} ]</span>
      <span class="log-extra">${e.extra}</span>
    </div>`;
  }).join('');
}

function clearLog() {
  State.auditLog = [];
  State.stats    = { ops:0, signs:0, valid:0, invalid:0 };
  ['log-count','total-ops','total-signs','total-valid','total-invalid'].forEach(id => {
    const el = document.getElementById(id); if (el) el.textContent = '0';
  });
  const bn = document.querySelector('.bn-item[data-tab="audit"] .bn-badge');
  if (bn) bn.textContent = '0';
  document.getElementById('audit-terminal').innerHTML =
    '<div class="terminal-empty" id="audit-empty">[ Log cleared ]</div>';
  showToast('Log cleared', 'success');
}

function exportLog() {
  if (!State.auditLog.length) { showToast('No entries to export', 'error'); return; }
  downloadText(JSON.stringify(State.auditLog, null, 2), 'audit_log.json', 'application/json');
}


// ============================================================
//  UTILITY FUNCTIONS
// ============================================================
function formatBytes(bytes) {
  if (bytes >= 1048576) return (bytes/1048576).toFixed(2)+' MB';
  if (bytes >= 1024)    return (bytes/1024).toFixed(2)+' KB';
  return bytes+' B';
}

function downloadText(text, filename, mime) {
  const blob = new Blob([text],{type:mime});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(()=>{ document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
}

function setResult(id, text, type) {
  const el = document.getElementById(id);
  el.textContent = text; el.className = 'result-box visible '+type;
}

function showEl(id) { const e = document.getElementById(id); if(e) e.style.display=''; }
function hideEl(id) { const e = document.getElementById(id); if(e) e.style.display='none'; }

let toastTimer;
function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'show '+(type||'info');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3000);
}


// ============================================================
//  DRAG & DROP
// ============================================================
document.querySelectorAll('.drop-zone').forEach(zone => {
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', e => {
    e.preventDefault(); zone.classList.remove('dragover');
    const fi = zone.querySelector('input[type="file"]');
    if (fi && e.dataTransfer.files[0]) {
      const dt = new DataTransfer(); dt.items.add(e.dataTransfer.files[0]);
      fi.files = dt.files; fi.dispatchEvent(new Event('change'));
    }
  });
});


// ============================================================
//  INIT
// ============================================================
toggleKeySize();