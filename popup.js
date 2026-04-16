/**
 * PhisShield — Popup Script v2.0 (popup.js)
 */
'use strict';

const runtimeApi = typeof browser !== 'undefined' ? browser : chrome;

const MSG = Object.freeze({
  SCAN_URLS:'PHISSHIELD_SCAN_URLS', GET_SETTINGS:'PHISSHIELD_GET_SETTINGS',
  SAVE_SETTINGS:'PHISSHIELD_SAVE_SETTINGS', CLEAR_CACHE:'PHISSHIELD_CLEAR_CACHE',
  PING_BACKEND:'PHISSHIELD_PING_BACKEND', GET_STATS:'PHISSHIELD_GET_STATS'
});

const VERDICT_LABELS = { safe:'✅ Safe', suspicious:'⚠️ Suspicious', malicious:'🚨 Malicious', unknown:'❓ Unknown' };
const VERDICT_COLORS = { safe:'#22d87a', suspicious:'#f5b935', malicious:'#f24444', unknown:'#8fa0b8' };

/* ── DOM ── */
const backendInput  = document.getElementById('backendBaseUrl');
const saveBtn       = document.getElementById('saveButton');
const testBtn       = document.getElementById('testButton');
const clearCacheBtn = document.getElementById('clearCacheButton');
const statusLine    = document.getElementById('statusLine');
const modePill      = document.getElementById('modePill');
const scanUrlInput  = document.getElementById('scanUrlInput');
const scanBtn       = document.getElementById('scanButton');
const clearInputBtn = document.getElementById('clearInputBtn');
const scanResult    = document.getElementById('scanResult');
const resultCanvas  = document.getElementById('resultCanvas');
const chartScore    = document.getElementById('chartScore');
const verdictBadge  = document.getElementById('verdictBadge');
const verdictText   = document.getElementById('verdictText');
const engineRow     = document.getElementById('engineRow');
const chipMal       = document.getElementById('chipMal');
const chipSusp      = document.getElementById('chipSusp');
const chipSafe      = document.getElementById('chipSafe');
const resultSummary = document.getElementById('resultSummary');
const resultLink    = document.getElementById('resultLink');
const scanBtnIcon   = document.getElementById('scanBtnIcon');
const scanBtnText   = document.getElementById('scanBtnText');
const statScans     = document.getElementById('statScans');
const statHits      = document.getElementById('statHits');
const statErrors    = document.getElementById('statErrors');

const ctx = resultCanvas.getContext('2d');
let animId = null;

/* ══ BOOT ══════════════════════════════════════════════════════════════════ */
(async function boot() {
  try {
    const r = await send(MSG.GET_SETTINGS);
    if (r?.ok) backendInput.value = r.settings?.backendBaseUrl || 'http://localhost:3000';
    drawDonut(ctx, 72, [], '#1a2436', 1);
    pingAndShowMode();
    loadStats();
  } catch (e) { setStatus('Could not load settings.','error'); console.error(e); }
})();

/* ══ SETTINGS ══════════════════════════════════════════════════════════════ */
saveBtn.addEventListener('click', async () => {
  setStatus('Saving…'); saveBtn.disabled = true;
  try {
    const r = await send(MSG.SAVE_SETTINGS, { backendBaseUrl: backendInput.value.trim() });
    setStatus(r?.ok ? 'Settings saved.' : (r?.error || 'Save failed.'), r?.ok ? 'ok' : 'error');
  } catch { setStatus('Communication error.','error'); } finally { saveBtn.disabled = false; }
});

testBtn.addEventListener('click', async () => {
  setStatus('Checking backend…'); testBtn.disabled = true;
  try {
    const r = await send(MSG.PING_BACKEND);
    if (!r?.ok) { setStatus(r?.error || 'Unreachable.','error'); modePill.textContent='offline'; return; }
    modePill.textContent = r.status?.mode || 'online';
    if (r.warning)              setStatus('⚠️ '+r.warning,'warn');
    else if (!r.status?.hasVirusTotalKey) setStatus('Backend OK (no VT key — mock mode).','warn');
    else                        setStatus('Backend OK ✓','ok');
  } catch { setStatus('Connection failed.','error'); } finally { testBtn.disabled = false; }
});

clearCacheBtn.addEventListener('click', async () => {
  setStatus('Clearing…'); clearCacheBtn.disabled = true;
  try {
    const r = await send(MSG.CLEAR_CACHE);
    setStatus(r?.ok ? `Cleared ${r.removed||0} entries.` : (r?.error||'Failed.'), r?.ok?'ok':'error');
  } catch { setStatus('Error.','error'); } finally { clearCacheBtn.disabled = false; }
});

/* ══ MANUAL SCANNER ════════════════════════════════════════════════════════ */
scanUrlInput.addEventListener('input', () => {
  clearInputBtn.classList.toggle('visible', scanUrlInput.value.trim().length > 0);
  if (scanResult.classList.contains('visible')) scanResult.classList.remove('visible');
});

scanUrlInput.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); triggerScan(); } });

clearInputBtn.addEventListener('click', () => {
  scanUrlInput.value = '';
  clearInputBtn.classList.remove('visible');
  scanResult.classList.remove('visible');
  drawDonut(ctx, 72, [], '#1a2436', 1);
  scanUrlInput.focus();
});

scanBtn.addEventListener('click', triggerScan);

async function triggerScan() {
  const raw = scanUrlInput.value.trim();
  if (!raw) { scanUrlInput.focus(); return; }
  const url = normalizeUrl(raw);
  if (!url) { showScanError('Invalid URL — enter a full http:// or https:// address.'); return; }

  setScanLoading(true);
  scanResult.classList.add('visible');

  try {
    const r = await send(MSG.SCAN_URLS, { urls: [url] });

    if (!r?.ok)                             { showScanError(r?.error || 'Scan failed. Is the backend running?'); return; }
    if (!r.results || typeof r.results !== 'object') { showScanError('Backend returned an unexpected response.'); return; }

    const result = r.results[url];
    if (!result) { showScanError('No result returned. Backend may be unreachable.'); return; }

    renderResult(result);
    loadStats();
  } catch (e) {
    console.error('[PhisShield]', e);
    showScanError('Unexpected error. Check the console for details.');
  } finally {
    setScanLoading(false);
  }
}

function renderResult(result) {
  const verdict   = validateVerdict(result?.verdict);
  const score     = clamp(result?.riskScore, 0, 100, 50);
  const summary   = (typeof result?.summary === 'string' && result.summary.trim()) ? result.summary.trim() : 'Risk undetermined.';
  const reportUrl = (typeof result?.reportUrl === 'string' && result.reportUrl) ? result.reportUrl : null;
  const stats     = result?.stats || null;

  verdictBadge.className    = `verdict-badge ${verdict}`;
  verdictText.textContent   = VERDICT_LABELS[verdict] || VERDICT_LABELS.unknown;
  chartScore.textContent    = score;
  chartScore.style.color    = VERDICT_COLORS[verdict];

  if (stats) {
    chipMal.textContent = `${stats.malicious||0} mal`;
    chipSusp.textContent= `${stats.suspicious||0} susp`;
    chipSafe.textContent= `${stats.harmless||0} safe`;
    engineRow.style.display = '';
  } else { engineRow.style.display = 'none'; }

  animateDonut(buildSegments(verdict, score, stats), '#1a2436', 72);
  resultSummary.textContent = summary;

  if (reportUrl) { resultLink.href = reportUrl; resultLink.classList.remove('hidden'); }
  else           { resultLink.classList.add('hidden'); }
}

function showScanError(msg) {
  scanResult.classList.add('visible');
  verdictBadge.className  = 'verdict-badge unknown';
  verdictText.textContent = VERDICT_LABELS.unknown;
  chartScore.textContent  = '?'; chartScore.style.color = VERDICT_COLORS.unknown;
  engineRow.style.display = 'none';
  resultSummary.textContent = msg;
  resultLink.classList.add('hidden');
  drawDonut(ctx, 72, [{value:1,color:'rgba(143,160,184,0.15)'}], '#1a2436', 1);
}

function setScanLoading(on) {
  scanBtn.disabled = on;
  if (on) {
    scanBtnIcon.innerHTML  = '<span class="spinner"></span>';
    scanBtnText.textContent= 'Scanning…';
    verdictBadge.className = 'verdict-badge unknown';
    verdictText.textContent= 'Analysing…';
    chartScore.textContent = '…'; chartScore.style.color = '';
    engineRow.style.display= 'none';
    resultSummary.textContent = 'Contacting backend…';
    resultLink.classList.add('hidden');
    drawDonut(ctx, 72, [{value:1,color:'rgba(59,130,246,0.22)'}], '#1a2436', 1);
  } else {
    scanBtnIcon.textContent  = '⚡';
    scanBtnText.textContent  = 'Scan URL';
  }
}

/* ══ DONUT CHART ════════════════════════════════════════════════════════════ */
function buildSegments(verdict, score, stats) {
  const C = { malicious:'#f24444', suspicious:'#f5b935', harmless:'#22d87a', undetected:'#2d4a6a', timeout:'#4a5a6a' };
  if (stats && (stats.totalEngines||0) > 0) {
    return [
      {value:stats.malicious||0,  color:C.malicious},
      {value:stats.suspicious||0, color:C.suspicious},
      {value:stats.harmless||0,   color:C.harmless},
      {value:stats.undetected||0, color:C.undetected},
      {value:stats.timeout||0,    color:C.timeout}
    ].filter(s => s.value > 0);
  }
  const malP  = verdict==='malicious' ? score : (verdict==='suspicious' ? Math.round(score*0.4) : 0);
  const suspP = verdict==='suspicious' ? Math.round(score*0.6) : 0;
  const safeP = Math.max(0, 100-malP-suspP);
  return [{value:malP,color:C.malicious},{value:suspP,color:C.suspicious},{value:safeP,color:C.harmless}].filter(s=>s.value>0);
}

function drawDonut(ctx, size, segs, bg, progress) {
  ctx.clearRect(0, 0, size, size);
  const cx=size/2, cy=size/2, outerR=size/2-2, innerR=size/2-16;
  const total = segs.reduce((s,seg)=>s+seg.value,0);

  // bg ring
  ctx.beginPath(); ctx.arc(cx,cy,outerR,0,Math.PI*2); ctx.arc(cx,cy,innerR,Math.PI*2,0,true);
  ctx.fillStyle = bg||'#1a2436'; ctx.fill();

  if (!segs.length||total===0) {
    ctx.beginPath(); ctx.arc(cx,cy,outerR,0,Math.PI*2); ctx.arc(cx,cy,innerR,Math.PI*2,0,true);
    ctx.fillStyle='rgba(148,180,220,0.08)'; ctx.fill(); return;
  }

  let cur = -Math.PI/2;
  const sweep = Math.PI*2*(progress??1);
  for (const seg of segs) {
    if (seg.value<=0) continue;
    const end = cur + (seg.value/total)*sweep;
    ctx.beginPath(); ctx.arc(cx,cy,outerR,cur,end); ctx.arc(cx,cy,innerR,end,cur,true); ctx.closePath();
    ctx.shadowColor=seg.color; ctx.shadowBlur=8; ctx.fillStyle=seg.color; ctx.fill(); ctx.shadowBlur=0;
    cur = end;
  }
}

function animateDonut(segs, bg, size) {
  if (animId) cancelAnimationFrame(animId);
  const t0 = performance.now(), dur = 480;
  function frame(now) {
    const p = Math.min((now-t0)/dur,1), e = 1-Math.pow(1-p,3);
    drawDonut(ctx, size, segs, bg, e);
    if (p<1) animId = requestAnimationFrame(frame);
  }
  animId = requestAnimationFrame(frame);
}

/* ══ HELPERS ════════════════════════════════════════════════════════════════ */
async function pingAndShowMode() {
  try { const r = await send(MSG.PING_BACKEND); modePill.textContent = r?.status?.mode||(r?.ok?'online':'offline'); }
  catch { modePill.textContent='offline'; }
}

async function loadStats() {
  try {
    const r = await send(MSG.GET_STATS);
    if (r?.ok && r.stats) {
      statScans.textContent  = r.stats.scans    ?? '0';
      statHits.textContent   = r.stats.cacheHits?? '0';
      statErrors.textContent = r.stats.errors   ?? '0';
    }
  } catch {}
}

function setStatus(msg, type='') { statusLine.textContent=msg; statusLine.className=`status-line ${type}`.trim(); }
function validateVerdict(v) { return ['safe','suspicious','malicious','unknown'].includes(v)?v:'unknown'; }
function normalizeUrl(v) {
  if (!v) return null; let r=v.trim();
  if (!/^https?:\/\//i.test(r)) r='https://'+r;
  try { const p=new URL(r); if(!['http:','https:'].includes(p.protocol))return null;
    p.hash=''; p.username=''; p.password=''; p.hostname=p.hostname.toLowerCase();
    if((p.protocol==='http:'&&p.port==='80')||(p.protocol==='https:'&&p.port==='443'))p.port='';
    return p.toString(); } catch { return null; }
}
function clamp(v,min,max,fb) { const n=Number(v); return Number.isFinite(n)?Math.min(max,Math.max(min,n)):(fb??min); }
function send(type, payload) { return runtimeApi.runtime.sendMessage({type, payload}); }
