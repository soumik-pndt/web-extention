/**
 * PhisShield — Content Script v2.0 (content-script.js)
 * Scans page links, shows hover tooltip with donut pie chart.
 * Depends on utils.js being injected first (window.PhisShieldUtils).
 */
'use strict';

/* ─── Runtime API (Firefox / Chrome) ─────────────────────────────────────── */
const runtimeApi = typeof browser !== 'undefined' ? browser : chrome;

/* ─── Utils (injected by utils.js) ──────────────────────────────────────── */
const Utils = window.PhisShieldUtils;

/* ─── Constants ──────────────────────────────────────────────────────────── */
const MSG = Object.freeze({ SCAN_URLS: 'PHISSHIELD_SCAN_URLS' });

/* ─── State ──────────────────────────────────────────────────────────────── */
const scannedResults = new Map();   // normalizedUrl → result
const queuedUrls     = new Set();   // URLs waiting for a scan response
let scanTimer   = null;
let activeAnchor = null;
let hideTimer    = null;
let tooltip      = null;            // { root, canvas, ctx, scoreEl, verdictEl, … }

/* ─── Boot ───────────────────────────────────────────────────────────────── */
initialize();

function initialize() {
  buildTooltip();
  scanDocumentLinks();
  attachGlobalListeners();
  attachMutationObserver();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TOOLTIP CREATION
 * ═══════════════════════════════════════════════════════════════════════════ */

function buildTooltip() {
  if (tooltip) return tooltip;

  const root = document.createElement('div');
  root.className = 'phisshield-tooltip phisshield-hidden';
  root.setAttribute('role', 'dialog');
  root.setAttribute('aria-live', 'polite');

  root.innerHTML = `
    <div class="phisshield-card">
      <div class="phisshield-top-row">

        <!-- Donut chart -->
        <div class="phisshield-chart-wrap">
          <canvas class="phisshield-chart-canvas" width="64" height="64"></canvas>
          <div class="phisshield-chart-score">
            <span class="phisshield-chart-number">50</span>
            <span class="phisshield-chart-unit">/100</span>
          </div>
        </div>

        <!-- Verdict + engine chips -->
        <div class="phisshield-verdict-info">
          <div class="phisshield-verdict-badge unknown">
            <span class="phisshield-verdict-dot"></span>
            <span class="phisshield-verdict-text">Unknown</span>
          </div>
          <div class="phisshield-engine-row">
            <span class="phisshield-engine-chip mal"  data-chip="mal">0 mal</span>
            <span class="phisshield-engine-chip susp" data-chip="susp">0 susp</span>
            <span class="phisshield-engine-chip safe" data-chip="safe">0 safe</span>
          </div>
        </div>
      </div>

      <p class="phisshield-summary">Scanning…</p>

      <a class="phisshield-report-link phisshield-link-disabled"
         href="#" target="_blank" rel="noopener noreferrer">
        🔗 Full VirusTotal report
      </a>

      <div class="phisshield-branding">
        <span class="phisshield-brand-name">🛡️ PhisShield</span>
      </div>
    </div>
  `;

  /* Prevent tooltip hover from triggering hide */
  root.addEventListener('mouseenter', clearHideTimer, true);
  root.addEventListener('mouseleave', scheduleHide,   true);

  document.documentElement.appendChild(root);

  const canvas = root.querySelector('.phisshield-chart-canvas');

  tooltip = {
    root,
    canvas,
    ctx:         canvas.getContext('2d'),
    scoreEl:     root.querySelector('.phisshield-chart-number'),
    badgeEl:     root.querySelector('.phisshield-verdict-badge'),
    verdictText: root.querySelector('.phisshield-verdict-text'),
    chipMal:     root.querySelector('[data-chip="mal"]'),
    chipSusp:    root.querySelector('[data-chip="susp"]'),
    chipSafe:    root.querySelector('[data-chip="safe"]'),
    summaryEl:   root.querySelector('.phisshield-summary'),
    linkEl:      root.querySelector('.phisshield-report-link'),
    animFrame:   null
  };

  /* Initial placeholder draw */
  drawDonut(tooltip.ctx, 64, [], '#1a2436');

  return tooltip;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DONUT CHART DRAWING (pure canvas, zero dependencies)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Draw an animated donut chart.
 * @param {CanvasRenderingContext2D} ctx
 * @param {number} size  canvas dimension (square)
 * @param {{ value:number, color:string }[]} segments
 * @param {string} bgColor  ring background
 * @param {number} progress  0–1 animation progress
 */
function drawDonut(ctx, size, segments, bgColor, progress = 1) {
  ctx.clearRect(0, 0, size, size);

  const cx        = size / 2;
  const cy        = size / 2;
  const outerR    = size / 2 - 2;
  const innerR    = size / 2 - 14;  // donut hole radius
  const startAngle = -Math.PI / 2;  // start at 12 o'clock
  const total     = segments.reduce((s, seg) => s + seg.value, 0);

  /* Background ring */
  ctx.beginPath();
  ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
  ctx.arc(cx, cy, innerR, Math.PI * 2, 0, true);
  ctx.fillStyle = bgColor || '#1a2436';
  ctx.fill();

  if (!segments.length || total === 0) {
    /* Draw empty ring */
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
    ctx.arc(cx, cy, innerR, Math.PI * 2, 0, true);
    ctx.fillStyle = 'rgba(148,180,220,0.1)';
    ctx.fill();
    return;
  }

  /* Animated arc segments */
  let currentAngle = startAngle;
  const targetArc  = Math.PI * 2 * progress;

  for (const seg of segments) {
    if (seg.value <= 0) continue;
    const slice     = (seg.value / total) * targetArc;
    const endAngle  = currentAngle + slice;

    ctx.beginPath();
    ctx.arc(cx, cy,  outerR, currentAngle, endAngle);
    ctx.arc(cx, cy,  innerR, endAngle, currentAngle, true);
    ctx.closePath();

    /* Glow effect for main segment */
    ctx.shadowColor = seg.color;
    ctx.shadowBlur  = 6;
    ctx.fillStyle   = seg.color;
    ctx.fill();
    ctx.shadowBlur  = 0;

    currentAngle = endAngle;
  }
}

/**
 * Animate the donut chart from 0 → full over ~500ms.
 */
function animateDonut(segments, bgColor) {
  if (!tooltip) return;
  const { ctx, animFrame } = tooltip;
  if (animFrame) cancelAnimationFrame(animFrame);

  const size      = 64;
  const duration  = 480;
  const startTime = performance.now();

  function frame(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    // Ease-out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    drawDonut(ctx, size, segments, bgColor, eased);
    if (progress < 1) {
      tooltip.animFrame = requestAnimationFrame(frame);
    }
  }

  tooltip.animFrame = requestAnimationFrame(frame);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TOOLTIP UPDATE
 * ═══════════════════════════════════════════════════════════════════════════ */

function showTooltip(anchor, result) {
  const t = buildTooltip();

  const verdict   = ['safe','suspicious','malicious','unknown'].includes(result?.verdict) ? result.verdict : 'unknown';
  const riskScore = Utils.clamp(result?.riskScore, 0, 100, 50);
  const summary   = (typeof result?.summary === 'string' && result.summary.trim())
    ? result.summary.trim()
    : 'Risk could not be determined right now.';
  const reportUrl = (typeof result?.reportUrl === 'string' && result.reportUrl) ? result.reportUrl : null;
  const stats     = result?.stats || null;

  /* ── Verdict badge ── */
  t.badgeEl.className    = `phisshield-verdict-badge ${verdict}`;
  t.verdictText.textContent = Utils.verdictLabel(verdict);

  /* ── Score ── */
  t.scoreEl.textContent  = riskScore;

  /* ── Engine chips (only when VT stats are available) ── */
  if (stats) {
    t.chipMal.textContent  = `${stats.malicious  || 0} mal`;
    t.chipSusp.textContent = `${stats.suspicious || 0} susp`;
    t.chipSafe.textContent = `${stats.harmless   || 0} safe`;
    t.chipMal.style.display  = '';
    t.chipSusp.style.display = '';
    t.chipSafe.style.display = '';
  } else {
    t.chipMal.style.display  = 'none';
    t.chipSusp.style.display = 'none';
    t.chipSafe.style.display = 'none';
  }

  /* ── Donut chart segments ── */
  const segments = buildChartSegments(verdict, riskScore, stats);
  animateDonut(segments, '#1a2436');

  /* ── Summary ── */
  t.summaryEl.textContent = summary;

  /* ── Report link ── */
  if (reportUrl) {
    t.linkEl.href = reportUrl;
    t.linkEl.classList.remove('phisshield-link-disabled');
  } else {
    t.linkEl.href = '#';
    t.linkEl.classList.add('phisshield-link-disabled');
  }

  /* ── Show ── */
  t.root.classList.remove('phisshield-hidden');
  requestAnimationFrame(() => positionTooltip(anchor, t.root));
}

/**
 * Build chart segments from scan result.
 * Priority: use real stats if available, otherwise use score-based estimate.
 */
function buildChartSegments(verdict, riskScore, stats) {
  const COLOR = {
    malicious:  '#f24444',
    suspicious: '#f5b935',
    harmless:   '#22d87a',
    undetected: '#3b5a7e',
    timeout:    '#5a6e82'
  };

  if (stats && stats.totalEngines > 0) {
    return [
      { value: stats.malicious  || 0, color: COLOR.malicious  },
      { value: stats.suspicious || 0, color: COLOR.suspicious },
      { value: stats.harmless   || 0, color: COLOR.harmless   },
      { value: stats.undetected || 0, color: COLOR.undetected },
      { value: stats.timeout    || 0, color: COLOR.timeout    }
    ].filter(s => s.value > 0);
  }

  /* Fallback: synthesise from risk score */
  const malPct  = verdict === 'malicious'  ? riskScore           : (verdict === 'suspicious' ? riskScore * 0.4 : 0);
  const suspPct = verdict === 'suspicious' ? riskScore * 0.6     : 0;
  const safePct = Math.max(0, 100 - malPct - suspPct);

  return [
    { value: malPct,  color: COLOR.malicious  },
    { value: suspPct, color: COLOR.suspicious },
    { value: safePct, color: COLOR.harmless   }
  ].filter(s => s.value > 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LINK SCANNING
 * ═══════════════════════════════════════════════════════════════════════════ */

function scanDocumentLinks() {
  const anchors = document.querySelectorAll('a:not([data-phisshield-scanned="true"])');
  const toRequest = [];

  anchors.forEach(anchor => {
    if (!(anchor instanceof HTMLAnchorElement)) return;

    const url = normalizeAnchorUrl(anchor);
    anchor.setAttribute('data-phisshield-scanned', 'true');

    if (!url) return;
    anchor.dataset.phisshieldUrl = url;
    attachAnchorListeners(anchor);

    if (scannedResults.has(url) || queuedUrls.has(url)) return;
    queuedUrls.add(url);
    toRequest.push(url);
  });

  if (toRequest.length) {
    requestScans(toRequest).catch(err => console.error('[PhisShield] requestScans error:', err));
  }
}

function attachAnchorListeners(anchor) {
  if (anchor.dataset.phisshieldListenersAttached === 'true') return;
  anchor.dataset.phisshieldListenersAttached = 'true';
  anchor.addEventListener('mouseenter', onAnchorEnter, true);
  anchor.addEventListener('mouseleave', onAnchorLeave, true);
  anchor.addEventListener('focus',      onAnchorEnter, true);
  anchor.addEventListener('blur',       onAnchorLeave, true);
}

async function requestScans(urls) {
  try {
    const resp = await runtimeApi.runtime.sendMessage({
      type:    MSG.SCAN_URLS,
      payload: { urls }
    });

    const results = (resp?.results && typeof resp.results === 'object') ? resp.results : {};

    urls.forEach(url => {
      queuedUrls.delete(url);
      if (results[url]) {
        scannedResults.set(url, results[url]);
        /* If user is hovering this link right now, update immediately */
        if (activeAnchor?.dataset?.phisshieldUrl === url) {
          showTooltip(activeAnchor, results[url]);
        }
      }
    });
  } catch (err) {
    urls.forEach(u => queuedUrls.delete(u));
    throw err;
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HOVER HANDLERS
 * ═══════════════════════════════════════════════════════════════════════════ */

function onAnchorEnter(event) {
  const anchor = event.currentTarget;
  if (!(anchor instanceof HTMLAnchorElement)) return;

  const url = anchor.dataset.phisshieldUrl;
  if (!url) return;

  activeAnchor = anchor;
  clearHideTimer();

  if (scannedResults.has(url)) {
    showTooltip(anchor, scannedResults.get(url));
  } else {
    // Show loading tooltip
    const loadingResult = {
      verdict: 'unknown',
      riskScore: 50,
      summary: 'Scanning…',
      reportUrl: '',
      stats: null
    };
    showTooltip(anchor, loadingResult);
    // Request scan if not already queued
    if (!queuedUrls.has(url)) {
      queuedUrls.add(url);
      requestScans([url]).catch(err => console.error('[PhisShield] requestScans error:', err));
    }
  }
}

function onAnchorLeave() { scheduleHide(); }

/* ═══════════════════════════════════════════════════════════════════════════
 * TOOLTIP POSITION
 * ═══════════════════════════════════════════════════════════════════════════ */

function positionTooltip(anchor, el) {
  const aRect  = anchor.getBoundingClientRect();
  const margin = 10;
  const maxW   = Math.min(300, window.innerWidth - margin * 2);

  el.style.maxWidth = `${maxW}px`;
  el.style.left = '0px';
  el.style.top  = '0px';

  const tRect = el.getBoundingClientRect();
  let left = aRect.left + window.scrollX;
  let top  = aRect.bottom + window.scrollY + 8;

  /* Overflow right */
  if (left + tRect.width + margin > window.scrollX + window.innerWidth) {
    left = window.scrollX + window.innerWidth - tRect.width - margin;
  }
  /* Overflow left */
  if (left < window.scrollX + margin) left = window.scrollX + margin;

  /* Flip above if overflows below */
  if (top + tRect.height + margin > window.scrollY + window.innerHeight) {
    top = aRect.top + window.scrollY - tRect.height - 8;
  }
  /* Overflow top */
  if (top < window.scrollY + margin) top = window.scrollY + margin;

  el.style.left = `${left}px`;
  el.style.top  = `${top}px`;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HIDE LOGIC
 * ═══════════════════════════════════════════════════════════════════════════ */

function scheduleHide() {
  clearHideTimer();
  hideTimer = setTimeout(() => hideTooltip(false), 200);
}

function clearHideTimer() {
  if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
}

function hideTooltip(immediate) {
  clearHideTimer();
  activeAnchor = null;
  if (!tooltip) return;
  if (immediate) {
    tooltip.root.classList.add('phisshield-hidden', 'phisshield-no-transition');
    requestAnimationFrame(() => tooltip.root.classList.remove('phisshield-no-transition'));
    return;
  }
  tooltip.root.classList.add('phisshield-hidden');
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GLOBAL LISTENERS + MUTATION OBSERVER
 * ═══════════════════════════════════════════════════════════════════════════ */

function attachGlobalListeners() {
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') hideTooltip(true);
  }, true);
}

function attachMutationObserver() {
  const observer = new MutationObserver(mutations => {
    let rescan = false;
    for (const m of mutations) {
      if (m.type === 'attributes' && m.target instanceof HTMLAnchorElement) {
        m.target.removeAttribute('data-phisshield-scanned');
        delete m.target.dataset.phisshieldUrl;
        rescan = true; break;
      }
      if (m.type === 'childList') { rescan = true; break; }
    }
    if (rescan) debounceScan();
  });

  observer.observe(document.documentElement || document.body, {
    childList: true, subtree: true,
    attributes: true, attributeFilter: ['href']
  });
}

function debounceScan() {
  if (scanTimer) clearTimeout(scanTimer);
  scanTimer = setTimeout(() => {
    scanTimer = null;
    scanDocumentLinks();
  }, 350);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * URL HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

function normalizeAnchorUrl(anchor) {
  if (!(anchor instanceof HTMLAnchorElement)) return null;
  const href = anchor.getAttribute('href');
  if (typeof href !== 'string' || !href.trim()) return null;
  const t = href.trim();
  if (
    t.startsWith('#') || t.startsWith('javascript:') ||
    t.startsWith('mailto:') || t.startsWith('tel:') ||
    t.startsWith('about:') || t.startsWith('moz-extension:') ||
    t.startsWith('chrome-extension:')
  ) return null;

  try {
    const p = new URL(t, document.baseURI);
    if (!['http:', 'https:'].includes(p.protocol)) return null;
    p.hash = ''; p.username = ''; p.password = '';
    if ((p.protocol === 'http:'  && p.port === '80')  ||
        (p.protocol === 'https:' && p.port === '443')) p.port = '';
    p.hostname = p.hostname.toLowerCase();
    return p.toString();
  } catch { return null; }
}
