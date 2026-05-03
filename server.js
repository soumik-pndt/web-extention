'use strict';

require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const app     = express();

/* ─── Config ─────────────────────────────────────────────────────────────── */
const PORT                = clamp(process.env.PORT, 1, 65535, 3000);
const VIRUSTOTAL_API_KEY  = String(process.env.VIRUSTOTAL_API_KEY  || '').trim();
const ENABLE_MOCK_SCANNER = String(process.env.ENABLE_MOCK_SCANNER || 'false').toLowerCase() === 'true';
const CACHE_TTL_MS        = clamp(process.env.CACHE_TTL_MS, 60_000, 7*24*60*60*1000, 6*60*60*1000);
const MAX_URLS            = clamp(process.env.MAX_URLS_PER_REQUEST, 1, 50, 25);
const MAX_BODY            = process.env.MAX_BODY_BYTES || '100kb';
const ALLOWED_ORIGINS     = String(process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);

const VT_BASE = 'https://www.virustotal.com/api/v3';

/* ─── In-memory cache ────────────────────────────────────────────────────── */
const cache = new Map();

/* ─── Express setup ──────────────────────────────────────────────────────── */
app.disable('x-powered-by');
app.use(express.json({ limit: MAX_BODY }));
app.use(cors(buildCorsOptions()));

/* ─── Health endpoint ────────────────────────────────────────────────────── */
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service:           'phisshield-backend',
    version:           '2.0.0',
    mode:              scannerMode(),
    hasVirusTotalKey:  Boolean(VIRUSTOTAL_API_KEY),
    cacheSize:         cache.size,
    time:              new Date().toISOString()
  });
});

/* ─── Scan endpoint ──────────────────────────────────────────────────────── */
app.post('/api/extension/scan-links', async (req, res) => {
  try {
    /* ── Input validation ── */
    const input = Array.isArray(req.body?.urls) ? req.body.urls : null;
    if (!input)          return res.status(400).json({ ok: false, error: 'Request body must contain a urls array.' });
    if (!input.length)   return res.status(400).json({ ok: false, error: 'At least one URL is required.' });
    if (input.length > MAX_URLS)
      return res.status(400).json({ ok: false, error: `Maximum ${MAX_URLS} URLs per request.` });

    /* ── Normalise & deduplicate ── */
    const seen = new Set();
    const urls = [];
    for (const raw of input) {
      const url = normalizeUrl(raw);
      if (!url) return res.status(400).json({ ok: false, error: `Invalid URL: ${String(raw).slice(0, 200)}` });
      if (!seen.has(url)) { seen.add(url); urls.push(url); }
    }

    /* ── Scan (parallel) ── */
    const entries    = await Promise.all(urls.map(scanUrl));
    const results    = Object.fromEntries(entries.map(e => [e.url, e]));

    return res.json({
      ok: true,
      results,
      meta: { count: urls.length, mode: scannerMode(), scannedAt: new Date().toISOString() }
    });

  } catch (err) {
    console.error('[PhisShield] scan-links error:', err);
    return res.status(500).json({ ok: false, error: 'Internal scanner error.' });
  }
});

/* ─── 404 / error handlers ───────────────────────────────────────────────── */
app.use((req, res) => res.status(404).json({ ok: false, error: `No route: ${req.method} ${req.originalUrl}` }));
app.use((err, _req, res, _next) => {
  if (err?.type === 'entity.too.large') return res.status(413).json({ ok: false, error: 'Request body too large.' });
  console.error('[PhisShield] unhandled error:', err);
  return res.status(500).json({ ok: false, error: 'Unexpected server error.' });
});

app.listen(PORT, () => {
  console.log(`[PhisShield] Backend v2.0.0 → http://localhost:${PORT}`);
  console.log(`[PhisShield] Scanner mode  : ${scannerMode()}`);
  console.log(`[PhisShield] VT key present: ${Boolean(VIRUSTOTAL_API_KEY)}`);
});

/* ═══════════════════════════════════════════════════════════════════════════
 * SCANNING
 * ═══════════════════════════════════════════════════════════════════════════ */

async function scanUrl(url) {
  const cached = getCached(url);
  if (cached) {
    console.log(`[PhisShield] Cache hit: ${url}`);
    return cached;
  }
  const result = (ENABLE_MOCK_SCANNER || !VIRUSTOTAL_API_KEY)
    ? buildMockResult(url)
    : await scanWithVirusTotal(url);
  setCached(url, result);
  return result;
}

/* ─── VirusTotal integration ──────────────────────────────────────────────── */
async function scanWithVirusTotal(url) {
  const urlId  = vtUrlId(url);
  const headers = { 'x-apikey': VIRUSTOTAL_API_KEY, accept: 'application/json' };

  try {
    const resp = await fetch(`${VT_BASE}/urls/${urlId}`, { headers });

    /* Rate limit */
    if (resp.status === 429) {
      const retryAfter = resp.headers.get('X-RateLimit-Reset') || resp.headers.get('Retry-After') || '60';
      console.warn(`[PhisShield] VT rate-limited — retry in ${retryAfter}s`);
      return buildUnknown(url, `VirusTotal rate limit reached. Retry in ~${retryAfter}s.`);
    }

    /* Not yet in VT DB — submit it */
    if (resp.status === 404) {
      console.log(`[PhisShield] URL not in VT — submitting: ${url}`);
      const submitted = await submitToVT(url, headers);
      if (!submitted) return buildUnknown(url, 'Submission to VirusTotal failed.');
      return buildUnknown(url, 'URL submitted to VirusTotal. Analysis pending — check back shortly.');
    }

    /* API key problem */
    if (resp.status === 401 || resp.status === 403) {
      console.error(`[PhisShield] VT auth error ${resp.status} — check VIRUSTOTAL_API_KEY`);
      return buildUnknown(url, 'VirusTotal API key is invalid or missing. Contact the administrator.');
    }

    if (!resp.ok) {
      return buildUnknown(url, `VirusTotal returned HTTP ${resp.status}.`);
    }

    const payload = await resp.json();
    return mapVTPayload(url, payload);

  } catch (err) {
    console.error('[PhisShield] VT fetch error:', err);
    return buildUnknown(url, 'Could not reach VirusTotal. Check server internet connectivity.');
  }
}

async function submitToVT(url, headers) {
  try {
    const resp = await fetch(`${VT_BASE}/urls`, {
      method: 'POST',
      headers,
      body:   new URLSearchParams({ url })
    });
    return resp.ok;
  } catch { return false; }
}

/* ─── VirusTotal response mapper ─────────────────────────────────────────── */
function mapVTPayload(url, payload) {
  const attrs = payload?.data?.attributes || {};
  const raw   = attrs.last_analysis_stats  || {};

  const malicious  = safeInt(raw.malicious);
  const suspicious = safeInt(raw.suspicious);
  const harmless   = safeInt(raw.harmless);
  const undetected = safeInt(raw.undetected);
  const timeout    = safeInt(raw.timeout);
  const total      = malicious + suspicious + harmless + undetected + timeout;

  /*
   * NEW scoring formula (matches client-side utils.js):
   *   riskScore = ((malicious + suspicious×0.5) / total) × 100
   * Categories:
   *   0-20  → safe
   *   21-60 → suspicious
   *   61-100→ malicious
   */
  let riskScore = 50;
  if (total > 0) {
    riskScore = Math.round(((malicious + suspicious * 0.5) / total) * 100);
    riskScore = Math.min(100, Math.max(0, riskScore));
  }

  let verdict = 'unknown';
  if      (riskScore <= 20) verdict = 'safe';
  else if (riskScore <= 60) verdict = 'suspicious';
  else                       verdict = 'malicious';

  // Edge-case: if total === 0 or no strong signal
  if (total === 0) verdict = 'unknown';

  const summary = buildVTSummary({ malicious, suspicious, harmless, undetected, timeout, verdict, riskScore, total });

  return {
    url, verdict, riskScore, summary,
    reportUrl: `https://www.virustotal.com/gui/url/${vtUrlId(url)}`,
    scannedAt: new Date().toISOString(),
    stats: { harmless, malicious, suspicious, undetected, timeout, totalEngines: total },
    source: 'virustotal'
  };
}

function buildVTSummary({ malicious, suspicious, harmless, undetected, timeout, verdict, riskScore, total }) {
  if (verdict === 'malicious') {
    return `${malicious}/${total} engine(s) flagged this URL as malicious (score: ${riskScore}/100). ${suspicious > 0 ? `${suspicious} also flagged as suspicious.` : ''}`.trim();
  }
  if (verdict === 'suspicious') {
    return `${suspicious}/${total} engine(s) flagged this URL as suspicious (score: ${riskScore}/100). No malicious detections.`;
  }
  if (verdict === 'safe') {
    return `${harmless}/${total} engine(s) confirmed this URL as safe (score: ${riskScore}/100). ${undetected} undetected.`;
  }
  return `VirusTotal returned no strong verdict. ${timeout} timed out, ${undetected} undetected out of ${total} engines.`;
}

/* ─── Mock scanner (development / no API key) ─────────────────────────────── */
function buildMockResult(url) {
  const host = new URL(url).hostname.toLowerCase();

  /* Heuristic scoring */
  const signals = [
    { tokens: ['login','signin'],       score: 18 },
    { tokens: ['verify','verification'],score: 20 },
    { tokens: ['secure','security'],    score: 12 },
    { tokens: ['update','account'],     score: 10 },
    { tokens: ['wallet','crypto'],      score: 22 },
    { tokens: ['free','gift','bonus'],  score: 18 },
    { tokens: ['reset','password'],     score: 14 }
  ];

  let riskScore = 5;
  const lc = url.toLowerCase();
  signals.forEach(({ tokens, score }) => {
    if (tokens.some(t => lc.includes(t))) riskScore += score;
  });

  const hyphens = (host.match(/-/g) || []).length;
  if (hyphens >= 2) riskScore += 15;
  if (host.split('.').length > 3) riskScore += 10;
  if (/\d{2,}/.test(host)) riskScore += 8;

  riskScore = Math.min(100, Math.max(0, riskScore));

  let verdict = 'safe';
  if      (riskScore > 60) verdict = 'malicious';
  else if (riskScore > 20) verdict = 'suspicious';

  /* Fake stats for pie chart */
  const fakeTotal   = 90;
  const fakeMal     = verdict === 'malicious' ? Math.round(riskScore * 0.7) : (verdict === 'suspicious' ? Math.round(riskScore * 0.3) : 0);
  const fakeSusp    = verdict === 'suspicious' ? Math.round(riskScore * 0.5) : 0;
  const fakeHarm    = Math.max(0, fakeTotal - fakeMal - fakeSusp - 5);

  return {
    url, verdict, riskScore,
    summary:   `[Mock] Heuristic analysis of "${host}". Score: ${riskScore}/100.`,
    reportUrl: '',
    scannedAt: new Date().toISOString(),
    stats: {
      malicious:    fakeMal,
      suspicious:   fakeSusp,
      harmless:     fakeHarm,
      undetected:   5,
      timeout:      0,
      totalEngines: fakeTotal
    },
    source: 'mock'
  };
}

/* ─── Unknown result ──────────────────────────────────────────────────────── */
function buildUnknown(url, reason) {
  return {
    url, verdict: 'unknown', riskScore: 50,
    summary:   reason || 'Risk could not be determined.',
    reportUrl: '',
    scannedAt: new Date().toISOString(),
    stats: null,
    source: 'fallback'
  };
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

function normalizeUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    const p = new URL(value.trim());
    if (!['http:', 'https:'].includes(p.protocol)) return null;
    p.hash = ''; p.username = ''; p.password = '';
    p.hostname = p.hostname.toLowerCase();
    if ((p.protocol === 'http:'  && p.port === '80')  ||
        (p.protocol === 'https:' && p.port === '443')) p.port = '';
    return p.toString();
  } catch { return null; }
}

function vtUrlId(url) {
  return Buffer.from(url).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function getCached(url) {
  const e = cache.get(url);
  if (!e) return null;
  if (e.expiresAt <= Date.now()) { cache.delete(url); return null; }
  return e.value;
}

function setCached(url, value) {
  cache.set(url, { value, expiresAt: Date.now() + CACHE_TTL_MS });
}

function scannerMode() {
  if (ENABLE_MOCK_SCANNER) return 'mock';
  if (VIRUSTOTAL_API_KEY)  return 'virustotal';
  return 'mock';
}

function buildCorsOptions() {
  if (ALLOWED_ORIGINS.includes('*')) return { origin: true };
  return {
    origin(origin, cb) {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) cb(null, true);
      else cb(new Error('Origin blocked by PhisShield CORS policy.'));
    }
  };
}

function clamp(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function safeInt(v) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 0;
}
