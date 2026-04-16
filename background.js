/**
 * PhisShield — Background Service Worker (background.js)
 * Handles messaging, batching, throttling, caching, and backend calls.
 * Manifest V3 — uses chrome.storage (also compatible with browser.storage via runtimeApi).
 */
'use strict';

const runtimeApi = typeof browser !== 'undefined' ? browser : chrome;

/* ─── Message type constants ─────────────────────────────────────────────── */
const MSG = Object.freeze({
  SCAN_URLS:     'PHISSHIELD_SCAN_URLS',
  GET_SETTINGS:  'PHISSHIELD_GET_SETTINGS',
  SAVE_SETTINGS: 'PHISSHIELD_SAVE_SETTINGS',
  CLEAR_CACHE:   'PHISSHIELD_CLEAR_CACHE',
  PING_BACKEND:  'PHISSHIELD_PING_BACKEND',
  GET_STATS:     'PHISSHIELD_GET_STATS'
});

const STORAGE = Object.freeze({
  SETTINGS:     'phisshield.settings',
  CACHE_PREFIX: 'phisshield.cache.',
  STATS:        'phisshield.stats'
});

/* ─── Defaults ───────────────────────────────────────────────────────────── */
const DEFAULT_SETTINGS = Object.freeze({
  backendBaseUrl: 'http://localhost:3000',
  cacheTtlMs:     6 * 60 * 60 * 1000,  // 6 hours
  batchSize:      25,
  queueDelayMs:   250,
  throttleMs:     800
});

const UNKNOWN_SUMMARY = 'Risk could not be determined right now.';

/* ─── In-memory state ────────────────────────────────────────────────────── */
const memoryCache       = new Map();   // url → { value, expiresAt }
const inFlightResolvers = new Map();   // url → [resolveFn, …]
const queuedUrls        = new Set();

let queueTimer      = null;
let queueInProgress = false;
let lastDispatchAt  = 0;

// Runtime stats (scans performed, errors, cache hits)
let stats = { scans: 0, cacheHits: 0, errors: 0, rateLimit: 0 };

/* ─── Install / startup ──────────────────────────────────────────────────── */
runtimeApi.runtime.onInstalled.addListener(async () => {
  const existing = await getStoredSettings();
  await runtimeApi.storage.local.set({
    [STORAGE.SETTINGS]: { ...DEFAULT_SETTINGS, ...(existing || {}) }
  });
  console.log('[PhisShield] Extension installed/updated — settings initialised.');
  setupContextMenu();
});

/* ─── Context menu ───────────────────────────────────────────────────────── */
function setupContextMenu() {
  if (!chrome.contextMenus) return;
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id:       'phisshield-scan',
      title:    '🛡️ Scan with PhisShield',
      contexts: ['link']
    });
  });
}

chrome.contextMenus?.onClicked?.addListener((info) => {
  if (info.menuItemId === 'phisshield-scan' && info.linkUrl) {
    const url = info.linkUrl;
    scanSingleUrl(url).then((result) => {
      const verdict = result?.verdict || 'unknown';
      const score   = result?.riskScore ?? 50;
      chrome.notifications?.create({
        type:    'basic',
        iconUrl: 'icons/icon48.png',
        title:   `PhisShield — ${capitalise(verdict)}`,
        message: `Risk score: ${score}/100\n${result?.summary || UNKNOWN_SUMMARY}`
      });
    }).catch(console.error);
  }
});

/* ─── Message router ─────────────────────────────────────────────────────── */
runtimeApi.runtime.onMessage.addListener((msg, _sender) => {
  if (!msg || typeof msg.type !== 'string') {
    return Promise.resolve({ ok: false, error: 'Invalid message.' });
  }
  switch (msg.type) {
    case MSG.SCAN_URLS:     return handleScanMessage(msg);
    case MSG.GET_SETTINGS:  return getMergedSettings().then(s => ({ ok: true, settings: s }));
    case MSG.SAVE_SETTINGS: return saveSettings(msg.payload);
    case MSG.CLEAR_CACHE:   return clearAllCache();
    case MSG.PING_BACKEND:  return pingBackend();
    case MSG.GET_STATS:     return Promise.resolve({ ok: true, stats });
    default:                return Promise.resolve({ ok: false, error: 'Unknown message type.' });
  }
});

/* ─── Scan message handler ───────────────────────────────────────────────── */
async function handleScanMessage(msg) {
  const urls = Array.isArray(msg.payload?.urls)
    ? [...new Set(msg.payload.urls.filter(u => typeof u === 'string' && u.trim()))]
    : [];

  if (!urls.length) return { ok: true, results: {} };

  const settings = await getMergedSettings();
  const { results, misses } = await getCachedEntries(urls, settings.cacheTtlMs);

  stats.cacheHits += (urls.length - misses.length);

  if (!misses.length) return { ok: true, results };

  const pending = misses.map(url => new Promise(resolve => {
    const resolvers = inFlightResolvers.get(url) || [];
    resolvers.push(resolve);
    inFlightResolvers.set(url, resolvers);
    queuedUrls.add(url);
  }));

  scheduleQueueFlush(settings.queueDelayMs);

  const resolved = await Promise.all(pending);
  resolved.forEach(entry => { results[entry.url] = entry; });

  return { ok: true, results };
}

/* ─── Queue + batch flush ────────────────────────────────────────────────── */
function scheduleQueueFlush(delayMs) {
  if (queueTimer) return;
  queueTimer = setTimeout(async () => {
    queueTimer = null;
    await flushQueue();
  }, Math.max(100, Number(delayMs) || DEFAULT_SETTINGS.queueDelayMs));
}

async function flushQueue() {
  if (queueInProgress || !queuedUrls.size) return;
  queueInProgress = true;
  let batch = [];
  try {
    const settings  = await getMergedSettings();
    const batchSize = clamp(settings.batchSize, 1, 50, DEFAULT_SETTINGS.batchSize);
    const throttle  = clamp(settings.throttleMs, 0, 15000, DEFAULT_SETTINGS.throttleMs);
    const elapsed   = Date.now() - lastDispatchAt;
    if (elapsed < throttle) await wait(throttle - elapsed);

    batch = [...queuedUrls].slice(0, batchSize);
    batch.forEach(u => queuedUrls.delete(u));

    const scanMap = await requestBackendBatch(batch, settings);
    lastDispatchAt = Date.now();
    await persistResults(scanMap, settings.cacheTtlMs);
    resolveBatch(batch, scanMap);
  } catch (err) {
    console.error('[PhisShield] Queue flush error:', err);
    stats.errors++;
    resolveBatch(batch, buildFallbackMap(batch, 'Backend request failed.'));
  } finally {
    queueInProgress = false;
    if (queuedUrls.size) scheduleQueueFlush(DEFAULT_SETTINGS.queueDelayMs);
  }
}

function resolveBatch(batchUrls, resultMap) {
  batchUrls.forEach(url => {
    const resolvers = inFlightResolvers.get(url) || [];
    const result    = resultMap[url] || buildUnknown(url, 'No result returned.');
    resolvers.forEach(fn => fn(result));
    inFlightResolvers.delete(url);
  });
}

/* ─── Backend call ───────────────────────────────────────────────────────── */
async function requestBackendBatch(urls, settings) {
  if (!urls.length) return {};
  const base = sanitizeBackendUrl(settings.backendBaseUrl);
  if (!base) return buildFallbackMap(urls, 'Backend URL is not configured.');

  try {
    const resp = await fetch(`${base}/api/extension/scan-links`, {
      method:  'POST',
      headers: {
        'Content-Type':       'application/json',
        'X-PhisShield-Client': 'extension-v2'
      },
      body: JSON.stringify({ urls })
    });

    /* Rate limit handling */
    if (resp.status === 429) {
      stats.rateLimit++;
      const retryAfter = Number(resp.headers.get('Retry-After') || 60);
      console.warn(`[PhisShield] Rate limited — retry in ${retryAfter}s`);
      return buildFallbackMap(urls, `Rate limited. Please wait ${retryAfter}s before retrying.`);
    }

    if (!resp.ok) {
      console.error(`[PhisShield] Backend error ${resp.status}`);
      return buildFallbackMap(urls, `Backend returned HTTP ${resp.status}.`);
    }

    let data;
    try {
      data = await resp.json();
    } catch {
      return buildFallbackMap(urls, 'Backend returned malformed JSON.');
    }

    if (!data?.ok || typeof data.results !== 'object') {
      return buildFallbackMap(urls, data?.error || 'Unexpected backend response format.');
    }

    stats.scans += urls.length;

    return Object.fromEntries(urls.map(url => [url, normalizeResult(url, data.results[url])]));

  } catch (err) {
    console.error('[PhisShield] fetch error:', err);
    stats.errors++;
    return buildFallbackMap(urls, 'Backend is unreachable. Is it running?');
  }
}

/* ─── Single URL convenience helper (used by context menu) ──────────────── */
async function scanSingleUrl(url) {
  const settings = await getMergedSettings();
  const { results, misses } = await getCachedEntries([url], settings.cacheTtlMs);
  if (!misses.length) return results[url];
  const map = await requestBackendBatch([url], settings);
  await persistResults(map, settings.cacheTtlMs);
  return map[url];
}

/* ─── Result normalisation ───────────────────────────────────────────────── */
function normalizeResult(url, raw) {
  const verdict   = ['safe','suspicious','malicious','unknown'].includes(raw?.verdict) ? raw.verdict : 'unknown';
  const riskScore = clamp(raw?.riskScore, 0, 100, 50);
  const summary   = (typeof raw?.summary === 'string' && raw.summary.trim()) ? raw.summary.trim() : UNKNOWN_SUMMARY;
  const reportUrl = typeof raw?.reportUrl === 'string' ? raw.reportUrl : '';
  const scannedAt = typeof raw?.scannedAt === 'string' ? raw.scannedAt : new Date().toISOString();
  const stats_    = (raw?.stats && typeof raw.stats === 'object') ? raw.stats : null;

  return { url, verdict, riskScore, summary, reportUrl, scannedAt, stats: stats_, source: 'backend' };
}

function buildFallbackMap(urls, reason) {
  return Object.fromEntries(urls.map(u => [u, buildUnknown(u, reason)]));
}

function buildUnknown(url, reason) {
  return {
    url, verdict: 'unknown', riskScore: 50,
    summary: reason || UNKNOWN_SUMMARY,
    reportUrl: '', scannedAt: new Date().toISOString(),
    stats: null, source: 'fallback'
  };
}

/* ─── Cache ──────────────────────────────────────────────────────────────── */
async function getCachedEntries(urls, ttlMs) {
  const results = {}, misses = [], storageKeys = [], keyToUrl = new Map();
  const now = Date.now();

  urls.forEach(url => {
    const mem = memoryCache.get(url);
    if (mem && mem.expiresAt > now) { results[url] = mem.value; return; }
    const k = STORAGE.CACHE_PREFIX + url;
    storageKeys.push(k);
    keyToUrl.set(k, url);
  });

  if (storageKeys.length) {
    const stored = await runtimeApi.storage.local.get(storageKeys);
    storageKeys.forEach(k => {
      const url   = keyToUrl.get(k);
      const entry = stored[k];
      if (entry && entry.expiresAt > now && entry.value) {
        memoryCache.set(url, entry);
        results[url] = entry.value;
      } else {
        misses.push(url);
      }
    });
  }

  return { results, misses };
}

async function persistResults(resultMap, ttlMs) {
  const expiresAt = Date.now() + clamp(ttlMs, 60000, 7 * 24 * 60 * 60 * 1000, DEFAULT_SETTINGS.cacheTtlMs);
  const toStore   = {};
  Object.entries(resultMap).forEach(([url, value]) => {
    const entry = { value, expiresAt };
    memoryCache.set(url, entry);
    toStore[STORAGE.CACHE_PREFIX + url] = entry;
  });
  if (Object.keys(toStore).length) await runtimeApi.storage.local.set(toStore);
}

async function clearAllCache() {
  const all  = await runtimeApi.storage.local.get(null);
  const keys = Object.keys(all).filter(k => k.startsWith(STORAGE.CACHE_PREFIX));
  memoryCache.clear();
  if (keys.length) await runtimeApi.storage.local.remove(keys);
  console.log(`[PhisShield] Cache cleared — removed ${keys.length} entries.`);
  return { ok: true, removed: keys.length };
}

/* ─── Backend health check ───────────────────────────────────────────────── */
async function pingBackend() {
  const settings = await getMergedSettings();
  const base     = sanitizeBackendUrl(settings.backendBaseUrl);
  if (!base) return { ok: false, error: 'Backend URL is empty or invalid.' };
  try {
    const resp = await fetch(`${base}/health`, {
      headers: { 'X-PhisShield-Client': 'extension-v2' }
    });
    if (!resp.ok) return { ok: false, error: `Backend returned HTTP ${resp.status}.` };
    const data = await resp.json();
    // Validate API key presence
    if (!data.hasVirusTotalKey) {
      return { ok: true, status: data, warning: 'No VirusTotal API key configured — running in mock mode.' };
    }
    return { ok: true, status: data };
  } catch {
    return { ok: false, error: 'Backend is unreachable. Please check the URL and ensure the server is running.' };
  }
}

/* ─── Settings ───────────────────────────────────────────────────────────── */
async function saveSettings(payload) {
  const current = await getMergedSettings();
  const next    = { ...current, ...(payload && typeof payload === 'object' ? payload : {}) };
  next.backendBaseUrl = sanitizeBackendUrl(next.backendBaseUrl);
  next.cacheTtlMs     = clamp(next.cacheTtlMs,   60000,  7*24*60*60*1000, DEFAULT_SETTINGS.cacheTtlMs);
  next.batchSize      = clamp(next.batchSize,     1,      50,              DEFAULT_SETTINGS.batchSize);
  next.queueDelayMs   = clamp(next.queueDelayMs,  100,    2000,            DEFAULT_SETTINGS.queueDelayMs);
  next.throttleMs     = clamp(next.throttleMs,    0,      15000,           DEFAULT_SETTINGS.throttleMs);
  await runtimeApi.storage.local.set({ [STORAGE.SETTINGS]: next });
  return { ok: true, settings: next };
}

async function getStoredSettings() {
  const s = await runtimeApi.storage.local.get(STORAGE.SETTINGS);
  return s[STORAGE.SETTINGS] || null;
}

async function getMergedSettings() {
  const stored = await getStoredSettings();
  return { ...DEFAULT_SETTINGS, ...(stored || {}) };
}

/* ─── Helpers ────────────────────────────────────────────────────────────── */
function sanitizeBackendUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return '';
  try {
    const p = new URL(value.trim());
    if (!['http:', 'https:'].includes(p.protocol)) return '';
    p.hash = '';
    return p.toString().replace(/\/$/, '');
  } catch { return ''; }
}

function clamp(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback ?? min;
  return Math.min(max, Math.max(min, n));
}

function wait(ms) { return new Promise(r => setTimeout(r, ms)); }
function capitalise(s) { return s ? s[0].toUpperCase() + s.slice(1) : s; }
