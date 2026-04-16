/**
 * PhisShield — Shared Utilities (utils.js)
 * Injected into every page before content-script.js
 * Also importable by background.js via self.PhisShieldUtils
 */
'use strict';

const PhisShieldUtils = (() => {

  /* ─────────────────────────────────────────────────────────────────────────
   * SCORING
   * New formula:  riskScore = ((malicious + suspicious×0.5) / totalEngines) × 100
   * Categories:   0-20  → safe
   *               21-60 → suspicious
   *               61-100→ malicious
   * ───────────────────────────────────────────────────────────────────────── */

  /**
   * Normalise raw VirusTotal stats into a 0-100 risk score.
   * @param {{ malicious:number, suspicious:number, harmless:number,
   *            undetected:number, timeout:number }} stats
   * @returns {number} integer 0-100
   */
  function calcRiskScore(stats) {
    if (!stats) return 50;
    const malicious  = safeInt(stats.malicious);
    const suspicious = safeInt(stats.suspicious);
    const harmless   = safeInt(stats.harmless);
    const undetected = safeInt(stats.undetected);
    const timeout    = safeInt(stats.timeout);
    const total      = malicious + suspicious + harmless + undetected + timeout;
    if (total === 0) return 50;
    const raw = ((malicious + suspicious * 0.5) / total) * 100;
    return clamp(Math.round(raw), 0, 100);
  }

  /**
   * Map a 0-100 risk score to a verdict string.
   */
  function scoreToVerdict(score) {
    if (score <= 20)  return 'safe';
    if (score <= 60)  return 'suspicious';
    return 'malicious';
  }

  /**
   * Map a verdict to its display label.
   */
  function verdictLabel(verdict) {
    return { safe: 'Safe', suspicious: 'Suspicious', malicious: 'Malicious', unknown: 'Unknown' }[verdict] || 'Unknown';
  }

  /**
   * Map a verdict to its CSS colour token (as hex for Canvas use).
   */
  function verdictColor(verdict) {
    return { safe: '#22d87a', suspicious: '#f5b935', malicious: '#f24444', unknown: '#8fa0b8' }[verdict] || '#8fa0b8';
  }

  /* ─────────────────────────────────────────────────────────────────────────
   * URL NORMALISATION
   * ───────────────────────────────────────────────────────────────────────── */

  /**
   * Normalise a raw URL string to a canonical http/https URL.
   * Returns null for non-http/https or invalid URLs.
   */
  function normalizeUrl(value, base) {
    if (typeof value !== 'string' || !value.trim()) return null;
    let raw = value.trim();
    // Auto-prepend https when scheme is missing
    if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
    try {
      const p = new URL(raw, base || undefined);
      if (!['http:', 'https:'].includes(p.protocol)) return null;
      p.hash = ''; p.username = ''; p.password = '';
      p.hostname = p.hostname.toLowerCase();
      if ((p.protocol === 'http:'  && p.port === '80')  ||
          (p.protocol === 'https:' && p.port === '443')) p.port = '';
      return p.toString();
    } catch { return null; }
  }

  /* ─────────────────────────────────────────────────────────────────────────
   * NUMBER HELPERS
   * ───────────────────────────────────────────────────────────────────────── */

  function safeInt(v) {
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 0;
  }

  function clamp(v, min, max) {
    return Math.min(max, Math.max(min, v));
  }

  /* ─────────────────────────────────────────────────────────────────────────
   * PUBLIC API
   * ───────────────────────────────────────────────────────────────────────── */
  return Object.freeze({
    calcRiskScore,
    scoreToVerdict,
    verdictLabel,
    verdictColor,
    normalizeUrl,
    safeInt,
    clamp
  });
})();

// Make available as a global for content-script.js (same page context)
if (typeof window !== 'undefined') window.PhisShieldUtils = PhisShieldUtils;
