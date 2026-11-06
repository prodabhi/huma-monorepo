// Small statistics for the detection features (features.mjs): plain functions over arrays of numbers, nothing kept.
export const mean = v => (v.length ? v.reduce((a, b) => a + b, 0) / v.length : null);
export const sd = v => { if (v.length < 2) return null; const m = mean(v); return Math.sqrt(v.reduce((a, b) => a + (b - m) ** 2, 0) / v.length); };
/** Coefficient of variation: the spread as a share of the mean. */
export const cv = v => { if (v.length < 2) return null; const m = mean(v); return m ? sd(v) / Math.abs(m) : null; };
export const sorted = v => [...v].sort((a, b) => a - b);
/** The value at share `p` (0..1) of the sorted values, interpolated. */
export function quantile(v, p) {
  if (!v.length) return null;
  const s = sorted(v), at = (s.length - 1) * p, lo = Math.floor(at), hi = Math.ceil(at);
  return s[lo] + (s[hi] - s[lo]) * (at - lo);
}
export const median = v => quantile(v, 0.5);
export const share = (v, test) => (v.length ? v.filter(test).length / v.length : null);
export const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));

/** Each value's rank (1-based, ties averaged). */
export function ranks(v) {
  const order = v.map((x, i) => [x, i]).sort((a, b) => a[0] - b[0]), out = new Array(v.length);
  for (let i = 0; i < order.length;) {
    let j = i; while (j < order.length && order[j][0] === order[i][0]) j++;
    for (let k = i; k < j; k++) out[order[k][1]] = (i + j + 1) / 2;
    i = j;
  }
  return out;
}
/** Pearson correlation, or null when either side doesn't vary. */
export function pearson(x, y) {
  const n = Math.min(x.length, y.length); if (n < 3) return null;
  const mx = mean(x.slice(0, n)), my = mean(y.slice(0, n));
  let sxy = 0, sxx = 0, syy = 0;
  for (let i = 0; i < n; i++) { const dx = x[i] - mx, dy = y[i] - my; sxy += dx * dy; sxx += dx * dx; syy += dy * dy; }
  return sxx && syy ? sxy / Math.sqrt(sxx * syy) : null;
}
export const spearman = (x, y) => pearson(ranks(x), ranks(y));
/** Lag-k autocorrelation of a series. */
export function autocorrelation(v, lag = 1) {
  if (v.length < lag + 3) return null;
  const m = mean(v); let num = 0, den = 0;
  for (let i = 0; i < v.length; i++) { den += (v[i] - m) ** 2; if (i >= lag) num += (v[i] - m) * (v[i - lag] - m); }
  return den ? num / den : null;
}
/** How strongly the values in `a` run larger than those in `b` (Mann-Whitney U as a z-score): about 0 when alike. */
export function shiftZ(a, b, min = 8) {
  if (a.length < min || b.length < min) return null;
  const r = ranks([...a, ...b]);
  let rankA = 0; for (let i = 0; i < a.length; i++) rankA += r[i];
  const n1 = a.length, n2 = b.length, u = rankA - n1 * (n1 + 1) / 2;
  return (u - n1 * n2 / 2) / Math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12);
}
/** Least-squares line through (x, y): { slope, intercept }. */
export function linearFit(x, y) {
  const n = Math.min(x.length, y.length); if (n < 2) return null;
  const mx = mean(x.slice(0, n)), my = mean(y.slice(0, n));
  let sxy = 0, sxx = 0;
  for (let i = 0; i < n; i++) { sxy += (x[i] - mx) * (y[i] - my); sxx += (x[i] - mx) ** 2; }
  return sxx ? { slope: sxy / sxx, intercept: my - (sxy / sxx) * mx } : null;
}
/**
 * The Hurst exponent by detrended fluctuation analysis: about 0.5 for independent values, higher (0.6–0.8) for the
 * long-range correlated series people produce. Needs 64 values or more.
 */
export function dfaHurst(v) {
  const n = v.length; if (n < 64) return null;
  const m = mean(v), profile = []; let sum = 0;
  for (const x of v) { sum += x - m; profile.push(sum); }
  const sizes = [], xs = [], ys = [];
  for (let s = 4; s <= Math.floor(n / 4); s = Math.max(s + 1, Math.round(s * 1.4))) sizes.push(s);
  for (const s of sizes) {
    const boxes = Math.floor(n / s); let f2 = 0;
    for (let b = 0; b < boxes; b++) {
      const xsBox = Array.from({ length: s }, (_, i) => i), seg = profile.slice(b * s, (b + 1) * s), fit = linearFit(xsBox, seg);
      if (!fit) continue;
      for (let i = 0; i < s; i++) f2 += (seg[i] - (fit.intercept + fit.slope * i)) ** 2;
    }
    const f = Math.sqrt(f2 / (boxes * s));
    if (f > 0) { xs.push(Math.log(s)); ys.push(Math.log(f)); }
  }
  return linearFit(xs, ys)?.slope ?? null;
}
/** The error function (Abramowitz & Stegun 7.1.26, within 1.5e-7). */
export function erf(x) {
  const sign = x < 0 ? -1 : 1, t = 1 / (1 + 0.3275911 * Math.abs(x));
  const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x);
  return sign * y;
}
export const normalCDF = (x, mu = 0, sigma = 1) => 0.5 * (1 + erf((x - mu) / (sigma * Math.SQRT2)));
/** The ex-Gaussian distribution's CDF (a normal plus an exponential tail). */
export function exGaussianCDF(x, mu, sigma, tau) {
  const u = (x - mu) / sigma, v = sigma / tau;
  const tail = Math.exp(-(x - mu) / tau + (sigma * sigma) / (2 * tau * tau)) * normalCDF(u - v);
  return clamp(normalCDF(u) - (Number.isFinite(tail) ? tail : 0), 0, 1);
}
/** The Kolmogorov–Smirnov distance between the values and a CDF: 0 is a perfect fit, 0.5 and more none at all. */
export function ksDistance(v, cdf) {
  const s = sorted(v), n = s.length; if (!n) return null;
  let worst = 0;
  for (let i = 0; i < n; i++) { const f = cdf(s[i]); worst = Math.max(worst, Math.abs(f - i / n), Math.abs(f - (i + 1) / n)); }
  return worst;
}
/** Ex-Gaussian parameters by the method of moments, and the KS distance of the values from that fit. */
export function exGaussianFit(v) {
  if (v.length < 30) return null;
  const m = mean(v), s = sd(v), skew = s ? mean(v.map(x => ((x - m) / s) ** 3)) : 0;
  const tau = s * Math.cbrt(Math.max(0.02, skew) / 2), sigma2 = s * s - tau * tau;
  if (!(sigma2 > 0)) return { mu: m - tau, sigma: s * 0.3, tau, ks: ksDistance(v, x => exGaussianCDF(x, m - tau, s * 0.3, tau)) };
  const sigma = Math.sqrt(sigma2), mu = m - tau;
  return { mu, sigma, tau, ks: ksDistance(v, x => exGaussianCDF(x, mu, sigma, tau)) };
}
/** The KS distance of positive values from the log-normal fitted to them. */
export function logNormalKS(v) {
  const logs = v.filter(x => x > 0).map(Math.log); if (logs.length < 30) return null;
  const m = mean(logs), s = sd(logs); if (!s) return 0.5;
  return ksDistance(logs, x => normalCDF(x, m, s));
}
/** Power of a series (sampled every `dt` seconds) in a frequency band, as a share of its power above `floorHz`. */
export function bandPowerShare(samples, dt, lowHz, highHz, floorHz = 2) {
  const n = samples.length; if (n < 16) return null;
  // Detrended first: a steady drift is no oscillation.
  const fit = linearFit(samples.map((_, i) => i), samples), x = samples.map((v, i) => v - (fit ? fit.intercept + fit.slope * i : 0));
  let band = 0, total = 0;
  for (let k = 1; k < n / 2; k++) {
    const f = k / (n * dt); if (f < floorHz) continue;
    let re = 0, im = 0;
    for (let t = 0; t < n; t++) { const a = (2 * Math.PI * k * t) / n; re += x[t] * Math.cos(a); im -= x[t] * Math.sin(a); }
    const p = re * re + im * im; total += p; if (f >= lowHz && f <= highHz) band += p;
  }
  return total ? band / total : null;
}
