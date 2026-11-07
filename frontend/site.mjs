// The site's public address, for the links and cards the server writes itself (preview images, analytics URLs).
// HUMA_SITE_URL sets it, as an origin (https://staging.example, no path); unset, it's huma.social. Pages written in a
// browser use the address they were loaded from instead (location.origin), which is this same site once deployed.
export const DEFAULT_SITE_URL = 'https://huma.social';

/** HUMA_SITE_URL as a bare origin, or huma.social when unset. Throws on a value that isn't one, so a typo fails at start. */
export function siteURL(env = process.env) {
  const value = (env.HUMA_SITE_URL ?? '').trim();
  if (!value) return DEFAULT_SITE_URL;
  let url;
  try { url = new URL(value); } catch { throw new Error(`HUMA_SITE_URL is not a URL: ${value}`); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/')
    throw new Error(`HUMA_SITE_URL must be an origin like https://huma.social, with no path: ${value}`);
  return url.origin;
}
