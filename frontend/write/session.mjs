// Server-anchored time (frontend/sessions.mjs): at Start the page asks huma.social for this session's nonce, which the
// recorder makes the page's public nonce, so the server can later check the writing really took as long as it says.
/** A fresh session from the server: { nonce (32 hex characters), key (the event stream's signing key, 64 hex
 *  characters, collector.mjs), canary (the session's canary word, canary.mjs) }, or null when it can't be had. */
export async function sessionNonce() {
  try {
    const response = await fetch('/api/sessions', { method: 'POST', signal: AbortSignal.timeout(15000) });
    const issued = response.ok ? await response.json() : null, nonce = issued?.nonce;
    if (typeof nonce !== 'string' || !/^[a-f0-9]{32}$/.test(nonce) || /^0+$/.test(nonce)) return null;
    return { nonce, key: typeof issued.key === 'string' && /^[a-f0-9]{64}$/.test(issued.key) ? issued.key : null,
      canary: typeof issued.canary === 'string' && /^[A-Za-z]{2,24}$/.test(issued.canary) ? issued.canary : null };
  } catch { return null; }
}
