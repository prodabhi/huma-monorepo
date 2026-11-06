// Server-anchored time (frontend/sessions.mjs): at Start the page asks huma.social for this session's nonce, which the
// recorder makes the page's public nonce, so the server can later check the writing really took as long as it says.
/** A fresh session nonce from the server (32 hex characters), or null when it can't be had. */
export async function sessionNonce() {
  try {
    const response = await fetch('/api/sessions', { method: 'POST', signal: AbortSignal.timeout(15000) });
    const nonce = response.ok ? (await response.json())?.nonce : null;
    return typeof nonce === 'string' && /^[a-f0-9]{32}$/.test(nonce) && !/^0+$/.test(nonce) ? nonce : null;
  } catch { return null; }
}
