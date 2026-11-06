// Reader-owned experimental profile. Producers never choose a verification key.
export const KIND = 'huma-media-public-proof-v1';
export const PROFILE = 'media-membership-v1';
export const MAX_EXPORT_BYTES = 64 * 1024;
export const MAX_MASTER_BYTES = 32 * 1024 * 1024;
export const VK_PIN = Object.freeze({ bytes: 3680, sha256: '8cada434b665ae722250b38cfc394dab269e71aa1efec9365fef1e347fbeae9a' });
export const hex = bytes => Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
export const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
export async function checkKey(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== VK_PIN.bytes || hex(await sha256(bytes)) !== VK_PIN.sha256) throw new Error('Unrecognized media verification key.');
  return bytes;
}
export async function loadKey() {
  // This path is bundled beside the existing bounded crypto worker and assets.
  const response = await fetch(new URL('./assets/media-membership.vk', import.meta.url), { credentials: 'omit', redirect: 'error' });
  if (!response.ok || !response.body) throw new Error('Media verification key unavailable.');
  const reader = response.body.getReader(), chunks = []; let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      size += value.length; if (size > VK_PIN.bytes) throw new Error('Oversized verification key.');
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return checkKey(bytes);
}
