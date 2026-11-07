// Reader-selected assets. An export can never supply or replace these pins.
export const PROFILE = 'cast256-v1';
export const KIND = 'huma-compact-public-proof-v1';
export const MAX_EXPORT_BYTES = 512 * 1024;
export const ASSETS = Object.freeze({
  'cast256.vk': { bytes: 3680, sha256: '149d13f114a80bc03df8966aa5b716ba86acc383c48c620e0bdb1afb09f4b600' },
  'journal-abi.json': { bytes: 2611, sha256: 'd3ac50086728791ab41503666e4f5454b9bfe30000abf2ddfefd624a7c21c952' },
  'g2.dat': { bytes: 128, sha256: '01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f' },
  'barretenberg.wasm': { bytes: 10571126, sha256: '662ed50ca7275398817ae780733a9fc1ad1681776c75615cb81ecd737bca17e6' },
  'barretenberg-threads.wasm': { bytes: 10475904, sha256: '454527654830b95af0c75d639194587119f4f25e20739254c2eb7bc7c5fec5a9' },
});
export const hex = bytes => Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
export const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

export async function checkAsset(name, bytes) {
  const pin = ASSETS[name];
  if (!pin || !(bytes instanceof Uint8Array) || bytes.length !== pin.bytes || hex(await sha256(bytes)) !== pin.sha256)
    throw new Error('Trusted verifier asset does not match its pin.');
  return bytes;
}

export async function loadAsset(name) {
  if (!Object.hasOwn(ASSETS, name)) throw new Error('Unknown verifier asset.');
  const response = await fetch(new URL('./assets/' + name, import.meta.url), { credentials: 'omit', redirect: 'error' });
  if (!response.ok || !response.body) throw new Error('Local verifier asset is unavailable.');
  const reader = response.body.getReader(), chunks = []; let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > ASSETS[name].bytes) throw new Error('Verifier asset exceeds its limit.');
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return checkAsset(name, bytes);
}
