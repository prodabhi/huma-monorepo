// Reader-owned V4 profile, separate from the unchanged V3 replay profile.
export const KIND = 'huma-compact-assurance-public-proof-v4';
export const PROFILE = 'assurance256-v1';
export const KIND_V5 = 'huma-compact-assurance-public-proof-v5';
export const PROFILE_V5 = 'assurance256-v2';
export const PROFILE_CP32 = 'assurance256-cp32-v1';
export const PROFILE_64 = 'assurance64-v1';
export const PROFILE_128 = 'assurance128-cp32-v1';
const STANDARD = { operations: 1536, samples: 516, bytes: 1024 };
export const PROFILES = Object.freeze({
  [PROFILE]: Object.freeze({ ...STANDARD, profile: PROFILE, version: 4, kind: KIND, key: 'assurance256.vk', abi: 'assurance-abi.json', publicBytes: 3008, checkpoints: 8 }),
  [PROFILE_V5]: Object.freeze({ ...STANDARD, profile: PROFILE_V5, version: 5, kind: KIND_V5, key: 'assurance256-v2.vk', abi: 'assurance-abi.json', publicBytes: 3008, checkpoints: 8 }),
  [PROFILE_CP32]: Object.freeze({ ...STANDARD, profile: PROFILE_CP32, version: 5, kind: KIND_V5, key: 'assurance256-cp32.vk', abi: 'assurance-cp32-abi.json', publicBytes: 4544, checkpoints: 32 }),
  [PROFILE_64]: Object.freeze({ operations: 372, samples: 132, bytes: 256, profile: PROFILE_64, version: 5, kind: KIND_V5, key: 'assurance64.vk', abi: 'assurance-abi.json', publicBytes: 3008, checkpoints: 8 }),
  [PROFILE_128]: Object.freeze({ operations: 756, samples: 260, bytes: 512, profile: PROFILE_128, version: 5, kind: KIND_V5, key: 'assurance128-cp32.vk', abi: 'assurance-cp32-abi.json', publicBytes: 4544, checkpoints: 32 }),
});
export function profileForProof(source) {
  const value = JSON.parse(source), selected = Object.hasOwn(PROFILES, value?.profile) ? PROFILES[value.profile] : undefined;
  if (!selected || selected.kind !== value.kind) throw new Error('Unsupported writing-policy profile.');
  return selected;
}
export const ASSETS = Object.freeze({
  'assurance256.vk': { bytes: 3680, sha256: '1cab7a6b3ce5947916ad8bc09616c801de66f896eecc6677dbaf43284696a496' },
  'assurance256-v2.vk': { bytes: 3680, sha256: '9faf09ad7af8b403cd8ea02cd1f896c96971f19bc03182660cc2008c8218f714' },
  'assurance-abi.json': { bytes: 2557, sha256: '729cc9a345f5b8a37549cddbe3ef848edb7bfc8d051867c016928ddabbf3fdc5' },
  'assurance256-cp32.vk': { bytes: 3680, sha256: '5b3a98abe325feca9d5187668fc3e97ab0486b0a0f1e5cb2f904de1c67621b11' },
  'assurance-cp32-abi.json': { bytes: 2559, sha256: '39aa83ef3ddeb5cb43c4f424d39f9ae349cc031241e5650da3678b3f96b9d075' },
  'assurance64.vk': { bytes: 3680, sha256: 'bf1319ff4d1bc49029fa4875a9c5f529a5d17ec85bae5547ace311bbbbc3d3df' },
  'assurance128-cp32.vk': { bytes: 3680, sha256: 'f8360140d689befc8f23b1794d5f0a9fe373a415804bd8881acdc4886af7f19c' },
  'long-chunk.vk': { bytes: 3680, sha256: 'b9e817091fcdd28ebbd43c21b068ab9a0e776f6cafa198335e531195ca18dfeb' },
  'long-final1024.vk': { bytes: 3680, sha256: '42d690d98c77c3ad2b83d986b12a5397bd8a1c634a55a316295c5bcd631c13fd' },
  'long-final4096.vk': { bytes: 3680, sha256: '4d6e31a67bf2a1b294b4cce61a31764e589f7d70357b5330fc94c51a63b046df' },
  'long-final10000.vk': { bytes: 3680, sha256: '842cdcaebc3c382f4c4f4b478cf08a8505be2a54ebe0e789270cf033aa013ce8' },
  'long2-final1024.vk': { bytes: 3680, sha256: 'ccc8f6538f604edcbc026c2a04b5d7bde7bbcad6652d2184ff5db94b9fafaf51' },
  'long2-final4096.vk': { bytes: 3680, sha256: '79315d8e8666d5922d49acf9879787c77253cae19ecca3eb7ff78e1b5fce2f16' },
  'long2-final10000.vk': { bytes: 3680, sha256: '8c7eaff3a810517bd82ed2d7de5747ee8f8fe4f4f57b4f31db3b62f8955e7f77' },
  'long3-chunk1024.vk': { bytes: 3680, sha256: '8d8a3bae78664b1b3883b94a1e361d56ee573b7102acc5c18bfd6e721490396b' },
  'long3-final1024.vk': { bytes: 3680, sha256: 'c9ce374434fdda60af5c436336410bacc83bdadfaef034ac33432d82a1b3cc28' },
  'long3-chunk4096.vk': { bytes: 3680, sha256: 'a73280bcdb84a952e6ca84bc7bcf264dcaea0ee480b3dde00933d7d123782894' },
  'long3-final4096.vk': { bytes: 3680, sha256: '75414e8be776c623d3eca1177fa1ba2af5f094cd6605427826e0af8c1e5ee95f' },
  'long3-chunk10000.vk': { bytes: 3680, sha256: 'fd0f825f50bfc0312b617bc02141c73a2691df7f444eee5ddd78b219cd3d0ba0' },
  'long3-final10000.vk': { bytes: 3680, sha256: '842cdcaebc3c382f4c4f4b478cf08a8505be2a54ebe0e789270cf033aa013ce8' },
});
export const hex = bytes => Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
export const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
export async function checkAsset(name, bytes) {
  const pin = ASSETS[name];
  if (!pin || !(bytes instanceof Uint8Array) || bytes.length !== pin.bytes || hex(await sha256(bytes)) !== pin.sha256) throw new Error('Unrecognized writing-policy verifier asset.');
  return bytes;
}
export async function loadAsset(name) {
  if (!Object.hasOwn(ASSETS, name)) throw new Error('Unknown policy verifier asset.');
  const response = await fetch(new URL('./assets/' + name, import.meta.url), { credentials: 'omit', redirect: 'error' });
  if (!response.ok || !response.body) throw new Error('Policy verifier asset unavailable.');
  const reader = response.body.getReader(), chunks = []; let size = 0;
  try {
    while (true) { const { value, done } = await reader.read(); if (done) break;
      size += value.length; if (size > ASSETS[name].bytes) throw new Error('Oversized verifier asset.'); chunks.push(value); }
  } finally { await reader.cancel(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return checkAsset(name, bytes);
}
