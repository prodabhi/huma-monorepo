// Uploads the Mac app's downloads as GitHub release assets, where huma.social sends browsers and the app (frontend/releases.mjs):
//   node backend/scripts/github-release.mjs installer [file]   build/release/Huma.dmg as Huma-<version>.dmg in release v<version>
//   node backend/scripts/github-release.mjs engine             the first 2^21 proving points as bn254_g1_compressed-3e1ac096.dat
//                                                              in release "engine" (HumaCore ProvingSetup checks the same fingerprint)
// Needs GITHUB_TOKEN: a token that can write this repository's contents (a fine-grained token with Contents: read and write).
// An asset is written once: one already there with the same size is left as it is, a different one stops the upload.
import { openSync, readSync, closeSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { RELEASES_URL, ENGINE_TAG } from '../../frontend/releases.mjs';

const root = new URL('../../', import.meta.url).pathname;
const repo = process.env.HUMA_RELEASES_REPO || new URL(RELEASES_URL).pathname.split('/').slice(1, 3).join('/');
const token = process.env.GITHUB_TOKEN;
if (!token) throw new Error('Set GITHUB_TOKEN to a token that can write ' + repo + "'s releases.");
const [what, given] = process.argv.slice(2);

let tag, name, body, type;
if (what === 'installer') {
  const version = readFileSync(root + 'extra/Resources/Info.plist', 'utf8').match(/<key>CFBundleShortVersionString<\/key>\s*<string>([\d.]+)<\/string>/)?.[1];
  const served = readFileSync(root + 'frontend/registry.mjs', 'utf8').match(/const HUMA_RELEASE = '([\d.]+)'/)?.[1];
  if (!version || version !== served) throw new Error(`App version ${version} doesn't match HUMA_RELEASE ${served} in frontend/registry.mjs.`);
  tag = 'v' + version; name = `Huma-${version}.dmg`; type = 'application/x-apple-diskimage';
  body = readFileSync(given ?? root + 'build/release/Huma.dmg');
} else if (what === 'engine') {
  // The same first 2^21 points backend/integrations/noir/package.py takes from the published setup.
  const SHA256 = '3e1ac09652ee9df779a4955fb8f7050620c7b1ee7f18566581bd00326b06be37';
  tag = ENGINE_TAG; name = 'bn254_g1_compressed-3e1ac096.dat'; type = 'application/octet-stream';
  body = Buffer.alloc((1 << 21) * 32);
  const fd = openSync(given ?? root + 'build/research/noir-crs/bn254_g1_compressed.dat', 'r');
  try { if (readSync(fd, body, 0, body.length, 0) !== body.length) throw new Error('The setup file is too short.'); } finally { closeSync(fd); }
  if (createHash('sha256').update(body).digest('hex') !== SHA256) throw new Error('The proving points differ from the pinned fingerprint.');
} else throw new Error('Usage: node backend/scripts/github-release.mjs installer [file] | engine [setup-file]');

const api = async (url, options = {}) => {
  const response = await fetch(url.startsWith('https://') ? url : 'https://api.github.com/repos/' + repo + url, { ...options,
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', ...options.headers },
    signal: AbortSignal.timeout(600000) });
  if (response.status === 404 && options.missing) return null;
  if (!response.ok) throw new Error(`GitHub ${options.method ?? 'GET'} ${url.split('?')[0]}: ${response.status} ${(await response.text()).slice(0, 300)}`);
  return response.json();
};
const release = await api('/releases/tags/' + tag, { missing: true }) ?? await api('/releases', { method: 'POST',
  headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tag_name: tag, name: tag === ENGINE_TAG ? 'Proving setup' : 'Huma ' + tag.slice(1),
    body: tag === ENGINE_TAG ? "The Mac app's proving points, downloaded on first use." : 'The Mac app.', make_latest: tag === ENGINE_TAG ? 'false' : 'true' }) });
const existing = release.assets.find(asset => asset.name === name);
if (existing) {
  if (existing.size !== body.length || existing.state !== 'uploaded') throw new Error(`${tag}/${name} already holds a different file.`);
  console.log(`${tag}/${name} is already uploaded.`); process.exit(0);
}
const uploaded = await api(`https://uploads.github.com/repos/${repo}/releases/${release.id}/assets?name=${encodeURIComponent(name)}`, {
  method: 'POST', headers: { 'Content-Type': type, 'Content-Length': String(body.length) }, body });
if (uploaded.size !== body.length) throw new Error('Uploaded size differs.');
console.log(`Uploaded ${tag}/${name}: ${body.length} bytes, sha256 ${createHash('sha256').update(body).digest('hex')}\n  ${uploaded.browser_download_url}`);
