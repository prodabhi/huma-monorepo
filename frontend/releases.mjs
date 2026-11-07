// The Mac app's downloads, kept as GitHub release assets (backend/scripts/github-release.mjs uploads them):
//   the installer   v<version>/Huma-<version>.dmg   behind /download/Huma.dmg (and the update feed, appcast.xml)
//   proving points  engine/<name>.dat                behind /engine/proving-setup (HumaCore ProvingSetup checks their fingerprint)
// HUMA_RELEASES_URL points at another repository's release downloads.
export const RELEASES_URL = 'https://github.com/prodabhi/huma-monorepo/releases/download';
export const ENGINE_TAG = 'engine';

const base = (env = process.env) => (env.HUMA_RELEASES_URL || RELEASES_URL).replace(/\/+$/, '');
export const installerURL = (version, env) => `${base(env)}/v${version}/Huma-${version}.dmg`;
export const engineURL = (name, env) => `${base(env)}/${ENGINE_TAG}/${name}`;

/** Whether a release asset is uploaded yet, so a link never lands on GitHub's 404. Asked at most once a minute per link. */
const checks = new Map();
export async function released(url, now = Date.now()) {
  let check = checks.get(url);
  if (!check || check.at < now - 60000) {
    const ready = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(10000) }).then(response => response.ok, () => false);
    checks.set(url, check = { at: now, ready });
  }
  return check.ready;
}
