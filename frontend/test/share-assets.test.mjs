import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { shareAssetFiles } from '../share-assets.mjs';
import { packagePublication } from '../../backend/scripts/package-publication.mjs';
import { createHash } from 'node:crypto';

test('approval graph includes lazy chunks and rejects missing references or escaping paths', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'huma-share-graph-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = path.join(root, 'dist/share'); await mkdir(path.join(directory, '.vite'), { recursive: true });
  const manifest = { 'index.html': { file: 'assets/main-a.js', isEntry: true, dynamicImports: ['wallet'] },
    wallet: { file: 'assets/index.web-b.js', assets: ['assets/wallet-c.wasm'] } };
  const save = () => writeFile(path.join(directory, '.vite/manifest.json'), JSON.stringify(manifest));
  await writeFile(path.join(directory, 'index.html'), '<script src="/share/assets/main-a.js"></script>'); await save();
  assert.ok((await shareAssetFiles(root)).includes('assets/index.web-b.js'));
  manifest.wallet.file = '../private.json'; await save(); await assert.rejects(shareAssetFiles(root));
  delete manifest.wallet; await save(); await assert.rejects(shareAssetFiles(root));
});

test('host package verifies every copied hash, excludes private sources and refuses overwrite', async t => {
  const parent = await mkdtemp(path.join(tmpdir(), 'huma-host-package-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const directory = path.join(parent, 'bundle');
  const result = await packagePublication(directory);
  const source = await readFile(path.join(directory, 'bundle-manifest.json'), 'utf8'), manifest = JSON.parse(source);
  assert.equal(Object.keys(manifest.files).length, result.files);
  for (const [name, expected] of Object.entries(manifest.files)) {
    assert.equal(/(?:^|\/)(?:node_modules|test|tests|data|candidates|noir-tools|NoirEngine)(?:\/|$)|\.env|\.huma$/.test(name), false, name);
    const bytes = await readFile(path.join(directory, name));
    assert.equal((await stat(path.join(directory, name))).mode & 0o777, 0o644);
    assert.equal(bytes.length, expected.bytes);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), expected.sha256);
  }
  assert.ok(manifest.files['frontend/dist/compact/assets/assurance256-v2.vk']);
  assert.ok(manifest.files['frontend/dist/share/.vite/manifest.json']);
  await assert.rejects(packagePublication(directory), { code: 'EEXIST' });
  assert.equal(await readFile(path.join(directory, 'bundle-manifest.json'), 'utf8'), source);
});
