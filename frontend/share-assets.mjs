import { readFile } from 'node:fs/promises';
import path from 'node:path';

// The build manifest defines the complete public chunk graph, including lazy
// sign-in chunks. Never package arbitrary files from a possibly stale dist/.
// Privy's sign-in UI splits into roughly 260 lazy chunks; the cap leaves room above that.
const LIMIT = 512;
export async function shareAssetFiles(webRoot) {
  const directory = path.join(webRoot, 'dist/share');
  const source = await readFile(path.join(directory, '.vite/manifest.json'), 'utf8');
  if (Buffer.byteLength(source) > 1024 * 1024) throw Error('Approval build manifest exceeds limits.');
  const manifest = JSON.parse(source), entry = manifest['index.html'];
  if (!entry?.isEntry) throw Error('Approval build entry is missing.');
  const files = new Set(['index.html', '.vite/manifest.json']), visited = new Set();
  const add = file => {
    if (typeof file !== 'string' || !/^assets\/[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:js|css|wasm|woff2|png|svg)$/.test(file)) throw Error('Invalid approval asset path.');
    files.add(file);
    if (files.size > LIMIT) throw Error('Approval build exceeds file limit.');
  };
  function visit(key) {
    if (visited.has(key)) return;
    visited.add(key);
    if (visited.size > LIMIT) throw Error('Approval build exceeds chunk limit.');
    const chunk = manifest[key];
    if (!chunk || typeof chunk !== 'object') throw Error('Approval build dependency is missing.');
    add(chunk.file);
    for (const field of ['css', 'assets']) {
      if (chunk[field] !== undefined && !Array.isArray(chunk[field])) throw Error('Invalid approval build assets.');
      for (const file of chunk[field] ?? []) add(file);
    }
    for (const field of ['imports', 'dynamicImports']) {
      if (chunk[field] !== undefined && !Array.isArray(chunk[field])) throw Error('Invalid approval build imports.');
      for (const dependency of chunk[field] ?? []) visit(dependency);
    }
  }
  visit('index.html');
  const html = await readFile(path.join(directory, 'index.html'), 'utf8');
  if (!html.includes('/share/' + entry.file)) throw Error('Approval page differs from its build manifest.');
  return [...files].sort();
}
