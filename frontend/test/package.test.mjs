import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { fixed } from '../../backend/scripts/package-publication.mjs';

// The host runs only the files scripts/package-publication.mjs copies; a server file importing one it leaves out
// stops the site at startup (as documents.mjs did on 31 October). Follows every relative import of the modules
// the server runs (pages under web/pages/ import by their served URL, which this doesn't map).
test('every module the package ships has its local imports shipped too', async () => {
  const root = fileURLToPath(new URL('../../', import.meta.url)), shipped = new Set(fixed);
  for (const file of fixed.filter(name => name.endsWith('.mjs') && !name.startsWith('frontend/pages/'))) {
    const source = await readFile(path.join(root, file), 'utf8');
    for (const [, local] of source.matchAll(/(?:from|import\() *'(\.{1,2}\/[^']+\.mjs)'/g)) {
      const target = path.relative(root, path.resolve(root, path.dirname(file), local));
      assert.ok(shipped.has(target), `${file} imports ${target}, which the package leaves out`);
    }
  }
});
