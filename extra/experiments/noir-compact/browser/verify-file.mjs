#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises';
import { verifyCompactPublic } from './node-verifier.mjs';

try {
  const args = process.argv.slice(2), filename = args.shift(), options = {};
  if (!filename || filename.startsWith('--')) throw new Error('Usage: verify-file.mjs proof.json [--text text.txt] [--expected-key fingerprint]');
  const decode = bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  while (args.length) {
    const option = args.shift(), value = args.shift();
    if (!value || !['--text', '--expected-key'].includes(option)) throw new Error('Unknown or incomplete option.');
    const key = option === '--text' ? 'text' : 'expectedKey';
    if (Object.hasOwn(options, key)) throw new Error('Duplicate option.');
    if (option === '--text') {
      if ((await stat(value)).size > 65536) throw new Error('Text exceeds 64 KiB.');
      options.text = decode(await readFile(value));
    } else options.expectedKey = value;
  }
  if ((await stat(filename)).size > 512 * 1024) throw new Error('Proof exceeds 512 KiB.');
  const source = decode(await readFile(filename));
  // All verifier assets come from disk. Prove that no runtime fetch is needed.
  globalThis.fetch = () => { throw new Error('Network access is disabled for this file verifier.'); };
  console.log(JSON.stringify(await verifyCompactPublic(source, options), null, 2));
} catch (error) { console.error(error instanceof Error ? error.message : 'Verification failed.'); process.exitCode = 1; }
