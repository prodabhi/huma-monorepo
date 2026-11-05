#!/usr/bin/env node
// Offline package verification using the same bounded reader as the browser.
import { createReadStream } from 'node:fs';
import { verify } from '../../../frontend/verify-core/node.mjs';
import { boundedJSON, ENVELOPE_KIND, fullMatch, writingDisclosure } from '../../../frontend/verify-core/contract.mjs';
async function boundedFile(file, limit) {
    const chunks = []; let size = 0;
    for await (const chunk of createReadStream(file)) {
        size += chunk.length;
        if (size > limit) throw new Error('Input exceeds its size limit.');
        chunks.push(chunk);
    }
    return Buffer.concat(chunks);
}
const textFile = async (file, limit) => new TextDecoder('utf-8', { fatal: true }).decode(await boundedFile(file, limit));
try {
    const [file, ...arguments_] = process.argv.slice(2);
    if (!file || file.startsWith('--')) throw new Error('Usage: node zkvm/scripts/verify-file.mjs proof.json [--text text.txt | --media master-file] [--expected-key fingerprint] [--device-evidence evidence.json --device-policy policy.json]');
    const options = new Map();
    for (let i = 0; i < arguments_.length; i += 2) {
        const flag = arguments_[i], value = arguments_[i + 1];
        if (!value || !['--text', '--media', '--expected-key', '--device-evidence', '--device-policy'].includes(flag) || options.has(flag)) throw new Error('Unknown, duplicate or incomplete verifier option.');
        options.set(flag, value);
    }
    if (options.has('--text') && options.has('--media')) throw new Error('Supply text or a media master.');
    if (options.has('--device-evidence') !== options.has('--device-policy')) throw new Error('Device evidence requires an independently trusted app policy.');
    const source = await textFile(file, 32 * 1024 * 1024), parsed = boundedJSON(source);
    const disclosed=writingDisclosure(source);
    const proof = disclosed ? boundedJSON(disclosed.proof) : parsed?.kind === ENVELOPE_KIND ? boundedJSON(parsed.proof) : parsed;
    const content = options.has('--media') ? new Uint8Array(await boundedFile(options.get('--media'), 32 * 1024 * 1024))
        : options.has('--text') ? await textFile(options.get('--text'), 65536) : proof?.text;
    if (content === undefined) throw new Error('Supply the expected text or media master.');
    const policy = {}, attachments = {};
    if (options.has('--expected-key')) {
        const key = options.get('--expected-key');
        if (!fullMatch(/^[a-f0-9]{64}$/, key)) throw new Error('Expected key must be a lowercase SHA-256 fingerprint.');
        policy.expectedKey = key;
    }
    if (options.has('--device-evidence')) {
        attachments.device = await textFile(options.get('--device-evidence'), 256 * 1024);
        policy.device = boundedJSON(await textFile(options.get('--device-policy'), 16384), 16384);
    }
    const report = await verify(source, policy, content, { attachments });
    if (!report.verified) throw new Error('Proof, content or selected evidence did not verify.');
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} catch (error) {
    process.stderr.write('Verification failed: ' + String(error?.message ?? error) + '\n');
    process.exitCode = 1;
}
