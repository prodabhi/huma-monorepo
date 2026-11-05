import { readFile } from 'node:fs/promises';

try {
    const chunks = []; let size = 0;
    for await (const chunk of process.stdin) {
        size += chunk.length; if (size > 2 * 1024 * 1024) throw new Error('Input exceeds limit.');
        chunks.push(chunk);
    }
    const source = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    const parsed = JSON.parse(source);
    if (parsed?.kind === 'huma-evidence-envelope-v1') {
        // This process already has the registry's memory/deadline bounds.
        const { engine } = await import('./verify-core/node-engine.mjs');
        if (!parsed.attachments || Object.keys(parsed.attachments).length) throw new Error('Attachment publication is not supported.');
        const text = JSON.parse(parsed.proof).text;
        if (typeof text !== 'string') throw new Error('Public text required.');
        const normalized = await engine.envelope(parsed.proof, {}, text);
        // Verify the claimed outer statement against the typed public projection.
        // Optional private disclosures are not publication claims.
        const projected = { ...parsed, proof: JSON.parse(normalized.envelope).proof };
        if (!(await engine.verify(JSON.stringify(projected), {}, text)).verified) throw new Error('Envelope does not verify.');
        process.stdout.write(normalized.envelope, () => process.exit(0));
    } else if (['huma-compact-assurance-public-proof-v4','huma-compact-assurance-public-proof-v5'].includes(parsed?.kind)) {
        if (typeof parsed.text !== 'string') throw new Error('Public text required.');
        const { engine } = await import('./verify-core/node-engine.mjs');
        const normalized = await engine.envelope(source, {}, parsed.text);
        process.stdout.write(normalized.envelope, () => process.exit(0));
    } else if (parsed?.kind === 'huma-compact-public-proof-v1') {
        if (typeof parsed.text !== 'string') throw new Error('A shared proof needs its public text.');
        const { verifyCompactPublic } = await import('../extra/experiments/noir-compact/browser/node-verifier.mjs');
        await verifyCompactPublic(source);
        const record = JSON.stringify({ kind: parsed.kind, profile: parsed.profile, proof: parsed.proof,
            publicInputs: parsed.publicInputs, publicKey: parsed.publicKey, signatures: parsed.signatures, text: parsed.text });
        process.stdout.write(record, () => process.exit(0));
    } else {
    if (typeof parsed.text !== 'string' || Buffer.from(parsed.text).toString() !== parsed.text || !parsed.bundle) throw new Error('Invalid public record.');
    if (parsed.bundle.system !== 'risc0-3.0.6') throw new Error('Unsupported replay proof.');
    const { initSync, public_replay } = await import('./dist/replay/huma_replay_browser.js');
    initSync({ module: await readFile(new URL('./dist/replay/huma_replay_browser_bg.wasm', import.meta.url)) });
    // Pass original JSON to Rust; do not round signed u64 values through JS.
    const record = public_replay(source);
    process.stdout.write(record, () => process.exit(0));
    }
} catch {
    process.exit(1);
}
