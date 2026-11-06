import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { configuredOnchain, onchainRoutes, pageCall, statementOf, PER_TX } from '../onchain.mjs';

// Real EVM proofs of the existing circuits (backend/onchain/test/fixtures, checked by the Solidity verifiers there).
const FIXTURES = fileURLToPath(new URL('../../backend/onchain/test/fixtures/', import.meta.url));
const b64 = file => readFileSync(file).toString('base64');
function page(name, tier) {
  const dir = FIXTURES + name, parts = readdirSync(dir).filter(d => d.startsWith('part')).sort((a, b) => a.slice(4) - b.slice(4));
  return { tier, parts: parts.map(p => ({ proof: b64(path.join(dir, p, 'proof')), publicInputs: b64(path.join(dir, p, 'public_inputs')) })),
    final: { proof: b64(path.join(dir, 'final/proof')), publicInputs: b64(path.join(dir, 'final/public_inputs')) } };
}
const KEY = '0x' + '11'.repeat(32), CONTRACT = '0x' + '22'.repeat(20);
/** A chain that records every call and verifies whatever it's told to. */
function fakeChain({ refuse = null } = {}) {
  const recorded = new Map(), calls = [];
  const reader = {
    async readContract({ args: [statement] }) { const r = recorded.get(statement); return r ? [BigInt(r.block), r.parts, r.tier, r.submitter] : [0n, 0, 0, '0x0']; },
    async getLogs() { return [{ transactionHash: '0x' + 'ab'.repeat(32) }]; },
    async simulateContract({ functionName, args }) {
      if (refuse) throw refuse;
      calls.push(functionName);
      return { request: { functionName, args } };
    },
    async waitForTransactionReceipt() { return { status: 'success' }; },
  };
  const writer = {
    async writeContract({ functionName, args }) {
      if (functionName === 'submit') recorded.set(statementOf(Buffer.from(args[3].map(f => f.slice(2)).join(''), 'hex')), { block: 7, parts: args[0].length, tier: 1024, submitter: '0x0' });
      if (functionName === 'submitFinal') recorded.set(statementOf(Buffer.from(args[2].map(f => f.slice(2)).join(''), 'hex')), { block: 9, parts: 0, tier: 4096, submitter: '0x0' });
      return '0x' + 'cd'.repeat(32);
    },
  };
  return { clients: () => ({ reader, writer, account: { address: '0x0' } }), calls };
}
const env = { HUMA_RELAYER_KEY: KEY, HUMA_ONCHAIN_CONTRACT: CONTRACT };

test('on-chain verification is off unless a relayer key and a contract are set', async () => {
  for (const partial of [{}, { HUMA_RELAYER_KEY: KEY }, { HUMA_ONCHAIN_CONTRACT: CONTRACT }, { ...env, HUMA_CHAIN: 'mainnet' }])
    assert.equal(configuredOnchain(partial).enabled, false);
  const routes = onchainRoutes({ enabled: false });
  const replies = [];
  const json = (res, status, body) => replies.push([status, body]);
  assert.equal(await routes({ method: 'GET', headers: {} }, null, '/api/onchain', { json }), true);
  assert.equal(await routes({ method: 'POST', headers: {} }, null, '/api/onchain/pages', { json }), true);
  assert.equal(await routes({ method: 'GET', headers: {} }, null, '/api/other', { json }), false);
  assert.deepEqual(replies, [[200, { enabled: false }], [404, { error: 'On-chain verification is off.' }]]);
});

test('a page is checked for shape before anything reaches the chain', () => {
  const good = page('long-case-400', 1024), call = pageCall(good);
  assert.equal(call.parts.length, 4); assert.equal(call.finalInputs.length, 44); assert.match(call.statement, /^0x[0-9a-f]{64}$/);
  const broken = [
    { ...good, tier: 2048 }, { ...good, tier: 4096 }, { ...good, parts: [] },
    { ...good, parts: [{ ...good.parts[0], proof: 'not base64!' }] },
    { ...good, parts: [{ ...good.parts[0], publicInputs: good.final.publicInputs }] },
    { ...good, final: { ...good.final, publicInputs: good.parts[0].publicInputs } },
    { ...good, final: { ...good.final, proof: Buffer.alloc(20000).toString('base64') } },
  ];
  for (const p of broken) assert.throws(() => pageCall(p), { status: 400 });
});

test('a short page goes in one transaction, a long one in batches, and a recorded one is not sent again', async () => {
  const chain = fakeChain(), onchain = configuredOnchain(env, { clients: chain.clients });
  const first = await onchain.submit(page('long-case-400', 1024));
  assert.equal(first.verified, true); assert.equal(first.block, 7); assert.match(first.url, /\/tx\/0x(ab){32}$/);
  assert.deepEqual(chain.calls, ['submit']);
  assert.equal((await onchain.submit(page('long-case-400', 1024))).already, true);
  assert.deepEqual(chain.calls, ['submit']);
  const long = page('long-case-1500', 4096);
  assert.ok(long.parts.length > PER_TX);
  assert.equal((await onchain.submit(long)).verified, true);
  assert.deepEqual(chain.calls.slice(1), [...Array(Math.ceil(long.parts.length / PER_TX)).fill('submitParts'), 'submitFinal']);
});

test('a refusal comes back in words, and a client gets a few submissions an hour', async () => {
  const { ContractFunctionRevertedError, encodeErrorResult } = await import('viem');
  const { ABI } = await import('../onchain.mjs');
  const refuse = new ContractFunctionRevertedError({ abi: ABI, functionName: 'submit', data: encodeErrorResult({ abi: ABI, errorName: 'InvalidPartProof', args: [2n] }) });
  const onchain = configuredOnchain(env, { clients: fakeChain({ refuse }).clients });
  const routes = onchainRoutes(onchain);
  const body = JSON.stringify(page('long-case-400', 1024));
  const request = () => Object.assign((async function* () { yield Buffer.from(body); })(),
    { method: 'POST', headers: { 'content-type': 'application/json' }, socket: { remoteAddress: '203.0.113.9' } });
  const replies = [];
  const json = (res, status, reply) => replies.push([status, reply.error ?? reply]);
  for (let i = 0; i < 11; i++) await routes(request(), null, '/api/onchain/pages', { json });
  assert.equal(replies.length, 11);
  assert.deepEqual(replies[0], [422, 'Not verified on-chain: part 2 of the proof didn’t verify.']);
  assert.ok(replies.slice(0, 10).every(([status]) => status === 422));
  assert.equal(replies[10][0], 429);
});
