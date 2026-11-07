import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { keccak256 } from 'viem';
import { createRelayer, statementKey } from '../relayer.mjs';
import { keccak, pageKey } from '../../../backend/integrations/noir/long/chain.mjs';

const chainFixture = async () => JSON.parse(await readFile(new URL('../noir-compact/browser/test/fixtures/Long400V2-chain.json', import.meta.url), 'utf8'));
const fields = b64 => { const raw = Buffer.from(b64, 'base64'), out = []; for (let i = 0; i < raw.length; i += 32) out.push('0x' + raw.subarray(i, i + 32).toString('hex')); return out; };
const contract = '0x00000000000000000000000000000000000000aa', owner = '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A';

function fakeChain({ recorded = false, simulate = async () => ({ request: { simulated: true } }) } = {}) {
  const calls = { writes: 0 }; let block = recorded ? 5 : 0;
  const client = {
    readContract: async ({ functionName }) => { assert.equal(functionName, 'pages'); return [block ? owner : '0x' + '0'.repeat(40), BigInt(block)]; },
    simulateContract: simulate,
    waitForTransactionReceipt: async () => { block = 9; return { status: 'success' }; },
  };
  const wallet = { account: { address: '0x' + 'b'.repeat(40) }, writeContract: async request => { assert.equal(request.simulated, true); calls.writes++; return '0x' + 'c'.repeat(64); } };
  return { client, wallet, calls };
}

test('the record key is keccak of the 45 statement fields, here and in the browser reader', async () => {
  const { publicInputs } = await chainFixture(), inputs = fields(publicInputs);
  assert.equal(inputs.length, 46);
  const key = statementKey(inputs);
  assert.equal(key, keccak256(Buffer.concat(inputs.slice(0, 45).map(f => Buffer.from(f.slice(2), 'hex')))));
  assert.equal(await pageKey({ finalInputs: Buffer.from(Buffer.from(publicInputs, 'base64').subarray(0, 46 * 32)).toString('base64') }), key);
  for (const sample of ['', 'abc', 'a'.repeat(135), 'a'.repeat(136), 'a'.repeat(137), 'x'.repeat(1000)])
    assert.equal('0x' + Buffer.from(keccak(new TextEncoder().encode(sample))).toString('hex'), keccak256(Buffer.from(sample)), sample.length);
});

test('relays a page once, after simulating it, within a daily allowance', async () => {
  const { proof, publicInputs } = await chainFixture(), inputs = fields(publicInputs);
  const { client, wallet, calls } = fakeChain();
  let day = 0;
  const relayer = createRelayer({ name: 'base-sepolia', contract, client, wallet, dailyLimit: 1, now: () => day * 86400000 });
  const result = await relayer.submit('0x' + Buffer.from(proof, 'base64').toString('hex'), inputs);
  assert.deepEqual([result.blockNumber, result.owner, calls.writes], [9, owner, 1]);
  assert.match(result.explorer, /^https:\/\/sepolia\.basescan\.org\/tx\/0x/);
  // Already recorded: no transaction. A fresh page over the allowance waits for the next UTC day.
  const again = await relayer.submit('0x00', inputs); assert.equal(again.transactionHash, null); assert.equal(calls.writes, 1);
  const other = createRelayer({ name: 'base-sepolia', contract, ...fakeChain(), dailyLimit: 0, now: () => 0 });
  await assert.rejects(other.submit('0x00', inputs), e => e.status === 429);
});

test('a proof HumaPages would reject is never sent', async () => {
  const { client, wallet, calls } = fakeChain({ simulate: async () => { throw Object.assign(new Error('revert'), { shortMessage: 'InvalidProof()' }); } });
  const relayer = createRelayer({ name: 'base-sepolia', contract, client, wallet });
  await assert.rejects(relayer.submit('0x00', fields((await chainFixture()).publicInputs)), e => e.status === 422 && /InvalidProof/.test(e.message));
  assert.equal(calls.writes, 0);
});

test('a page that misses a required writing rule is explained, not sent to HumaPages', async () => {
  const { unmetWritingRules, notEligibleReason } = await import('../publication-contract.mjs');
  const raw = Buffer.from((await chainFixture()).publicInputs, 'base64').subarray(0, 46 * 32);
  assert.deepEqual(unmetWritingRules(raw.toString('base64')), []);
  // Every rule is required: short notes (under 20 s, under 30 keys, no pause) and an uneven rhythm can't go on Base.
  const short = Buffer.from(raw); for (const i of [35, 36, 40, 42]) short[i * 32 + 31] = 0;
  assert.deepEqual(unmetWritingRules(short.toString('base64')),
    ['it was typed for less than 20 seconds', 'it has fewer than 30 key presses', 'there was no natural pause']);
  const uneven = Buffer.from(raw); uneven[39 * 32 + 31] = 0;
  assert.deepEqual(unmetWritingRules(uneven.toString('base64')), ['the typing rhythm looked unusual']);
  assert.match(notEligibleReason(['it was typed for less than 20 seconds']), /writing rules: it was typed for less than 20 seconds\.$/);
});
