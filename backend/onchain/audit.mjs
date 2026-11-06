// Read-only audit of a deployment (deployments/<chainId>.json): each contract's code equals what this folder compiles
// (run `forge build` first), HumaPagesV3 points at its six verifiers, every verifier accepts a real proof of its size
// (test/fixtures) and rejects it with a bit flipped, every recorded page, and the deploy receipts. Nothing is sent.
// Usage: node audit.mjs [chainId]   (default 84532, Base Sepolia; HUMA_CHAIN_RPC overrides the public RPC)
import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
const O = new URL('./', import.meta.url).pathname, chainId = process.argv[2] ?? '84532';
const require = createRequire(new URL('../../frontend/package.json', import.meta.url).pathname);
const { createPublicClient, http, keccak256, parseAbi, formatEther } = require('viem');
const { base, baseSepolia } = require('viem/chains');
const c = createPublicClient({ chain: chainId === '8453' ? base : baseSepolia, transport: http(process.env.HUMA_CHAIN_RPC || undefined, { timeout: 30000 }) });
const dep = JSON.parse(readFileSync(O + 'deployments/' + chainId + '.json', 'utf8'));
const results = []; const ok = (name, pass, detail = '') => results.push([pass ? 'PASS' : 'FAIL', name, detail]);
const art = name => JSON.parse(readFileSync(path.join(O, 'out', name + '.sol', name + '.json'), 'utf8'));
// 1. Code on chain equals the compiled runtime code (HumaPagesV3: immutables masked).
const all = { ...dep.verifiers, HumaPagesV3: dep.HumaPagesV3 };
for (const [name, address] of Object.entries(all)) {
  const code = await c.getCode({ address }); const a = art(name), compiled = a.deployedBytecode.object;
  let same = code === compiled;
  if (!same && a.deployedBytecode.immutableReferences) {
    const buf = Buffer.from(code.slice(2), 'hex'), ref = Buffer.from(compiled.slice(2), 'hex');
    for (const refs of Object.values(a.deployedBytecode.immutableReferences)) for (const { start, length } of refs) buf.fill(0, start, start + length), ref.fill(0, start, start + length);
    same = buf.equals(ref);
  }
  ok(`code ${name}`, same, `${(code.length - 2) / 2} bytes at ${address}`);
}
// 2. Wiring and constants of HumaPagesV3.
const P = parseAbi(['function chunk1024() view returns (address)', 'function final1024() view returns (address)', 'function chunk4096() view returns (address)',
  'function final4096() view returns (address)', 'function chunk10000() view returns (address)', 'function final10000() view returns (address)',
  'function FINAL_INPUTS() view returns (uint256)', 'function MAX_PARTS_PER_TX() view returns (uint256)', 'function verified(bytes32) view returns (bool)',
  'function pages(bytes32) view returns (uint64,uint32,uint32,address)', 'event PageVerified(bytes32 indexed statement, address indexed submitter, uint256 tier, uint256 parts)']);
const read = (functionName, args = []) => c.readContract({ address: dep.HumaPagesV3, abi: P, functionName, args });
for (const t of ['1024', '4096', '10000']) for (const k of ['chunk', 'final']) {
  const got = (await read(k + t)).toLowerCase(), want = dep.verifiers[`Huma${k[0].toUpperCase() + k.slice(1)}${t}Verifier`].toLowerCase();
  ok(`HumaPagesV3.${k}${t}() → right verifier`, got === want, got);
}
ok('FINAL_INPUTS = 44, MAX_PARTS_PER_TX = 12', (await read('FINAL_INPUTS')) === 44n && (await read('MAX_PARTS_PER_TX')) === 12n);
// 3. Every verifier, on chain, with a real proof of its size; and a flipped bit.
const V = parseAbi(['function verify(bytes proof, bytes32[] publicInputs) view returns (bool)']);
const fields = b => Array.from({ length: b.length / 32 }, (_, i) => '0x' + b.subarray(i * 32, i * 32 + 32).toString('hex'));
const cases = { 1024: 'long-case-400', 4096: 'long-case-1500', 10000: 'long-case-4200' };
for (const [tier, name] of Object.entries(cases)) for (const [kind, dir] of [['Chunk', 'part0'], ['Final', 'final']]) {
  const f = O + 'test/fixtures/' + name + '/' + dir + '/', proof = readFileSync(f + 'proof'), inputs = fields(readFileSync(f + 'public_inputs'));
  const address = dep.verifiers[`Huma${kind}${tier}Verifier`];
  const good = await c.readContract({ address, abi: V, functionName: 'verify', args: ['0x' + proof.toString('hex'), inputs] }).catch(e => 'revert');
  const bad = Buffer.from(proof); bad[bad.length >> 1] ^= 1;
  const tampered = await c.readContract({ address, abi: V, functionName: 'verify', args: ['0x' + bad.toString('hex'), inputs] }).catch(() => 'revert');
  ok(`Huma${kind}${tier}Verifier: real proof accepted, tampered rejected`, good === true && tampered !== true, `real=${good} tampered=${tampered}`);
}
// 4. Pages recorded on chain (every PageVerified since deployment) and each one's record.
const deployBlock = (await c.getTransactionReceipt({ hash: dep.transactions.HumaPagesV3 })).blockNumber;
const latest = await c.getBlockNumber(), logs = [];
for (let from = deployBlock; from <= latest; from += 200n) logs.push(...await c.getLogs({ address: dep.HumaPagesV3, event: P.find(x => x.name === 'PageVerified'), fromBlock: from, toBlock: from + 199n > latest ? latest : from + 199n }));
ok('scanned every block since deployment for PageVerified', true, `${latest - deployBlock + 1n} blocks, ${logs.length} pages`);
for (const l of logs) {
  const [block, parts, tier, by] = await read('pages', [l.args.statement]);
  ok(`page ${l.args.statement.slice(0, 10)}… recorded`, (await read('verified', [l.args.statement])) && block === l.blockNumber, `tier ${tier}, ${parts} parts, block ${block}, tx ${l.transactionHash.slice(0, 12)}…, by ${by.slice(0, 8)}…`);
}
ok('verified(random statement) is false', (await read('verified', [keccak256('0x1234')])) === false);
// 5. Deploy transactions succeeded and the relayer's balance.
for (const [name, tx] of Object.entries(dep.transactions)) {
  const r = await c.getTransactionReceipt({ hash: tx }); ok(`deploy ${name} (${tx.slice(0, 10)}…) succeeded`, r.status === 'success', `block ${r.blockNumber}`);
}
ok('deployer balance', true, formatEther(await c.getBalance({ address: dep.deployer })) + ' ETH');
for (const [s, n, d] of results) console.log(s, n.padEnd(62), d);
console.log(`\n${results.filter(r => r[0] === 'PASS').length} pass, ${results.filter(r => r[0] === 'FAIL').length} fail`);
