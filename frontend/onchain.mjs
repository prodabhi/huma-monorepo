// On-chain verification of a page written here (backend/onchain): HumaPagesV3 on Base checks every zero-knowledge proof
// of the page with verifiers bb generated from the same circuits the browser proves, and records the page. The proofs
// are the browser's own, made again in the EVM format (keccak) after Finish (write/prove.mjs, proveForChain): the
// writing never leaves the browser, only proofs and the page's public statement do. This server's relayer wallet
// submits them, so the writer needs no wallet and pays no gas.
//
// Off unless HUMA_RELAYER_KEY (the relayer's private key, funded) and HUMA_ONCHAIN_CONTRACT (HumaPagesV3's address) are
// set. HUMA_CHAIN: base-sepolia (default) or base; HUMA_CHAIN_RPC overrides the chain's public RPC.
//
// GET  /api/onchain                     → { enabled, chainId, network, contract, explorer } (enabled false when off)
// POST /api/onchain/pages               ← { tier, parts: [{ proof, publicInputs }], final: { proof, publicInputs } } (base64)
//                                       → { statement, verified: true, block, tx, url }, submitted or already there
// POST /api/onchain/lookup              ← { finalInputs } (base64, the page proof's statement) → the record, or verified: false
import { createPublicClient, createWalletClient, http, keccak256, parseAbi, parseAbiItem, BaseError, ContractFunctionRevertedError } from 'viem';
import { privateKeyToAccount, nonceManager } from 'viem/accounts';
import { base, baseSepolia } from 'viem/chains';
import { clientIP } from './client-ip.mjs';

export const ABI = parseAbi([
  'function submit(bytes[] partProofs, bytes32[3][] partInputs, bytes finalProof, bytes32[] finalInputs) returns (bytes32)',
  'function submitParts(bytes32 genesisRoot, uint256 tier, uint256 startIndex, bytes[] partProofs, bytes32[3][] partInputs) returns (bytes32)',
  'function submitFinal(bytes32 genesisRoot, bytes finalProof, bytes32[] finalInputs) returns (bytes32)',
  'function pages(bytes32) view returns (uint64 blockNumber, uint32 parts, uint32 tier, address submitter)',
  'error AlreadyVerified()', 'error NoParts()', 'error TooManyParts(uint256 parts)', 'error UnsupportedTier(uint256 tier)',
  'error InvalidStatement()', 'error BrokenLinkage(uint256 part)', 'error InvalidPartProof(uint256 part)', 'error InvalidFinalProof()',
  'error UnknownSession()',
]);
const PAGE_VERIFIED = parseAbiItem('event PageVerified(bytes32 indexed statement, address indexed submitter, uint256 tier, uint256 parts)');
export const TIERS = [1024, 4096, 10000];
export const PER_TX = 12;                      // HumaPagesV3.MAX_PARTS_PER_TX
const MAX_PARTS = 256, MAX_PROOF = 12288, PART_INPUTS = 96, FINAL_INPUTS = 1408;
const BODY_LIMIT = 4 * 1024 * 1024, PER_CLIENT_HOUR = 10;
const NETWORKS = { 'base-sepolia': baseSepolia, base };

const fail = (status, message) => Object.assign(new Error(message), { status });
/** Base64 → bytes, exactly: a proof is a whole number of 32-byte fields, at most MAX_PROOF bytes. */
function bytesOf(value, { exact, max }) {
  if (typeof value !== 'string' || value.length > Math.ceil((max ?? exact) / 3) * 4 + 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw fail(400, 'Invalid proof.');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length % 32 || (exact !== undefined ? bytes.length !== exact : bytes.length < 32 || bytes.length > max)) throw fail(400, 'Invalid proof.');
  return bytes;
}
const hex = bytes => '0x' + Buffer.from(bytes).toString('hex');
const fields = bytes => Array.from({ length: bytes.length / 32 }, (_, i) => hex(bytes.subarray(i * 32, i * 32 + 32)));
/** The page's key on-chain: keccak256 of its 44 statement fields, as HumaPagesV3 computes it. */
export const statementOf = finalInputs => keccak256(finalInputs);

/** A page's EVM proofs, checked for shape (not validity: the contract does that) and laid out as the contract takes them. */
export function pageCall(page) {
  if (!page || typeof page !== 'object' || !TIERS.includes(page.tier) || !Array.isArray(page.parts) || !page.final) throw fail(400, 'Invalid page.');
  if (page.parts.length < 1 || page.parts.length > MAX_PARTS) throw fail(400, 'Invalid page.');
  const parts = page.parts.map(p => ({ proof: hex(bytesOf(p?.proof, { max: MAX_PROOF })), inputs: fields(bytesOf(p?.publicInputs, { exact: PART_INPUTS })) }));
  const finalInputs = bytesOf(page.final.publicInputs, { exact: FINAL_INPUTS });
  if (Number(BigInt(fields(finalInputs)[14])) !== page.tier) throw fail(400, 'Invalid page.'); // text_capacity
  return { tier: page.tier, parts, finalProof: hex(bytesOf(page.final.proof, { max: MAX_PROOF })), finalInputs: fields(finalInputs), statement: statementOf(finalInputs) };
}

/** Why the contract refused, in words, from its custom error. */
function refusal(error) {
  const revert = error instanceof BaseError ? error.walk(e => e instanceof ContractFunctionRevertedError) : null;
  const name = revert?.data?.errorName, arg = revert?.data?.args?.[0];
  if (name === 'AlreadyVerified') return { already: true };
  const words = { InvalidPartProof: `part ${arg} of the proof didn’t verify`, InvalidFinalProof: 'the final proof didn’t verify',
    BrokenLinkage: `the parts don’t join up (at part ${arg})`, InvalidStatement: 'the statement isn’t a page’s', UnsupportedTier: 'this length of page isn’t supported',
    TooManyParts: 'too many parts for one transaction', NoParts: 'the page has no parts', UnknownSession: 'the earlier parts weren’t found' };
  return name ? { status: 422, message: 'Not verified on-chain: ' + (words[name] ?? name) + '.' } : null;
}

export function configuredOnchain(env = process.env, { now = Date.now, clients: makeClients } = {}) {
  const key = env.HUMA_RELAYER_KEY ?? '', contract = env.HUMA_ONCHAIN_CONTRACT ?? '';
  const network = NETWORKS[env.HUMA_CHAIN || 'base-sepolia'];
  const enabled = /^0x[0-9a-fA-F]{64}$/.test(key) && /^0x[0-9a-fA-F]{40}$/.test(contract) && Boolean(network);
  if (!enabled) {
    if (contract || env.HUMA_CHAIN) console.warn('On-chain verification is off: set HUMA_RELAYER_KEY, HUMA_ONCHAIN_CONTRACT and HUMA_CHAIN (base-sepolia or base).');
    return { enabled: false };
  }
  const explorer = network.blockExplorers.default.url;
  let clients = null;
  const connect = () => (clients ??= makeClients ? makeClients() : (() => {
    const transport = http(env.HUMA_CHAIN_RPC || undefined, { timeout: 30000 });
    const account = privateKeyToAccount(key, { nonceManager });
    return { reader: createPublicClient({ chain: network, transport }), writer: createWalletClient({ chain: network, transport, account }), account };
  })());
  const info = { enabled: true, chainId: network.id, network: network.name, contract, explorer };

  /** What the chain says about a statement: { statement, verified, block, parts, tier, tx, url } (tx from its event). */
  async function record(statement) {
    const { reader } = connect();
    const [block, parts, tier] = await reader.readContract({ address: contract, abi: ABI, functionName: 'pages', args: [statement] });
    if (!block) return { statement, verified: false };
    const logs = await reader.getLogs({ address: contract, event: PAGE_VERIFIED, args: { statement }, fromBlock: block, toBlock: block }).catch(() => []);
    const tx = logs[0]?.transactionHash ?? null;
    return { statement, verified: true, block: Number(block), parts: Number(parts), tier: Number(tier), tx, url: tx ? `${explorer}/tx/${tx}` : `${explorer}/address/${contract}` };
  }
  /** Simulates, then sends, one contract call; a refusal comes back in words, AlreadyVerified as { already }. */
  async function send(functionName, args) {
    const { reader, writer, account } = connect();
    try {
      const { request } = await reader.simulateContract({ address: contract, abi: ABI, functionName, args, account });
      const hash = await writer.writeContract(request);
      const receipt = await reader.waitForTransactionReceipt({ hash, timeout: 180000 });
      if (receipt.status !== 'success') throw fail(502, 'The transaction failed on-chain.');
      return { hash, receipt };
    } catch (error) {
      const why = refusal(error);
      if (why?.already) return { already: true };
      if (why) throw fail(why.status, why.message);
      throw error.status ? error : fail(502, 'The chain couldn’t be reached. Try again.');
    }
  }
  // One page at a time through the one relayer wallet (nonces stay in order); the same page twice waits for the first.
  let queue = Promise.resolve();
  const inFlight = new Map();
  async function submitNow(call) {
    const known = await record(call.statement);
    if (known.verified) return { ...known, already: true };
    const proofs = call.parts.map(p => p.proof), inputs = call.parts.map(p => p.inputs);
    if (proofs.length <= PER_TX) await send('submit', [proofs, inputs, call.finalProof, call.finalInputs]);
    else {
      const genesis = inputs[0][0];
      for (let at = 0; at < proofs.length; at += PER_TX)
        await send('submitParts', [genesis, BigInt(call.tier), BigInt(at), proofs.slice(at, at + PER_TX), inputs.slice(at, at + PER_TX)]);
      await send('submitFinal', [genesis, call.finalProof, call.finalInputs]);
    }
    const done = await record(call.statement);
    if (!done.verified) throw fail(502, 'The page wasn’t recorded. Try again.');
    return done;
  }
  function submit(page) {
    const call = pageCall(page);
    if (!inFlight.has(call.statement)) {
      const run = queue.then(() => submitNow(call));
      queue = run.catch(() => {});
      inFlight.set(call.statement, run);
      run.finally(() => inFlight.delete(call.statement)).catch(() => {});
    }
    return inFlight.get(call.statement);
  }
  return { ...info, info, record, submit, now };
}

async function readJSON(req, limit) {
  if (!(req.headers['content-type'] ?? '').startsWith('application/json')) throw fail(415, 'JSON required.');
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > limit) throw fail(413, 'Request too large.'); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw fail(400, 'Invalid request.'); }
}

/** The routes above. `onchain` from configuredOnchain(); everything answers 404 when it's off, except the config. */
export function onchainRoutes(onchain, { now = Date.now } = {}) {
  const clients = new Map(); let swept = null; // client → { hour, count }
  return async (req, res, pathname, { json }) => {
    if (!pathname.startsWith('/api/onchain')) return false;
    try {
      if (pathname === '/api/onchain' && req.method === 'GET') { json(res, 200, onchain.enabled ? onchain.info : { enabled: false }); return true; }
      if (pathname !== '/api/onchain/pages' && pathname !== '/api/onchain/lookup') { json(res, 404, { error: 'Not found.' }); return true; }
      if (req.method !== 'POST') { json(res, 405, { error: 'Method not allowed.' }); return true; }
      if (!onchain.enabled) { json(res, 404, { error: 'On-chain verification is off.' }); return true; }
      if (pathname === '/api/onchain/lookup') {
        const { finalInputs } = await readJSON(req, 4096) ?? {};
        json(res, 200, await onchain.record(statementOf(bytesOf(finalInputs, { exact: FINAL_INPUTS }))));
        return true;
      }
      // Each submission costs the relayer gas, so a client gets a few an hour.
      const ip = clientIP(req), hour = Math.floor(now() / 3600000);
      if (swept !== hour) { swept = hour; for (const [k, v] of clients) if (v.hour !== hour) clients.delete(k); }
      const client = clients.get(ip) ?? { hour, count: 0 };
      if (client.count >= PER_CLIENT_HOUR || (!clients.has(ip) && clients.size >= 100000)) { json(res, 429, { error: 'Too many on-chain checks from here. Try again later.' }); return true; }
      const page = await readJSON(req, BODY_LIMIT);
      client.count++; clients.set(ip, client);
      json(res, 200, await onchain.submit(page));
    } catch (error) {
      json(res, error.status ?? 502, { error: error.status ? error.message : 'On-chain verification failed. Try again.' });
    }
    return true;
  };
}
