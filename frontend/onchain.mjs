// On-chain verification of a page written here (backend/onchain): HumaPagesV4 on Base checks every zero-knowledge proof
// of the page with verifiers bb generated from the same circuits the browser proves, and everything Huma's reader checks
// besides (the writer key's signature of every event, the event digest, the nonce's binding to that key, the statement's
// bounds, passkey approvals), and records the page. The proofs
// are the browser's own, made again in the EVM format (keccak) after Finish (write/prove.mjs, proveForChain): the
// writing never leaves the browser, only proofs and the page's public statement do. This server's relayer wallet
// submits them, so the writer needs no wallet and pays no gas.
//
// Off unless HUMA_RELAYER_KEY (the relayer's private key, funded) and HUMA_ONCHAIN_CONTRACT (HumaPagesV3's address) are
// set. HUMA_CHAIN: base-sepolia (default) or base; HUMA_CHAIN_RPC overrides the chain's public RPC.
//
// GET  /api/onchain                     → { enabled, chainId, network, contract, explorer } (enabled false when off)
// POST /api/onchain/pages               ← { tier, parts: [{ proof, publicInputs }], final: { proof, publicInputs } } (base64),
//                                         pageProof (the page proof's JSON, which carries the signed events)
//                                       → { statement, verified: true, block, tx, url }, submitted or already there
// POST /api/onchain/lookup              ← { finalInputs } (base64, the page proof's statement) → the record, or verified: false
import { createPublicClient, createWalletClient, http, keccak256, parseAbi, parseAbiItem, BaseError, ContractFunctionRevertedError } from 'viem';
import { privateKeyToAccount, nonceManager } from 'viem/accounts';
import { base, baseSepolia } from 'viem/chains';
import { clientIP } from './client-ip.mjs';

const STRUCTS = ['struct Writer { bytes32 x; bytes32 y; bool passkey; bytes32 passkeyX; bytes32 passkeyY; }',
  'struct Event { uint8 kind; bytes32 root; bytes32 r; bytes32 s; }',
  'struct Assertion { bytes authenticatorData; bytes clientDataJSON; uint256 typeIndex; uint256 challengeIndex; uint256 originIndex; bytes32 r; bytes32 s; bytes32 bindR; bytes32 bindS; }',
  'struct Proofs { bytes[] partProofs; bytes32[3][] partInputs; bytes finalProof; bytes32[] finalInputs; }',
  'struct Evidence { Writer writer; Event[] events; Assertion[] assertions; }'];
export const ABI = parseAbi([...STRUCTS,
  'function submit(Proofs p, Evidence ev) returns (bytes32)',
  'function submitParts(bytes32 genesisRoot, uint256 tier, uint256 startIndex, bytes[] partProofs, bytes32[3][] partInputs) returns (bytes32)',
  'function submitEvents(bytes32 genesisRoot, uint256 startEvent, Evidence ev) returns (bytes32)',
  'function submitFinal(bytes32 genesisRoot, bytes finalProof, bytes32[] finalInputs) returns (bytes32)',
  'function pages(bytes32) view returns (uint64 blockNumber, uint32 parts, uint32 tier, uint32 events, bool passkey, address submitter)',
  'error AlreadyVerified()', 'error NoParts()', 'error TooMany(uint256 count)', 'error UnsupportedTier(uint256 tier)',
  'error InvalidStatement(uint256 field)', 'error BrokenLinkage(uint256 part)', 'error InvalidPartProof(uint256 part)', 'error InvalidFinalProof()',
  'error UnknownSession()', 'error InvalidEvent(uint256 index)', 'error InvalidSignature(uint256 index)', 'error InvalidPasskey(uint256 index)',
  'error WrongWriter()', 'error EventsDontMatch()', 'error NonceNotBound()',
]);
const PAGE_VERIFIED = parseAbiItem('event PageVerified(bytes32 indexed statement, address indexed submitter, uint256 tier, uint256 parts, uint256 events, bytes32 keyHash, bool passkey)');
export const TIERS = [1024, 4096, 10000];
export const PER_TX = 12;                      // HumaPagesV4.MAX_PARTS_PER_TX
export const EVENTS_PER_TX = 64;               // HumaPagesV4.MAX_EVENTS_PER_TX
const MAX_PARTS = 256, MAX_PROOF = 12288, PART_INPUTS = 96, FINAL_INPUTS = 1408, MAX_PAGE_PROOF = 3 * 1024 * 1024;
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

/** A page's EVM proofs and its page proof's signed events, checked for shape (not validity: the contract does that) and
 *  laid out as the contract takes them. */
export function pageCall(page) {
  if (!page || typeof page !== 'object' || !TIERS.includes(page.tier) || !Array.isArray(page.parts) || !page.final) throw fail(400, 'Invalid page.');
  if (page.parts.length < 1 || page.parts.length > MAX_PARTS) throw fail(400, 'Invalid page.');
  const parts = page.parts.map(p => ({ proof: hex(bytesOf(p?.proof, { max: MAX_PROOF })), inputs: fields(bytesOf(p?.publicInputs, { exact: PART_INPUTS })) }));
  const finalInputs = bytesOf(page.final.publicInputs, { exact: FINAL_INPUTS });
  if (Number(BigInt(fields(finalInputs)[14])) !== page.tier) throw fail(400, 'Invalid page.'); // text_capacity
  if (typeof page.pageProof !== 'string' || page.pageProof.length > MAX_PAGE_PROOF) throw fail(400, 'Invalid page.');
  let source; try { source = JSON.parse(page.pageProof); } catch { throw fail(400, 'Invalid page.'); }
  // The page proof is the one these proofs are for: the same statement (byte for byte) and the same parts.
  if (typeof source?.finalInputs !== 'string' || Buffer.from(source.finalInputs, 'base64').compare(finalInputs) !== 0
      || !Array.isArray(source.chunkInputs) || source.chunkInputs.length !== parts.length) throw fail(400, 'This page proof is for another page.');
  return { tier: page.tier, parts, finalProof: hex(bytesOf(page.final.proof, { max: MAX_PROOF })), finalInputs: fields(finalInputs), statement: statementOf(finalInputs),
    evidence: evidenceCall(source) };
}

/** A DER ECDSA signature (base64, as page proofs carry them) as (r, s), 32 bytes each. */
export function rs(der) {
  const b = Buffer.from(der, 'base64');
  if (b.length < 8 || b.length > 72 || b[0] !== 0x30 || b[1] !== b.length - 2 || b[2] !== 0x02) throw fail(400, 'Invalid signature.');
  const rLength = b[3], r = b.subarray(4, 4 + rLength);
  if (b[4 + rLength] !== 0x02) throw fail(400, 'Invalid signature.');
  const s = b.subarray(6 + rLength, 6 + rLength + b[5 + rLength]);
  const word = x => { const t = x[0] === 0 ? x.subarray(1) : x; if (!t.length || t.length > 32) throw fail(400, 'Invalid signature.'); return hex(Buffer.concat([Buffer.alloc(32 - t.length), t])); };
  return [word(r), word(s)];
}
const rootWord = value => {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,76})$/.test(value)) throw fail(400, 'Invalid page proof.');
  return '0x' + BigInt(value).toString(16).padStart(64, '0');
};
const ORIGIN_MEMBER = '"origin":"https://huma.social"';
/**
 * What HumaPagesV4 checks besides the proofs, from the page proof the browser made (the public JSON: publicKey, events,
 * checkpointRoots, presenceRoots, signatures, presenceSignatures and, on passkey pages, passkey): the writer, its signed
 * events in the session's order, and one passkey approval per check-in. { writer, events, assertions }, as the contract
 * takes them. Shape only: the contract does every check.
 */
export function evidenceCall(pageProof) {
  const p = typeof pageProof === 'string' ? JSON.parse(pageProof) : pageProof;
  if (!p || typeof p.events !== 'string' || !/^[12]{1,4096}$/.test(p.events) || !Array.isArray(p.checkpointRoots) || !Array.isArray(p.presenceRoots)
      || !Array.isArray(p.signatures) || !Array.isArray(p.presenceSignatures)) throw fail(400, 'Invalid page proof.');
  const key = Buffer.from(String(p.publicKey), 'base64');
  if (key.length !== 65 || key[0] !== 4) throw fail(400, 'Invalid page proof.');
  const roots = [p.checkpointRoots, p.presenceRoots], signatures = [p.signatures, p.presenceSignatures], next = [0, 0];
  const events = [...p.events].map(Number).map(kind => {
    const i = next[kind - 1]++, root = roots[kind - 1][i], signature = signatures[kind - 1][i];
    if (root === undefined || signature === undefined) throw fail(400, 'Invalid page proof.');
    const [r, s] = rs(signature);
    return { kind, root: rootWord(root), r, s };
  });
  if (next[0] !== roots[0].length || next[1] !== roots[1].length) throw fail(400, 'Invalid page proof.');
  const writer = { x: hex(key.subarray(1, 33)), y: hex(key.subarray(33, 65)), passkey: false, passkeyX: '0x' + '00'.repeat(32), passkeyY: '0x' + '00'.repeat(32) };
  const assertions = [];
  if (p.passkey) {
    const pk = Buffer.from(String(p.passkey.publicKey), 'base64');
    if (pk.length !== 65 || pk[0] !== 4 || !Array.isArray(p.passkey.assertions) || p.passkey.assertions.length !== roots[1].length) throw fail(400, 'Invalid page proof.');
    Object.assign(writer, { passkey: true, passkeyX: hex(pk.subarray(1, 33)), passkeyY: hex(pk.subarray(33, 65)) });
    for (const a of p.passkey.assertions) {
      const client = Buffer.from(String(a.clientDataJSON), 'base64'), text = client.toString('latin1');
      const index = member => { const at = text.indexOf(member); return BigInt(at < 0 ? client.length : at); };
      const [r, s] = rs(a.signature), [bindR, bindS] = rs(a.binding);
      assertions.push({ authenticatorData: hex(Buffer.from(String(a.authenticatorData), 'base64')), clientDataJSON: hex(client),
        typeIndex: index('"type":"webauthn.get"'), challengeIndex: index('"challenge":"'), originIndex: index(ORIGIN_MEMBER), r, s, bindR, bindS });
    }
  }
  return { writer, events, assertions };
}

/** Why the contract refused, in words, from its custom error. */
function refusal(error) {
  const revert = error instanceof BaseError ? error.walk(e => e instanceof ContractFunctionRevertedError) : null;
  const name = revert?.data?.errorName, arg = revert?.data?.args?.[0];
  if (name === 'AlreadyVerified') return { already: true };
  const words = { InvalidPartProof: `part ${arg} of the proof didn’t verify`, InvalidFinalProof: 'the final proof didn’t verify',
    BrokenLinkage: `the parts don’t join up (at part ${arg})`, InvalidStatement: 'the statement isn’t a page’s', UnsupportedTier: 'this length of page isn’t supported',
    TooMany: 'too much for one transaction', NoParts: 'the page has no parts', UnknownSession: 'the earlier batches weren’t found',
    InvalidEvent: `event ${arg} isn’t a checkpoint or check-in`, InvalidSignature: `the writer key didn’t sign event ${arg}`,
    InvalidPasskey: `the passkey approval of event ${arg} didn’t check`, WrongWriter: 'a batch came from another writer key',
    EventsDontMatch: 'the signed events aren’t the ones the proof counted', NonceNotBound: 'the session isn’t bound to this writer key' };
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
    const [block, parts, tier, events, passkey] = await reader.readContract({ address: contract, abi: ABI, functionName: 'pages', args: [statement] });
    if (!block) return { statement, verified: false };
    const logs = await reader.getLogs({ address: contract, event: PAGE_VERIFIED, args: { statement }, fromBlock: block, toBlock: block }).catch(() => []);
    const tx = logs[0]?.transactionHash ?? null;
    return { statement, verified: true, block: Number(block), parts: Number(parts), tier: Number(tier), events: Number(events), passkey, tx,
      url: tx ? `${explorer}/tx/${tx}` : `${explorer}/address/${contract}` };
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
    const proofs = call.parts.map(p => p.proof), inputs = call.parts.map(p => p.inputs), { writer, events, assertions } = call.evidence;
    if (proofs.length <= PER_TX && events.length <= EVENTS_PER_TX)
      await send('submit', [{ partProofs: proofs, partInputs: inputs, finalProof: call.finalProof, finalInputs: call.finalInputs }, call.evidence]);
    else {
      const genesis = inputs[0][0];
      for (let at = 0; at < proofs.length; at += PER_TX)
        await send('submitParts', [genesis, BigInt(call.tier), BigInt(at), proofs.slice(at, at + PER_TX), inputs.slice(at, at + PER_TX)]);
      // Events in runs, each with the approvals of its own check-ins.
      let used = 0;
      for (let at = 0; at < events.length; at += EVENTS_PER_TX) {
        const run = events.slice(at, at + EVENTS_PER_TX), checkins = writer.passkey ? run.filter(e => e.kind === 2).length : 0;
        await send('submitEvents', [genesis, BigInt(at), { writer, events: run, assertions: assertions.slice(used, used + checkins) }]);
        used += checkins;
      }
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
