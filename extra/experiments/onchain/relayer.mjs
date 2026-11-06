// HumaPages on Base: sends page proofs made on writers' Macs from a relayer wallet the host funds,
// and reads page records. Each proof names its owner wallet inside the proof, so the relayer can
// only send it as is; it can't change whose page is recorded. Every call is simulated first.
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../../frontend/package.json', import.meta.url));
const { createPublicClient, createWalletClient, http, parseAbi, getAddress, keccak256, concat } = require('viem');
const { privateKeyToAccount } = require('viem/accounts');
const { base, baseSepolia } = require('viem/chains');

export const NETWORKS = {
  'base-sepolia': { chain: baseSepolia, rpc: 'https://sepolia.base.org', explorer: 'https://sepolia.basescan.org' },
  base: { chain: base, rpc: 'https://mainnet.base.org', explorer: 'https://basescan.org' },
};
export const PAGES_ABI = parseAbi([
  'function submit(bytes proof, bytes32[] publicInputs) returns (bytes32)',
  'function pages(bytes32 statement) view returns (address owner, uint64 blockNumber)',
  'error AlreadyVerified()', 'error InvalidProof()', 'error InvalidStatement()',
]);
export const STATEMENT_FIELDS = 45;
const fail = (status, message) => Object.assign(new Error(message), { status });

/** The page's record key: keccak256 of its 45 statement fields (bytes32 hex strings). */
export const statementKey = publicInputs => keccak256(concat(publicInputs.slice(0, STATEMENT_FIELDS)));

/** The relayer for this host, or null when on-chain records are not configured. */
export function configuredRelayer(env = process.env) {
  if (!env.HUMA_PAGES_ADDRESS) return null;
  const name = env.HUMA_CHAIN ?? 'base-sepolia', network = NETWORKS[name];
  if (!network) throw new Error('HUMA_CHAIN must be base-sepolia or base.');
  if (!/^0x[0-9a-fA-F]{64}$/.test(env.HUMA_RELAYER_KEY ?? '')) throw new Error('Set HUMA_RELAYER_KEY to the funded relayer wallet\'s private key.');
  const account = privateKeyToAccount(env.HUMA_RELAYER_KEY), transport = http(env.HUMA_CHAIN_RPC ?? network.rpc, { timeout: 20000 });
  return createRelayer({ name, contract: env.HUMA_PAGES_ADDRESS, dailyLimit: Number(env.HUMA_RELAYER_DAILY_LIMIT ?? 50),
    client: createPublicClient({ chain: network.chain, transport }), wallet: createWalletClient({ account, chain: network.chain, transport }) });
}

export function createRelayer({ name, contract, client, wallet, dailyLimit = 50, now = Date.now }) {
  const network = NETWORKS[name], address = getAddress(contract);
  if (!Number.isSafeInteger(dailyLimit) || dailyLimit < 0) throw new Error('HUMA_RELAYER_DAILY_LIMIT must be a whole number.');
  let day = null, sent = 0, queue = Promise.resolve();
  async function record(statement) {
    const [owner, blockNumber] = await client.readContract({ address, abi: PAGES_ABI, functionName: 'pages', args: [statement] });
    return Number(blockNumber) ? { owner: getAddress(owner), blockNumber: Number(blockNumber) } : null;
  }
  /** One transaction at a time: the daily count can't be raced and nonces never collide. */
  const serial = task => { const run = queue.then(task, task); queue = run.catch(() => {}); return run; };
  return {
    network: name, contract: address, record,
    /** Records a page unless it already is, and returns where. `publicInputs` are 46 bytes32 hex strings. */
    submit: (proof, publicInputs) => serial(async () => {
      const statement = statementKey(publicInputs), owner = getAddress('0x' + publicInputs[45].slice(-40));
      let transactionHash = null, found = await record(statement);
      if (!found) {
        const today = Math.floor(now() / 86400000);
        if (today !== day) { day = today; sent = 0; }
        if (sent >= dailyLimit) throw fail(429, 'The host reached today\'s on-chain allowance. Try again tomorrow.');
        let request;
        try {
          ({ request } = await client.simulateContract({ address, abi: PAGES_ABI, functionName: 'submit', args: [proof, publicInputs], account: wallet.account }));
        } catch (error) { throw fail(422, 'HumaPages would reject this proof (' + (error.shortMessage ?? 'simulation failed') + ').'); }
        sent++;
        transactionHash = await wallet.writeContract(request);
        // A slow or reverted receipt may still mean the page is recorded (e.g. someone else submitted it first).
        const receipt = await client.waitForTransactionReceipt({ hash: transactionHash, timeout: 180000 }).catch(() => null);
        found = await record(statement);
        if (!found) throw fail(502, receipt?.status === 'success' ? 'HumaPages did not record the page.' : 'The page transaction did not confirm. Try again shortly.');
      }
      // The same writing session can't be shown as this page's record under a different wallet.
      if (found.owner !== owner) throw fail(409, 'This writing session is already recorded on-chain for another wallet.');
      return { network: name, contract: address, statement, owner: found.owner, blockNumber: found.blockNumber, transactionHash,
        explorer: transactionHash ? `${network.explorer}/tx/${transactionHash}` : `${network.explorer}/address/${address}` };
    }),
  };
}
