// Submits a page's EVM proofs (a folder of part<i>/ and final/, each with `proof` and `public_inputs`, as bb writes them)
// to HumaPagesV3 and prints each transaction's real gas from its receipt. One transaction when the page has at most
// MAX_PARTS_PER_TX parts, else submitParts batches and submitFinal.
//
//   HUMA_CHAIN_RPC, HUMA_RELAYER_KEY as for deploy.mjs; PAGES=<HumaPagesV3 address>
// Usage: node submit.mjs <proof dir> [batch size] [--yes]
import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(process.env.HUMA_VIEM_FROM ?? new URL('../../frontend/package.json', import.meta.url).pathname);
const { createPublicClient, createWalletClient, http, toHex } = require('viem');
const { privateKeyToAccount } = require('viem/accounts');

const [dir, batchArg] = process.argv.slice(2).filter(a => a !== '--yes');
const rpc = process.env.HUMA_CHAIN_RPC ?? 'https://sepolia.base.org', pages = process.env.PAGES;
if (!/^0x[0-9a-fA-F]{40}$/.test(pages ?? '')) throw new Error('Set PAGES to the HumaPagesV3 address.');
const account = privateKeyToAccount(process.env.HUMA_RELAYER_KEY);
const transport = http(rpc, { timeout: 60000 });
const publicClient = createPublicClient({ transport });
const chainId = await publicClient.getChainId();
if (chainId !== 31337 && !process.argv.includes('--yes')) throw new Error(`Chain ${chainId} is not local: pass --yes to submit there.`);
const chain = { id: chainId, name: 'chain-' + chainId, nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [rpc] } } };
const walletClient = createWalletClient({ account, chain, transport });
const { abi } = JSON.parse(readFileSync(path.join(here, 'out/HumaPagesV3.sol/HumaPagesV3.json'), 'utf8'));

const words = buffer => Array.from({ length: buffer.length / 32 }, (_, i) => toHex(buffer.subarray(i * 32, i * 32 + 32)));
const read = name => ({ proof: toHex(readFileSync(path.join(dir, name, 'proof'))), inputs: words(readFileSync(path.join(dir, name, 'public_inputs'))) });
const count = readdirSync(dir).filter(n => /^part\d+$/.test(n)).length;
const parts = Array.from({ length: count }, (_, i) => read('part' + i)), final = read('final');
const tier = Number(BigInt(final.inputs[14]));
const max = Number(await publicClient.readContract({ address: pages, abi, functionName: 'MAX_PARTS_PER_TX' }));
const batch = Math.min(Number(batchArg ?? max), max);

const send = async (functionName, args) => {
  const hash = await walletClient.writeContract({ address: pages, abi, functionName, args, gas: 16_000_000n });
  const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 180000 });
  console.log(JSON.stringify({ functionName, status: receipt.status, gasUsed: String(receipt.gasUsed), tx: hash, block: String(receipt.blockNumber) }));
  if (receipt.status !== 'success') throw new Error(functionName + ' reverted');
  return receipt;
};
let total = 0n;
if (count <= max && !batchArg) {
  total += (await send('submit', [parts.map(p => p.proof), parts.map(p => p.inputs), final.proof, final.inputs])).gasUsed;
} else {
  const genesis = parts[0].inputs[0];
  for (let at = 0; at < count; at += batch) {
    const run = parts.slice(at, at + batch);
    total += (await send('submitParts', [genesis, BigInt(tier), BigInt(at), run.map(p => p.proof), run.map(p => p.inputs)])).gasUsed;
  }
  total += (await send('submitFinal', [genesis, final.proof, final.inputs])).gasUsed;
}
const { keccak256, encodePacked } = require('viem');
const statement = keccak256(encodePacked(final.inputs.map(() => 'bytes32'), final.inputs));
const verified = await publicClient.readContract({ address: pages, abi, functionName: 'verified', args: [statement] });
console.log(JSON.stringify({ tier, parts: count, totalGas: String(total), statement, verified }));
