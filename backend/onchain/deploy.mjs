// Deploys Huma's on-chain page verification: the six verifiers bb generated from the existing long3 circuits
// (chunk/final × 1024/4096/10000, `-t evm --optimized`) and HumaPagesV3, which routes each page to its tier's pair.
// Reads the compiled contracts from foundry/out (run `forge build` in foundry/ first).
//
//   HUMA_CHAIN_RPC   RPC endpoint (default https://sepolia.base.org)
//   HUMA_RELAYER_KEY 0x… private key of the funded deployer (never printed)
//
// Usage: node deploy.mjs [--yes]
// Anything other than a local chain (31337) is refused without --yes, so it can't deploy to a public chain by accident.
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(process.env.HUMA_VIEM_FROM ?? new URL('../../frontend/package.json', import.meta.url).pathname);
const { createPublicClient, createWalletClient, http, formatEther } = require('viem');
const { privateKeyToAccount } = require('viem/accounts');

const rpc = process.env.HUMA_CHAIN_RPC ?? 'https://sepolia.base.org';
const key = process.env.HUMA_RELAYER_KEY ?? '';
if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error('Set HUMA_RELAYER_KEY to the deployer\'s private key (0x + 64 hex digits).');
const account = privateKeyToAccount(key);
const transport = http(rpc, { timeout: 60000 });
const publicClient = createPublicClient({ transport });
const chainId = await publicClient.getChainId();
const chain = { id: chainId, name: 'chain-' + chainId, nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [rpc] } } };
const walletClient = createWalletClient({ account, chain, transport });
const balance = await publicClient.getBalance({ address: account.address });
console.log(JSON.stringify({ rpc: rpc.replace(/\/\/([^/]*@)?/, '//'), chainId, deployer: account.address, balance: formatEther(balance) }));
if (chainId !== 31337 && !process.argv.includes('--yes')) throw new Error(`Chain ${chainId} is not local: pass --yes to deploy there.`);

const artifact = name => JSON.parse(readFileSync(path.join(here, 'out', name + '.sol', name + '.json'), 'utf8'));
const deploy = async (name, args = []) => {
  const { abi, bytecode } = artifact(name);
  const hash = await walletClient.deployContract({ abi, bytecode: bytecode.object, args });
  const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 180000 });
  if (receipt.status !== 'success' || !receipt.contractAddress) throw new Error(`${name}: deployment failed (${hash})`);
  console.log(JSON.stringify({ contract: name, address: receipt.contractAddress, tx: hash, gasUsed: String(receipt.gasUsed) }));
  return receipt.contractAddress;
};

const verifiers = {};
for (const name of ['HumaChunk1024Verifier', 'HumaFinal1024Verifier', 'HumaChunk4096Verifier', 'HumaFinal4096Verifier', 'HumaChunk10000Verifier', 'HumaFinal10000Verifier'])
  verifiers[name] = await deploy(name);
const pages = await deploy('HumaPagesV3', [verifiers.HumaChunk1024Verifier, verifiers.HumaFinal1024Verifier, verifiers.HumaChunk4096Verifier,
  verifiers.HumaFinal4096Verifier, verifiers.HumaChunk10000Verifier, verifiers.HumaFinal10000Verifier]);
const out = { chainId, rpc: rpc.replace(/\/\/([^/]*@)?/, '//'), deployer: account.address, HumaPagesV3: pages, verifiers, at: new Date().toISOString() };
writeFileSync(path.join(here, 'deployments', `${chainId}.json`), JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify({ HumaPagesV3: pages, saved: `deployments/${chainId}.json` }));
