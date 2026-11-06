// Deploys HumaPoseidon2 and HumaPagesV4 next to the six verifiers already deployed (deployments/<chainId>.json, from
// deploy.mjs), and adds them to that record. HumaPagesV4 checks everything HumaPagesV3 does and the reader's checks
// besides the proofs (signatures, event digest, nonce binding, statement bounds, passkey approvals).
//
//   HUMA_CHAIN_RPC   RPC endpoint (default https://sepolia.base.org)
//   HUMA_RELAYER_KEY 0x… private key of the funded deployer (never printed)
//
// Usage: forge build && node deploy-v4.mjs [--yes]   (anything but a local chain, 31337, needs --yes)
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
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
console.log(JSON.stringify({ rpc: rpc.replace(/\/\/([^/]*@)?/, '//'), chainId, deployer: account.address, balance: formatEther(await publicClient.getBalance({ address: account.address })) }));
if (chainId !== 31337 && !process.argv.includes('--yes')) throw new Error(`Chain ${chainId} is not local: pass --yes to deploy there.`);

const recordFile = path.join(here, 'deployments', `${chainId}.json`);
if (!existsSync(recordFile)) throw new Error(`No ${path.relative(here, recordFile)}: deploy the verifiers first (deploy.mjs).`);
const record = JSON.parse(readFileSync(recordFile, 'utf8'));
const v = record.verifiers;
for (const [name, address] of Object.entries(v)) if ((await publicClient.getCode({ address }))?.length > 2 !== true) throw new Error(`${name} has no code at ${address}.`);

const artifact = name => JSON.parse(readFileSync(path.join(here, 'out', name + '.sol', name + '.json'), 'utf8'));
const deploy = async (name, args = []) => {
  const { abi, bytecode } = artifact(name);
  const hash = await walletClient.deployContract({ abi, bytecode: bytecode.object, args });
  const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 180000 });
  if (receipt.status !== 'success' || !receipt.contractAddress) throw new Error(`${name}: deployment failed (${hash})`);
  console.log(JSON.stringify({ contract: name, address: receipt.contractAddress, tx: hash, gasUsed: String(receipt.gasUsed) }));
  record.transactions = { ...record.transactions, [name]: hash };
  return receipt.contractAddress;
};
record.HumaPoseidon2 = await deploy('HumaPoseidon2');
record.HumaPagesV4 = await deploy('HumaPagesV4', [v.HumaChunk1024Verifier, v.HumaFinal1024Verifier, v.HumaChunk4096Verifier, v.HumaFinal4096Verifier,
  v.HumaChunk10000Verifier, v.HumaFinal10000Verifier, record.HumaPoseidon2]);
record.v4At = new Date().toISOString();
writeFileSync(recordFile, JSON.stringify(record, null, 2) + '\n');
console.log(JSON.stringify({ HumaPagesV4: record.HumaPagesV4, HumaPoseidon2: record.HumaPoseidon2, saved: path.relative(here, recordFile) }));
