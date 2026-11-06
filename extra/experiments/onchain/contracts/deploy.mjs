// Deploys the three page verifiers and HumaPages from the relayer wallet (HUMA_RELAYER_KEY, funded
// by the host), then prints the env lines the sharing server needs. Run after `forge build` in this
// archived contracts directory:
//   node --env-file=.env.local extra/experiments/onchain/contracts/deploy.mjs [base-sepolia|base]
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createRequire } from 'node:module';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../../../..');
const require = createRequire(path.join(repo, 'frontend/package.json'));
const { createPublicClient, createWalletClient, http, formatEther } = await import(require.resolve('viem'));
const { privateKeyToAccount } = await import(require.resolve('viem/accounts'));
const { NETWORKS } = await import(new URL('../relayer.mjs', import.meta.url));

const name = process.argv[2] ?? 'base-sepolia', network = NETWORKS[name];
if (!network) throw new Error('Network must be base-sepolia or base.');
if (!/^0x[0-9a-fA-F]{64}$/.test(process.env.HUMA_RELAYER_KEY ?? '')) throw new Error('Add HUMA_RELAYER_KEY (the funded relayer wallet\'s private key) to .env.local first.');
const artifact = async contract => JSON.parse(await readFile(path.join(here, 'out', contract + '.sol', contract + '.json'), 'utf8'));
const account = privateKeyToAccount(process.env.HUMA_RELAYER_KEY), transport = http(process.env.HUMA_CHAIN_RPC ?? network.rpc, { timeout: 30000 });
const client = createPublicClient({ chain: network.chain, transport }), wallet = createWalletClient({ account, chain: network.chain, transport });
console.log(`Deploying from ${account.address} (balance ${formatEther(await client.getBalance({ address: account.address }))} ETH) to ${name}`);

async function deploy(contract, args = []) {
  const { abi, bytecode } = await artifact(contract);
  const hash = await wallet.deployContract({ abi, bytecode: bytecode.object, args });
  const receipt = await client.waitForTransactionReceipt({ hash, timeout: 180000 });
  if (receipt.status !== 'success' || !receipt.contractAddress) throw new Error(`${contract} deployment failed (${hash}).`);
  console.log(`${contract} at ${receipt.contractAddress} (gas ${receipt.gasUsed}) ${network.explorer}/tx/${hash}`);
  return receipt.contractAddress;
}
// HUMA_VERIFIER_ADDRESSES=a,b,c reuses deployed verifiers (1024, 4096, 10000) when only HumaPages changed.
const reuse = (process.env.HUMA_VERIFIER_ADDRESSES ?? '').split(',').filter(Boolean);
if (reuse.length && (reuse.length !== 3 || reuse.some(a => !/^0x[0-9a-fA-F]{40}$/.test(a)))) throw new Error('HUMA_VERIFIER_ADDRESSES needs three addresses.');
const verifiers = [...reuse];
if (!reuse.length) for (const tier of [1024, 4096, 10000]) verifiers.push(await deploy(`HumaFinal${tier}Verifier`));
else console.log('Reusing verifiers', verifiers.join(', '));
const pages = await deploy('HumaPages', verifiers);
console.log(`\nAdd to .env.local:\nHUMA_CHAIN=${name}\nHUMA_PAGES_ADDRESS=${pages}\n` +
  `\nPin it for readers in extra/experiments/onchain/chain.mjs: OFFICIAL_CONTRACTS['${name}'] = '${pages}', then rebuild the reader bundle.`);
