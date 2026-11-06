#!/bin/bash
# Rebuilds the batch circuit, its EVM verification key and the Solidity verifier, then pins them.
# Run only when src/ changes; the outputs are committed so the sharing server needs no compiler.
set -euo pipefail
cd "$(dirname "$0")"
REPO_ROOT=$(cd ../../../.. && pwd)
ONCHAIN_ROOT=$(cd .. && pwd)
NARGO=${NARGO:-$REPO_ROOT/build/research/noir-tools/noir/nargo}
BB=${BB:-$REPO_ROOT/build/research/noir-tools/bb/bb}
CRS=${HUMA_BATCH_CRS:-$REPO_ROOT/build/research/batch-crs}   # never the app bundle's reference string
VERIFIER=$ONCHAIN_ROOT/contracts/src/HumaBatchVerifier.sol
"$NARGO" compile
rm -rf target/vk
"$BB" write_vk -b target/huma_batch.json -t evm-no-zk -c "$CRS" -o target/vk
"$BB" write_solidity_verifier -k target/vk/vk -t evm-no-zk --optimized -o "$VERIFIER"
sed -i '' 's/^contract HonkVerifier /contract HumaBatchVerifier /' "$VERIFIER"
python3 -c "import json,sys; d=json.load(open('target/huma_batch.json')); json.dump({'noir_version':d['noir_version'],'abi':d['abi'],'bytecode':d['bytecode']},open('circuit.json','w'))"
cp target/vk/vk batch.vk
shasum -a 256 circuit.json batch.vk "$VERIFIER" | sed "s#$ONCHAIN_ROOT/##" > pins.txt
cat pins.txt
