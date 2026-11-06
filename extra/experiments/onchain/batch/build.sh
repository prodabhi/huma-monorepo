#!/bin/bash
# Rebuilds the batch circuit, its EVM verification key and the Solidity verifier, then pins them.
# Run only when src/ changes; the outputs are committed so the sharing server needs no compiler.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../../..
NARGO=${NARGO:-$ROOT/build/research/noir-tools/noir/nargo}
BB=${BB:-$ROOT/build/research/noir-tools/bb/bb}
CRS=${HUMA_BATCH_CRS:-$ROOT/build/research/batch-crs}   # never the app bundle's reference string
"$NARGO" compile
rm -rf target/vk
"$BB" write_vk -b target/huma_batch.json -t evm-no-zk -c "$CRS" -o target/vk
"$BB" write_solidity_verifier -k target/vk/vk -t evm-no-zk --optimized -o "$ROOT/contracts/src/HumaBatchVerifier.sol"
sed -i '' 's/^contract HonkVerifier /contract HumaBatchVerifier /' "$ROOT/contracts/src/HumaBatchVerifier.sol"
python3 -c "import json,sys; d=json.load(open('target/huma_batch.json')); json.dump({'noir_version':d['noir_version'],'abi':d['abi'],'bytecode':d['bytecode']},open('circuit.json','w'))"
cp target/vk/vk batch.vk
shasum -a 256 circuit.json batch.vk "$ROOT/contracts/src/HumaBatchVerifier.sol" | sed "s#$ROOT/##" > pins.txt
cat pins.txt
