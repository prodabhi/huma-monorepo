#!/usr/bin/env python3
"""Export verified cast256 evidence without a private witness or duplicate journal."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import verify

ROOT = Path(__file__).resolve().parents[3]
VK_HASH = '149d13f114a80bc03df8966aa5b716ba86acc383c48c620e0bdb1afb09f4b600'
ABI_HASH = 'd3ac50086728791ab41503666e4f5454b9bfe30000abf2ddfefd624a7c21c952'


def public_export(trusted_build, proof_dir, capsule, text=None):
    vk = (trusted_build / 'target/setup/vk').read_bytes()
    artifact = json.loads((trusted_build / 'target/huma_compact_experiment.json').read_text())
    expected = [p for p in artifact['abi']['parameters'] if p['visibility'] == 'public']
    if len(expected) != 1 or expected[0]['name'] != 'expected':
        raise ValueError('Unexpected public ABI')
    # Match the frozen ABI file byte-for-byte after its original serialization.
    abi = (json.dumps(expected[0]['type'], indent=2) + '\n').encode()
    if hashlib.sha256(vk).hexdigest() != VK_HASH or hashlib.sha256(abi).hexdigest() != ABI_HASH:
        raise ValueError('Build is not the reader-supported cast256 profile')
    proof = (proof_dir / 'proof').read_bytes()
    inputs = (proof_dir / 'public_inputs').read_bytes()
    if len(proof) != 14656 or len(inputs) != 1824:
        raise ValueError('Unsupported proof/public-input size')
    checked = verify.verify(trusted_build, proof_dir, capsule, text)
    raw = json.loads(capsule.read_bytes())
    encoded = lambda value: base64.b64encode(bytes(value)).decode('ascii')
    result = dict(kind='huma-compact-public-proof-v1', profile='cast256-v1',
                  proof=encoded(proof), publicInputs=encoded(inputs),
                  publicKey=encoded(raw['public_key']), signatures=[encoded(s) for s in raw['signatures']])
    if text is not None:
        if len(text.encode('utf-8')) > 65536:
            raise ValueError('Public text exceeds export limits')
        result['text'] = text
    return result, checked


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted-build', type=Path, default=ROOT / 'build/research/noir-compact/cast256')
    parser.add_argument('--proof-dir', type=Path, required=True)
    parser.add_argument('--capsule', type=Path, required=True)
    parser.add_argument('--text-file', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        text = args.text_file.read_bytes().decode('utf-8') if args.text_file else None
        exported, result = public_export(args.trusted_build, args.proof_dir, args.capsule, text)
        data = (json.dumps(exported, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        with args.output.open('xb') as file:
            os.chmod(args.output, 0o600)
            file.write(data)
        print(json.dumps(dict(exported=True, experimental=True, proofIdentity=result['proofIdentity'],
                             bytes=len(data), privateHistoryIncluded=False)))
    except (ValueError, OSError, KeyError, verify.subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')
