#!/usr/bin/env python3
"""Composite experimental verification: pinned local ZK build AND every P256 signature."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[3]
BB=ROOT/'build/research/noir-tools/bb/bb'
NATIVE=ROOT/'build/research/noir-compact-native-target/release/huma-compact-experiment'
MODULUS=21888242871839275222246405745257275088548364400416034343698204186575808495617


def decode(kind,values):
    if kind['kind']=='array':return [decode(kind['type'],values) for _ in range(kind['length'])]
    if kind['kind']=='struct':return {f['name']:decode(f['type'],values) for f in kind['fields']}
    value=next(values)
    if kind['kind']=='field':
        if not 0<=value<MODULUS:raise ValueError('Noncanonical field')
        return str(value)
    if kind['kind']=='boolean':
        if value not in [0,1]:raise ValueError('Noncanonical boolean')
        return bool(value)
    if kind['kind']!='integer' or not 0<=value<2**kind['width']:raise ValueError('Invalid public integer')
    return value


def verify(trusted_build,proof_dir,capsule_path,text=None,expected_key=None):
    # Reader chooses a locally compiled/trusted ABI/VK. Capsule cannot choose one.
    abi=json.loads((trusted_build/'target/huma_compact_experiment.json').read_text())['abi']
    public=[x for x in abi['parameters'] if x['visibility']=='public']
    if len(public)!=1 or public[0]['name']!='expected':raise ValueError('Unexpected circuit ABI')
    inputs=proof_dir/'public_inputs';proof=proof_dir/'proof'
    if not 0<inputs.stat().st_size<=131072 or not 0<proof.stat().st_size<=65536:raise ValueError('Proof exceeds experiment bounds')
    raw=inputs.read_bytes()
    if len(raw)%32:raise ValueError('Truncated public inputs')
    values=iter(int.from_bytes(raw[i:i+32],'big') for i in range(0,len(raw),32))
    journal=decode(public[0]['type'],values)
    if next(values,None) is not None:raise ValueError('Extra public inputs')
    if capsule_path.stat().st_size>512*1024:raise ValueError('Capsule exceeds bounds')
    capsule_raw=capsule_path.read_bytes();capsule=json.loads(capsule_raw)
    checkpoint_capacity=len(journal['checkpoint_roots'])
    if 'checkpoint_count' in journal:
        count=journal.pop('checkpoint_count')
        if not 2<=count<=checkpoint_capacity<=1024 or any(r!='0' for r in journal['checkpoint_roots'][count:]):
            raise ValueError('Invalid checkpoint padding/count')
        journal['checkpoint_roots']=journal['checkpoint_roots'][:count]
    if capsule.get('kind')!='huma-compact-replay-experiment-v3' or capsule.get('journal')!=journal:
        raise ValueError('Signed capsule does not match proven journal')
    env=dict(os.environ,HARDWARE_CONCURRENCY='2')
    if subprocess.check_output([str(BB),'--version'],text=True,env=env).strip()!='5.2.1':raise ValueError('Unexpected backend version')
    p=subprocess.run([str(x) for x in [BB,'verify','-p',proof,'-i',inputs,'-k',trusted_build/'target/setup/vk',
        '-t','noir-recursive','-c',ROOT/'build/research/noir-crs']],env=env,capture_output=True,timeout=15)
    if p.returncode:raise ValueError('ZK proof rejected')
    p=subprocess.run([str(NATIVE),'signatures'],input=capsule_raw,capture_output=True,timeout=15)
    if p.returncode:raise ValueError('Checkpoint signatures rejected')
    key=json.loads(p.stdout)['keyHash']
    if expected_key is not None and (not re.fullmatch('[0-9a-f]{64}',expected_key) or expected_key!=key):
        raise ValueError('Unexpected capture key')
    if text is not None:
        canonical=text.rstrip(' \t').encode('utf-8')
        if len(canonical)!=journal['byte_length'] or list(hashlib.sha256(canonical).digest())!=journal['text_hash']:
            raise ValueError('Reader text differs')
    program_key_hash=hashlib.sha256((trusted_build/'target/setup/vk').read_bytes()).digest()
    identity=hashlib.sha256(b'HUMA_COMPACT_EXPERIMENT_ID_V3\0'+program_key_hash+raw+bytes(capsule['public_key'])).hexdigest()
    return dict(verified=True,experimental=True,proofIdentity=identity,programKeyHash=program_key_hash.hex(),keyHash=key,journal=journal,
                checkpointCapacity=checkpoint_capacity,disclosedPublicKey=True,attestationVerified=False,trustedTime=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trusted-build',type=Path,required=True)
    p.add_argument('--proof-dir',type=Path,required=True)
    p.add_argument('--capsule',type=Path,required=True)
    p.add_argument('--text-file',type=Path)
    p.add_argument('--expected-key')
    a=p.parse_args()
    try:
        result=verify(a.trusted_build,a.proof_dir,a.capsule,a.text_file.read_bytes().decode('utf-8') if a.text_file else None,a.expected_key)
        print(json.dumps(result,indent=2))
    except (ValueError,OSError,subprocess.SubprocessError,StopIteration,KeyError) as error:p.exit(1,str(error)+'\n')
