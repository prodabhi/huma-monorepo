#!/usr/bin/env python3
"""Prove an already signed, simulated Swift V4 capture without re-signing it."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import assurance_cases as assurance

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
TRUSTED=ROOT/'build/research/noir-assurance/assurance-typed250-v1'
TOOLS=ROOT/'build/research/noir-tools'
BYTECODE_PIN='15d6b3c7d5db15310f56452b0d5808444daf166c6a610daffdd7ddf682c8b1c5'
VK_PIN='1cab7a6b3ce5947916ad8bc09616c801de66f896eecc6677dbaf43284696a496'
ABI_PIN='729cc9a345f5b8a37549cddbe3ef848edb7bfc8d051867c016928ddabbf3fdc5'
OFFLINE=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network-outbound)']
sys.path.insert(0,str(ROOT/'extra/experiments/noir-replay'))
import fixture
import size as budget

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600)

def check_program(artifact,vk):
    # Nargo's whole JSON also contains debug/source metadata. Pin the actual
    # program and the independently shipped reader ABI, rather than that metadata.
    program=json.loads(artifact.read_text())
    reader=HERE/'browser/assets/assurance-abi.json'
    if hashlib.sha256(program['bytecode'].encode()).hexdigest()!=BYTECODE_PIN or digest(vk)!=VK_PIN or digest(reader)!=ABI_PIN:
        raise ValueError('Frozen reader program, ABI or VK changed')
    public=[p for p in program['abi']['parameters'] if p['visibility']=='public']
    if len(public)!=1 or public[0]['name']!='expected' or public[0]['type']!=json.loads(reader.read_text()):
        raise ValueError('Program public ABI differs from the pinned reader')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path)
    p.add_argument('--prove',action='store_true')
    a=p.parse_args();work=a.capture.resolve();os.umask(0o077)
    input_file=work/'input.json'
    if input_file.stat().st_size>4*1024*1024:raise ValueError('Live fixture exceeds acceptance bound')
    raw=input_file.read_bytes();request=json.loads(raw);snapshot=request['snapshot'];capsule=snapshot['capsule']
    artifact=TRUSTED/'target/huma_compact_experiment.json';vk=TRUSTED/'target/setup/vk'
    check_program(artifact,vk)
    artifact_hash=digest(artifact)
    if subprocess.check_output([str(TOOLS/'bb/bb'),'--version'],text=True).strip()!='5.2.1':raise ValueError('Unexpected prover')
    if '1.0.0-beta.25' not in subprocess.check_output([str(TOOLS/'noir/nargo'),'--version'],text=True):raise ValueError('Unexpected compiler')
    result=subprocess.run([*OFFLINE,str(assurance.NATIVE),'assurance-input'],input=raw,capture_output=True,timeout=20)
    if result.returncode:raise ValueError('Native full-session binding rejected this capture')
    values=json.loads(result.stdout)
    if values!=assurance.inputs(snapshot['private'],capsule,assurance.PROFILES['cast256']):raise ValueError('Independent ABI input adapters disagree')
    write(work/'inputs.json',values);write(work/'capsule.json',capsule)
    label='SwiftLiveV4'+hashlib.sha256(raw).hexdigest()[:16]
    prover=TRUSTED/(label+'.toml')
    prover.write_text('\n'.join(k+' = '+fixture.toml(v) for k,v in values.items())+'\n');prover.chmod(0o600)
    budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    started=time.monotonic()
    # Keep process/RSS monitoring outside Seatbelt: macOS refuses /bin/ps inside
    # it even with allow-default. Every witness/proof/verification child is offline.
    witness,_=budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,TOOLS/'noir/nargo','execute',label,'--prover-name',label],TRUSTED)
    report=dict(softwareKeysOnly=True,simulatedInputAndTimes=True,existingSignaturesPreserved=True,
        completeSignedSessionBinding=True,independentABIAdaptersAgree=True,proofGenerated=False,
        inputSha256=hashlib.sha256(raw).hexdigest(),capture=json.loads((work/'capture-report.json').read_text()),
        witness=witness,artifactSha256=artifact_hash,bytecodeSha256=BYTECODE_PIN,publicABIHash=ABI_PIN,
        programKeyHash=VK_PIN,threads=2,zeroKnowledge=True,cryptoChildrenOutboundNetworkDenied=True)
    if a.prove:
        proof=work/'proof-2-threads'
        if proof.exists():raise ValueError('Existing proof directory was not replaced; verify it separately')
        env=dict(os.environ,HARDWARE_CONCURRENCY='2',RAYON_NUM_THREADS='2')
        cmd=[TOOLS/'worker-bench',*OFFLINE,TOOLS/'bb/bb','prove','-b',artifact,'-w',TRUSTED/'target'/(label+'.gz'),
            '-k',vk,'-o',proof,'-t','noir-recursive','-c',ROOT/'build/research/noir-crs']
        proved=subprocess.run([str(x) for x in cmd],cwd=work,env=env,capture_output=True,text=True,timeout=195)
        if proved.returncode:raise RuntimeError(proved.stderr[-1500:])
        timing=json.loads(proved.stdout)
        checked=assurance.verify(TRUSTED,proof,capsule,snapshot['text'],tool_prefix=OFFLINE)
        public=dict(kind='huma-compact-assurance-public-proof-v4',profile='assurance256-v1',
            proof=base64.b64encode((proof/'proof').read_bytes()).decode(),publicInputs=base64.b64encode((proof/'public_inputs').read_bytes()).decode(),
            publicKey=base64.b64encode(bytes(capsule['public_key'])).decode(),
            signatures=[base64.b64encode(bytes(v)).decode() for v in capsule['signatures']],
            presenceSignatures=[base64.b64encode(bytes(v)).decode() for v in capsule['presence_signatures']],text=snapshot['text'])
        write(work/'public-proof.json',public)
        report.update(proofGenerated=True,verified=checked['verified'],proofIdentity=checked['proofIdentity'],
            proveMs=timing['elapsedMs'],witnessProveNativeVerifyMs=round((time.monotonic()-started)*1000,2),
            checkpointSignatures=checked['checkpointSignatures'],presenceSignatures=checked['presenceSignatures'])
    check_program(artifact,vk)
    if digest(artifact)!=artifact_hash:raise ValueError('Artifact metadata changed during acceptance')
    report['sourceSha256']={str(p.relative_to(ROOT)):digest(p) for p in [HERE/'live_assurance_cases.py',HERE/'native/src/assurance_input.rs',HERE/'live-assurance.swift']}
    write(work/'acceptance.json',report);print(json.dumps(report),flush=True)

if __name__=='__main__':main()
