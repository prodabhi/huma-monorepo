#!/usr/bin/env python3
"""Validate native live capture against one frozen cast256 circuit and optional real proof."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import check
import verify

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
TOOLS=ROOT/'build/research/noir-tools'
NATIVE=ROOT/'build/research/noir-compact-native-target/release'

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',default='native-live-v1')
    parser.add_argument('--prove',action='store_true')
    parser.add_argument('--threads',type=int,choices=[2,8],default=2)
    args=parser.parse_args()
    if not args.name.replace('-','').isalnum():parser.error('Use an alphanumeric experiment name')
    env=dict(os.environ,DEVELOPER_DIR='/Library/Developer/CommandLineTools',RAYON_NUM_THREADS='2',
        CARGO_TARGET_DIR=str(ROOT/'build/research/noir-compact-native-target'),HARDWARE_CONCURRENCY=str(args.threads))
    subprocess.run(['cargo','build','--release','--locked','--manifest-path',str(HERE/'native/Cargo.toml'),
        '--lib','--bin','huma-compact-experiment','--example','live_cases','--jobs','2'],env=env,check=True)
    casework=ROOT/'build/research/noir-compact-native-capture'/args.name
    casework.mkdir(parents=True,exist_ok=True)
    paths=[ROOT/'extra/Sources/HumaCore/ExperimentalCompactCapture.swift',ROOT/'extra/Sources/HumaCore/ExperimentalCompactRecorder.swift',
        ROOT/'extra/Sources/HumaCore/SessionLog.swift',ROOT/'extra/Sources/HumaCore/SignedCapture.swift',ROOT/'extra/Sources/HumaCore/Draft.swift',
        HERE/'live-capture.swift',HERE/'native/src/capture.rs',HERE/'native/src/ffi.rs',HERE/'native/src/ops.rs',HERE/'native/src/commit.rs',
        HERE/'native/src/protocol.rs',HERE/'native/examples/live_cases.rs',HERE/'native/Cargo.lock',HERE/'native/include/huma_compact.h']
    source_hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    metadata=casework/'source-hashes.json'
    if metadata.exists():
        if json.loads(metadata.read_text())!=source_hashes:raise RuntimeError('Use a new name for changed native capture code')
    else:
        subprocess.run(['swift','build','--target','HumaCore','--jobs','2'],cwd=ROOT,check=True)
        binary_path=Path(subprocess.check_output(['swift','build','--package-path','extra','--scratch-path','.build','--show-bin-path'],cwd=ROOT,text=True).strip())
        generator=casework/'swift-live-capture'
        subprocess.run(['swiftc','-parse-as-library','-module-cache-path',str(ROOT/'build/module-cache'),
            '-I',str(binary_path),str(HERE/'live-capture.swift'),str(binary_path/'HumaCore.o'),'-o',str(generator)],cwd=ROOT,check=True)
        report=json.loads(subprocess.check_output([str(generator),str(NATIVE/'libhuma_compact_experiment.dylib'),str(casework)],cwd=ROOT))
        (casework/'swift-capture-timing.json').write_text(json.dumps(report,indent=2)+'\n')
        rust_cases=json.loads(subprocess.check_output([str(NATIVE/'examples/live_cases')]))
        (casework/'rust-snapshots.json').write_text(json.dumps(rust_cases));(casework/'rust-snapshots.json').chmod(0o600)
        metadata.write_text(json.dumps(source_hashes,indent=2)+'\n')
    snapshot=json.loads((casework/'SwiftLive250-snapshot.json').read_bytes())
    if snapshot['ok'] is not True:raise RuntimeError('Swift live capture failed')
    swift=snapshot['result']
    compiled=json.loads(subprocess.check_output([str(NATIVE/'huma-compact-experiment'),'compile'],
        input=(casework/'SwiftLive250-legacy.json').read_bytes()))
    if compiled['words']!=swift['private']['words']:raise RuntimeError('Live Swift words differ from independently validated capture history')
    legacy=json.loads((casework/'SwiftLive250-legacy.json').read_bytes())
    offsets=[compiled['captureOffsets'][cp['captureCount']] for cp in legacy['session']['signedCheckpoints']]
    if offsets!=[cp['offset'] for cp in swift['private']['checkpoints']]:raise RuntimeError('Live checkpoint boundaries differ')
    cases=[dict(name='SwiftLive250',snapshot=swift)]+json.loads((casework/'rust-snapshots.json').read_bytes())
    work=ROOT/'build/research/noir-compact/cast256'
    artifact=work/'target/huma_compact_experiment.json';vk=work/'target/setup/vk'
    pins={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [artifact,vk]}
    results=[]
    for case in cases:
        snapshot=case['snapshot'];private=snapshot['private'];capsule=snapshot['capsule'];words=private['words'];count=len(private['checkpoints'])
        if not 0<len(words)<=1536 or not 2<=count<=8:raise RuntimeError('Live case exceeds fixed profile')
        expected=dict(capsule['journal']);expected.update(checkpoint_count=count,checkpoint_roots=expected['checkpoint_roots']+['0']*(8-count))
        values=dict(nonce=private['nonce'],salt=private['salt'],op_count=len(words),
            ops=[dict(code=w>>56,arg=w&((1<<56)-1)) for w in words]+[dict(code=0,arg=0)]*(1536-len(words)),
            checkpoints=private['checkpoints']+[dict(offset=0,unix=0,elapsed=0)]*(8-count),expected=expected)
        label=args.name.replace('-','')+case['name']
        started=time.monotonic()
        result=check.solve(work,label,values,True)
        result.update(name=case['name'],operations=len(words),checkpoints=count,signaturesDuringCapture=True,proofGenerated=False)
        capsule_path=casework/(case['name']+'-capsule.json');capsule_path.write_text(json.dumps(capsule));capsule_path.chmod(0o600)
        subprocess.run([str(NATIVE/'huma-compact-experiment'),'signatures'],input=capsule_path.read_bytes(),stdout=subprocess.DEVNULL,check=True)
        if args.prove and case['name']=='SwiftLive250':
            proof_dir=casework/'proof'
            command=[TOOLS/'worker-bench',TOOLS/'bb/bb','prove','-b',artifact,'-t','noir-recursive','-c',ROOT/'build/research/noir-crs',
                '-w',work/'target'/(label+'.gz'),'-k',vk,'-o',proof_dir]
            proved=subprocess.run([str(x) for x in command],env=env,capture_output=True,text=True,timeout=195)
            if proved.returncode:raise RuntimeError(proved.stderr[-1500:])
            timing=json.loads(proved.stdout)
            checked=verify.verify(work,proof_dir,capsule_path,snapshot['text'])
            result.update(proofGenerated=True,verified=checked['verified'],proveMs=timing['elapsedMs'],
                contiguousWitnessProveVerifyMs=round((time.monotonic()-started)*1000,2),proofIdentity=checked['proofIdentity'])
            spec=importlib.util.spec_from_file_location('compact_export',HERE/'export.py');exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)
            public,_=exporter.public_export(work,proof_dir,capsule_path,snapshot['text'])
            public_path=casework/'public-proof.json';public_path.write_text(json.dumps(public,ensure_ascii=False));public_path.chmod(0o600)
            reader=json.loads(subprocess.check_output(['node',str(HERE/'browser/verify-file.mjs'),str(public_path)]))
            if not reader['verified'] or reader['proofIdentity']!=checked['proofIdentity']:raise RuntimeError('Independent public reader differs')
            result['independentWasmReader']=True
        results.append(result)
    if {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [artifact,vk]}!=pins:raise RuntimeError('Frozen trusted program or VK changed')
    report=dict(experimental=True,softwareKeysOnly=True,manufacturerAttestationVerified=False,macAppProverCutover=False,
        profile='cast256-v1',sourceHashes=source_hashes,swiftCapture=json.loads((casework/'swift-capture-timing.json').read_text()),cases=results,
        programKeyHash=pins[str(vk)])
    (casework/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
