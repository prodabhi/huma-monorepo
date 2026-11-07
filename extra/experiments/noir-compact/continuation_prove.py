#!/usr/bin/env python3
"""Offline proofs of selected replay-continuation chunks, not Huma sessions."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks

OFFLINE=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network-outbound)']

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('work',type=Path)
    args=parser.parse_args();os.umask(0o077);work=args.work.resolve()
    if work.parent!=cases.ROOT/'build/research/noir-continuation' or 'unsafe' in work.name:
        raise ValueError('Only a reviewed continuation component may be proved')
    sizing=json.loads((work/'results.json').read_text());fixture=json.loads((work/'reference.json').read_text())
    constraints=json.loads((work/'constraint-results.json').read_text())
    artifact=work/'target/huma_continuation_component.json'
    artifact_hash=hashlib.sha256(artifact.read_bytes()).hexdigest()
    if hashlib.sha256((work/'src/main.nr').read_bytes()).hexdigest()!=sizing['sourceSha256']:
        raise ValueError('Frozen continuation source changed')
    if constraints['artifactSha256']!=artifact_hash or len(constraints['cases'])!=19 or any(
        row['accepted']!=row['expectedAccepted'] for row in constraints['cases']):
        raise ValueError('All selected boundaries and malicious-state checks must pass before setup')
    if sizing['scalarPack']!=12 or sizing['gates']['functions'][0]['circuit_size']>262144:
        raise ValueError('Component exceeds the reviewed quarter-size research budget')
    if (work/'proof-results.json').exists() or (work/'target/setup').exists():
        raise ValueError('Existing proof and key outputs are immutable')
    common=['-b',artifact,'-t','noir-recursive','-c',cases.ROOT/'build/research/noir-crs']
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    def worker(command):
        result=subprocess.run([str(x) for x in [cases.TOOLS/'worker-bench',*OFFLINE,cases.TOOLS/'bb/bb',*command]],
            env=cases.budget.ENV,capture_output=True,timeout=210)
        if result.returncode:raise RuntimeError('Resource-controlled backend did not complete: '+result.stderr.decode()[-1000:])
        return json.loads(result.stdout)
    def verify(proof,inputs):
        result=subprocess.run([str(x) for x in [*OFFLINE,cases.TOOLS/'bb/bb','verify','-p',proof,'-i',inputs,
            '-k',work/'target/setup/vk','-t','noir-recursive','-c',cases.ROOT/'build/research/noir-crs']],
            env=cases.budget.ENV,capture_output=True,timeout=20)
        if result.returncode not in [0,1]:raise RuntimeError('Verifier did not return a conclusive result')
        return result.returncode==0
    setup=worker(['write_vk',*common,'-o',work/'target/setup'])
    reports=[]
    for selected in fixture['selected']:
        label='Chunk'+str(selected['index']);values={k:v for k,v in selected.items() if k!='index'}
        checks.toml(work/(label+'.toml'),values)
        started=time.monotonic()
        witness,_=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,cases.TOOLS/'noir/nargo','execute',label,'--prover-name',label],work)
        output=work/'target'/('proof-'+label)
        if output.exists():raise ValueError('Existing proof directory is immutable')
        timing=worker(['prove',*common,'-w',work/'target'/(label+'.gz'),'-k',work/'target/setup/vk','-o',output])
        b=selected['expected']
        public=b['nonce']+[b[k] for k in ['start_root','end_root','start_offset','end_offset','capture_root','final_step']]
        expected=b''.join(int(n).to_bytes(32,'big') for n in public)
        if (output/'public_inputs').read_bytes()!=expected:raise ValueError('The proof exposes a different boundary')
        if not verify(output/'proof',output/'public_inputs'):raise ValueError('Valid component proof rejected')
        elapsed=round((time.monotonic()-started)*1000,3)
        changed=bytearray(expected);changed[-33]^=1
        changed_path=output/'changed_public_inputs';changed_path.write_bytes(changed)
        if verify(output/'proof',changed_path):raise ValueError('Modified public capture prefix accepted')
        changed_proof=bytearray((output/'proof').read_bytes());changed_proof[len(changed_proof)//2]^=1
        changed_path=output/'changed_proof';changed_path.write_bytes(changed_proof)
        if verify(changed_path,output/'public_inputs'):raise ValueError('Modified proof accepted')
        report=dict(index=selected['index'],boundary=b,nativeVerified=True,changedCapturePrefixRejected=True,
            changedProofRejected=True,witness=witness,proveMs=timing['elapsedMs'],
            witnessProveVerifyMs=elapsed,proofBytes=(output/'proof').stat().st_size,publicInputsBytes=len(expected),
            proofSha256=hashlib.sha256((output/'proof').read_bytes()).hexdigest(),
            publicInputsSha256=hashlib.sha256(expected).hexdigest())
        reports.append(report);print(json.dumps(report),flush=True)
    if hashlib.sha256(artifact.read_bytes()).hexdigest()!=artifact_hash:raise ValueError('Circuit changed during proving')
    full=len(reports)==fixture['chunks']
    if full:
        assert reports[0]['boundary']['start_offset']==0
        for left,right in zip(reports,reports[1:]):
            a,b=left['boundary'],right['boundary']
            assert a['end_root']==b['start_root'] and a['end_offset']==b['start_offset'] and a['nonce']==b['nonce']
        assert all(row['boundary']['final_step']==(i+1==len(reports)) for i,row in enumerate(reports))
    result=dict(kind='huma-continuation-component-proof-v1',case=fixture['case'],
        softwareFixturesOnly=True,ownerIdentityUsed=False,completeHumaSessionProof=False,
        tenThousandCharacterSessionSupported=False,appChanged=False,allReplayChunksProved=full,
        nativeChunks=fixture['chunks'],selectedChunksProved=len(reports),
        artifactSha256=artifact_hash,sourceSha256=sizing['sourceSha256'],
        keySha256=hashlib.sha256((work/'target/setup/vk').read_bytes()).hexdigest(),
        setupMs=setup['elapsedMs'],setupExcludedFromChunkTiming=True,threads=2,nice=10,cases=reports)
    cases.write(work/'proof-results.json',result);print(json.dumps(result),flush=True)

if __name__=='__main__':main()
