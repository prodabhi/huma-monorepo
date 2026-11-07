#!/usr/bin/env python3
"""Bounded proof of the terminal-state text finalization; not a Huma session format."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path
import assurance_cases as cases
from continuation_cases import OFFLINE

# Public statement order follows `struct Final` in finalization_cases.circuit.
SCALAR_FIELDS=['state_root','capture_root','origin_root','op_count','raw_scalars','canonical_scalars',
    'raw_bytes','canonical_bytes','raw_commitment','canonical_commitment']

def public_inputs(f):
    values=f['nonce']+[f[k] for k in SCALAR_FIELDS]+f['rules']+[f['policy_satisfied'],f['origin_present'],f['origin_hid']]
    return b''.join(int(v).to_bytes(32,'big') for v in values)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('work',type=Path)
    args=parser.parse_args();os.umask(0o077);work=args.work.resolve()
    if work.parent!=cases.ROOT/'build/research/noir-finalization':raise ValueError('Use a reviewed finalization build')
    sizing=json.loads((work/'results.json').read_text());fixture=json.loads((work/'reference.json').read_text())
    constraints=json.loads((work/'constraint-results.json').read_text());artifact=work/'target/huma_text_finalization.json'
    digest=hashlib.sha256(artifact.read_bytes()).hexdigest()
    if sizing['gates']['functions'][0]['circuit_size']>1_048_576:raise ValueError('Finalization exceeds its 2^20 research budget')
    if hashlib.sha256((work/'src/main.nr').read_bytes()).hexdigest()!=sizing['sourceSha256']:raise ValueError('Circuit source changed')
    for name,d in sizing['dependencySha256'].items():
        if hashlib.sha256((work/'src'/name).read_bytes()).hexdigest()!=d:raise ValueError('Circuit dependency changed')
    required={'ValidFinal','RejectChangedRawCommitment','RejectChangedCanonicalCommitment','RejectCanonicalClaimsRawLength',
              'RejectSwappedCommitments','RejectChangedStateRoot','RejectChangedPrivateText','RejectForgedPolicyResult'}
    rows=constraints['cases']+constraints['emptyTextControls']
    if constraints['artifactSha256']!=digest or not required.issubset({r['case'] for r in rows}) or any(
        r['accepted']!=r['expectedAccepted'] for r in rows):raise ValueError('Required constraint checks are missing')
    if (work/'proof-results.json').exists() or (work/'target/setup').exists():raise ValueError('Existing key/proof outputs are immutable')
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    common=['-b',artifact,'-t','noir-recursive','-c',cases.ROOT/'build/research/noir-crs']
    def worker(command):
        result=subprocess.run([str(x) for x in [cases.TOOLS/'worker-bench',*OFFLINE,cases.TOOLS/'bb/bb',*command]],
            env=cases.budget.ENV,capture_output=True,timeout=300)
        if result.returncode:raise RuntimeError('Resource-controlled backend did not complete: '+result.stderr.decode()[-1000:])
        return json.loads(result.stdout)
    def verify(proof,inputs):
        result=subprocess.run([str(x) for x in [*OFFLINE,cases.TOOLS/'bb/bb','verify','-p',proof,'-i',inputs,
            '-k',work/'target/setup/vk','-t','noir-recursive','-c',cases.ROOT/'build/research/noir-crs']],
            env=cases.budget.ENV,capture_output=True,timeout=30)
        if result.returncode not in [0,1]:raise RuntimeError('Verifier returned an inconclusive result')
        return result.returncode==0
    setup=worker(['write_vk',*common,'-o',work/'target/setup'])
    started=time.monotonic()
    witness,_=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,cases.TOOLS/'noir/nargo','execute','Final','--prover-name','ValidFinal'],work)
    output=work/'target/proof-final'
    timing=worker(['prove',*common,'-w',work/'target/Final.gz','-k',work/'target/setup/vk','-o',output])
    expected=public_inputs(fixture['inputs']['expected'])
    if (output/'public_inputs').read_bytes()!=expected:raise ValueError('Proof exposes a different final statement')
    if not verify(output/'proof',output/'public_inputs'):raise ValueError('Valid finalization proof rejected')
    elapsed=round((time.monotonic()-started)*1000,3)
    tamper={}
    for name in ['raw_commitment','canonical_commitment','canonical_scalars','state_root']:
        index=2+SCALAR_FIELDS.index(name);changed=bytearray(expected);changed[index*32+31]^=1
        altered=output/('changed_'+name);altered.write_bytes(changed);tamper[name+'Rejected']=not verify(output/'proof',altered)
    changed=bytearray((output/'proof').read_bytes());changed[len(changed)//2]^=1
    (output/'changed_proof').write_bytes(changed);tamper['changedProofRejected']=not verify(output/'changed_proof',output/'public_inputs')
    if not all(tamper.values()):raise ValueError('Tampered finalization accepted: '+json.dumps(tamper))
    if digest!=hashlib.sha256(artifact.read_bytes()).hexdigest():raise ValueError('Frozen circuit changed during proving')
    result=dict(kind='huma-text-finalization-proof-v1',case=fixture['case'],capacity=fixture['capacity'],softwareFixturesOnly=True,
        ownerIdentityUsed=False,signaturesVerified=False,completeHumaSessionProof=False,appChanged=False,
        gates=sizing['gates']['functions'][0]['circuit_size'],artifactSha256=digest,sourceSha256=sizing['sourceSha256'],
        keySha256=hashlib.sha256((work/'target/setup/vk').read_bytes()).hexdigest(),setupMs=setup['elapsedMs'],
        witness=witness,proveMs=timing['elapsedMs'],witnessProveVerifyMs=elapsed,
        proofBytes=(output/'proof').stat().st_size,publicInputsBytes=len(expected),tamper=tamper,
        rawSha256=fixture['rawSha256'],canonicalSha256=fixture['canonicalSha256'],threads=2,nice=10)
    cases.write(work/'proof-results.json',result);print(json.dumps(result),flush=True)

if __name__=='__main__':main()
