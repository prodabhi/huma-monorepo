#!/usr/bin/env python3
"""Bounded proofs of combined continuation chunks; not a Huma session format."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks
from continuation_cases import OFFLINE

def linked(boundaries):
    return bool(boundaries) and boundaries[0]['start_offset']==0 and all(
        b['end_offset']>b['start_offset'] and b['final_step']==(i+1==len(boundaries)) and (i==0 or (
            boundaries[i-1]['end_root']==b['start_root'] and boundaries[i-1]['end_offset']==b['start_offset']
            and boundaries[i-1]['nonce']==b['nonce'])) for i,b in enumerate(boundaries))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('work',type=Path)
    args=parser.parse_args();os.umask(0o077);work=args.work.resolve()
    if work.parent!=cases.ROOT/'build/research/noir-interaction' or 'unsafe' in work.name:raise ValueError('Use a reviewed interaction component')
    sizing=json.loads((work/'results.json').read_text());fixture=json.loads((work/'reference.json').read_text())
    constraints=json.loads((work/'constraint-results.json').read_text());artifact=work/'target/huma_continuation_component.json'
    digest=hashlib.sha256(artifact.read_bytes()).hexdigest()
    if sizing['case'] not in ['revision','typing10000','rollover']:raise ValueError('Only the reviewed three benchmark cases may be proved')
    if sizing['gates']['functions'][0]['circuit_size']>524288:raise ValueError('Combined component exceeds its half-size research budget')
    if hashlib.sha256((work/'src/main.nr').read_bytes()).hexdigest()!=sizing['sourceSha256']:raise ValueError('Circuit source changed')
    for name,d in sizing['dependencySha256'].items():
        if hashlib.sha256((work/'src'/name).read_bytes()).hexdigest()!=d:raise ValueError('Circuit dependency changed')
    required={'RejectForgedRule'+str(n) for n in range(9)}|{'Reject'+n for n in [
        'ForgedGenesisHeldKey','ForgedGenesisPause','ForgedGenesisOriginHead','ChangedHeldKey','ChangedRateWindow',
        'ChangedAnomalies','ChangedCaptureRoot','ChangedOriginRoot','ChangedRepeat','ForgedPolicyResult']}
    if constraints['artifactSha256']!=digest or not required.issubset({r['case'] for r in constraints['cases']}) or any(
        r['accepted']!=r['expectedAccepted'] for r in constraints['cases']):raise ValueError('Required constraint checks are missing')
    if sum(r['accepted'] for r in constraints['cases'])!=len(fixture['selected']):raise ValueError('All selected boundaries must be checked')
    if (work/'proof-results.json').exists() or (work/'target/setup').exists():raise ValueError('Existing key/proof outputs are immutable')
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    common=['-b',artifact,'-t','noir-recursive','-c',cases.ROOT/'build/research/noir-crs']
    def worker(command):
        result=subprocess.run([str(x) for x in [cases.TOOLS/'worker-bench',*OFFLINE,cases.TOOLS/'bb/bb',*command]],
            env=cases.budget.ENV,capture_output=True,timeout=210)
        if result.returncode:raise RuntimeError('Resource-controlled backend did not complete: '+result.stderr.decode()[-1000:])
        return json.loads(result.stdout)
    def verify(proof,inputs):
        result=subprocess.run([str(x) for x in [*OFFLINE,cases.TOOLS/'bb/bb','verify','-p',proof,'-i',inputs,
            '-k',work/'target/setup/vk','-t','noir-recursive','-c',cases.ROOT/'build/research/noir-crs']],
            env=cases.budget.ENV,capture_output=True,timeout=20)
        if result.returncode not in [0,1]:raise RuntimeError('Verifier returned an inconclusive result')
        return result.returncode==0
    setup=worker(['write_vk',*common,'-o',work/'target/setup']);reports=[];all_checks_started=time.monotonic()
    for row in fixture['selected']:
        label='Chunk'+str(row['index']);values={k:v for k,v in row.items() if k!='index'}
        checks.toml(work/(label+'.toml'),values);started=time.monotonic()
        witness,_=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,cases.TOOLS/'noir/nargo','execute',label,'--prover-name',label],work)
        output=work/'target'/('proof-'+label)
        if output.exists():raise ValueError('Existing proof directory is immutable')
        timing=worker(['prove',*common,'-w',work/'target'/(label+'.gz'),'-k',work/'target/setup/vk','-o',output])
        b=row['expected'];public=b['nonce']+[b[k] for k in ['start_root','end_root','start_offset','end_offset','capture_root','final_step','origin_root']]
        public+=b['rules']+[b[k] for k in ['policy_satisfied','origin_present','origin_hid']]
        expected=b''.join(int(n).to_bytes(32,'big') for n in public)
        if (output/'public_inputs').read_bytes()!=expected:raise ValueError('Proof exposes a different combined boundary')
        if not verify(output/'proof',output/'public_inputs'):raise ValueError('Valid combined proof rejected')
        elapsed=round((time.monotonic()-started)*1000,3)
        for name,index in [('capture',6),('origin',8),('policy',18)]:
            changed=bytearray(expected);changed[index*32+31]^=1
            altered=output/('changed_'+name+'_inputs');altered.write_bytes(changed)
            if verify(output/'proof',altered):raise ValueError('Changed '+name+' statement accepted')
        changed=bytearray((output/'proof').read_bytes());changed[len(changed)//2]^=1
        altered=output/'changed_proof';altered.write_bytes(changed)
        if verify(altered,output/'public_inputs'):raise ValueError('Changed proof accepted')
        report=dict(index=row['index'],boundary=b,nativeVerified=True,changedCapturePrefixRejected=True,
            changedOriginRootRejected=True,changedPolicyRejected=True,changedProofRejected=True,
            witness=witness,proveMs=timing['elapsedMs'],witnessProveVerifyMs=elapsed,
            proofBytes=(output/'proof').stat().st_size,publicInputsBytes=len(expected),
            proofSha256=hashlib.sha256((output/'proof').read_bytes()).hexdigest(),publicInputsSha256=hashlib.sha256(expected).hexdigest())
        reports.append(report);print(json.dumps(report),flush=True)
    if digest!=hashlib.sha256(artifact.read_bytes()).hexdigest():raise ValueError('Frozen circuit changed during proving')
    full=len(reports)==fixture['chunks'];link_checks={}
    if full:
        import copy
        boundaries=[r['boundary'] for r in reports];assert linked(boundaries)
        if len(boundaries)>2:
            dropped=copy.deepcopy(boundaries);dropped.pop(1);link_checks['droppedChunkRejected']=not linked(dropped)
            reordered=copy.deepcopy(boundaries);reordered[1],reordered[2]=reordered[2],reordered[1]
            link_checks['reorderedChunksRejected']=not linked(reordered)
            reset=copy.deepcopy(boundaries);reset[1]['start_root']='1';link_checks['resetStateRejected']=not linked(reset)
            reset=copy.deepcopy(boundaries);reset[1]['nonce'][0]='2';link_checks['changedSessionRejected']=not linked(reset)
            assert all(link_checks.values())
    result=dict(kind='huma-interaction-continuation-proof-v1',case=fixture['case'],softwareFixturesOnly=True,ownerIdentityUsed=False,
        replayBehaviorAndOriginsBoundTogether=True,signaturesVerified=False,completeHumaSessionProof=False,
        completeTenThousandCharacterSessionVerified=False,appChanged=False,allReplayChunksProved=full,
        nativeChunks=fixture['chunks'],selectedChunksProved=len(reports),linkChecks=link_checks,artifactSha256=digest,
        sourceSha256=sizing['sourceSha256'],keySha256=hashlib.sha256((work/'target/setup/vk').read_bytes()).hexdigest(),
        setupMs=setup['elapsedMs'],setupExcludedFromChunkTiming=True,
        validPathSumMs=round(sum(r['witnessProveVerifyMs'] for r in reports),3),
        researchAllChecksWallMs=round((time.monotonic()-all_checks_started)*1000,3),
        appServiceMeasured=False,threads=2,nice=10,cases=reports)
    cases.write(work/'proof-results.json',result);print(json.dumps(result),flush=True)

if __name__=='__main__':main()
