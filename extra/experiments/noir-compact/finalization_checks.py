#!/usr/bin/env python3
"""Terminal-state text finalization: valid witness, altered statements and empty-text controls."""
import argparse,copy,hashlib,json,os
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks
import finalization_cases as finalization

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('work',type=Path)
    args=parser.parse_args();os.umask(0o077)
    work=args.work.resolve();artifact=work/'target/huma_text_finalization.json'
    if work.parent!=cases.ROOT/'build/research/noir-finalization':raise ValueError('Use an isolated finalization build')
    digest=hashlib.sha256(artifact.read_bytes()).hexdigest();fixture=json.loads((work/'reference.json').read_text())
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    original=fixture['inputs'];reports=[checks.execute(work,'ValidFinal',original,True)];variants=[]
    def variant(label,change,base=original):
        value=copy.deepcopy(base);change(value)
        if value==base:raise ValueError(label+': mutation did not change the input')
        variants.append((label,value))
    e='expected'
    for field in ['raw_commitment','canonical_commitment','state_root','capture_root','origin_root']:
        variant('Changed'+field.title().replace('_',''),lambda v,k=field:v[e].update({k:str((int(v[e][k])+1)%2**253)}))
    for field in ['raw_scalars','canonical_scalars','raw_bytes','canonical_bytes','op_count','origin_present','origin_hid']:
        variant('Changed'+field.title().replace('_',''),lambda v,k=field:v[e].update({k:v[e][k]+1}))
    # The policy keeps trailing ASCII space/tab out of the canonical text; claiming them back must fail.
    variant('CanonicalClaimsRawLength',lambda v:v[e].update(canonical_scalars=v[e]['raw_scalars'],canonical_bytes=v[e]['raw_bytes'],
        canonical_commitment=v[e]['raw_commitment']) if v[e]['raw_scalars']!=v[e]['canonical_scalars'] else v[e].update(canonical_scalars=v[e]['canonical_scalars']-1))
    variant('SwappedCommitments',lambda v:v[e].update(raw_commitment=v[e]['canonical_commitment'],canonical_commitment=v[e]['raw_commitment'])
        if v[e]['raw_commitment']!=v[e]['canonical_commitment'] else v[e].update(raw_commitment='1'))
    variant('ChangedSessionNonce',lambda v:v[e]['nonce'].__setitem__(0,'2'))
    for i in range(9):variant('ForgedRule'+str(i),lambda v,i=i:v[e]['rules'].__setitem__(i,not v[e]['rules'][i]))
    variant('ForgedPolicyResult',lambda v:v[e].update(policy_satisfied=not v[e]['policy_satisfied']))
    variant('ChangedPrivateText',lambda v:v['state']['buffer'].__setitem__(0,v['state']['buffer'][0]^1))
    variant('ChangedSalt',lambda v:v['salt'].__setitem__(0,str(int(v['salt'][0])^1)))
    variant('ZeroSalt',lambda v:v.update(salt=['0','0']))
    variant('ChangedCursor',lambda v:v['state'].update(cursor=v['state']['cursor']+1 if v['state']['cursor']<v['state']['total'] else v['state']['cursor']-1))
    variant('NotTerminalOps',lambda v:v['state'].update(remaining=1))
    for label,value in variants:reports.append(checks.execute(work,'Reject'+label,value,False))
    # Empty canonical text is never provable: whitespace-only and empty drafts at the same capacity.
    controls=[]
    for case in ['master-spaces','master-empty']:
        other=finalization.native(case)
        if other['capacity']!=fixture['capacity'] or other['chunkOperations']!=fixture['chunkOperations']:continue
        if other['expectedAccepted']:raise ValueError(case+' should be a negative witness')
        controls.append(checks.execute(work,'RejectEmpty'+case.split('-')[1].title(),other['inputs'],False))
    if fixture['capacity']==64 and len(controls)!=2:raise ValueError('Empty-text controls were not exercised')
    if digest!=hashlib.sha256(artifact.read_bytes()).hexdigest():raise ValueError('Frozen circuit changed during checks')
    result=dict(kind='huma-text-finalization-constraints-v1',case=fixture['case'],artifactSha256=digest,
        cases=reports,emptyTextControls=controls,appChanged=False,ownerIdentityUsed=False)
    cases.write(work/'constraint-results.json',result);print(json.dumps(result),flush=True)

if __name__=='__main__':main()
