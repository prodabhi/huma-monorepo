#!/usr/bin/env python3
"""Verify an experimental recursive proof and hostile inner inputs, offline."""
import argparse,copy,hashlib,json,os,subprocess,sys
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks

OFFLINE=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network-outbound)']

def backend():
    # Run inside WorkerBench's exclusive lease/thermal/deadline/process group.
    log=Path(sys.argv[2]);command=sys.argv[3:]
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    log.write_bytes(result.stderr);log.chmod(0o600)
    sys.stdout.write(json.dumps({'exitCode':result.returncode}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('work',type=Path)
    args=parser.parse_args();os.umask(0o077);work=args.work.resolve()
    sizing=json.loads((work/'results.json').read_text())
    if hashlib.sha256((work/'src/main.nr').read_bytes()).hexdigest()!=sizing['sourceSha256']:
        raise ValueError('Frozen recursive source changed')
    if hashlib.sha256((work/'src/bb.nr').read_bytes()).hexdigest()!=sizing['wrapperSha256']:
        raise ValueError('Pinned backend wrapper changed')
    if sizing['children']!=1 or sizing['gates']['functions'][0]['circuit_size']>1_050_000:
        raise ValueError('Only the reviewed single-child component may be proved')
    report_path=work/'proof-results.json'
    if report_path.exists() or (work/'target/setup').exists():raise ValueError('Existing proof/key outputs are never replaced')
    artifact=work/'target/huma_recursive_component.json';artifact_hash=hashlib.sha256(artifact.read_bytes()).hexdigest()
    inputs=json.loads((work/'inputs.json').read_text())
    common=['-b',artifact,'-t','noir-recursive','-c',cases.ROOT/'build/research/noir-crs']
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    def run(command,label):
        result=subprocess.run([str(x) for x in [cases.TOOLS/'worker-bench',*OFFLINE,Path(sys.executable),Path(__file__).resolve(),
            '--backend',work/(label+'-backend.log'),cases.TOOLS/'bb/bb',*command]],
            env=cases.budget.ENV,capture_output=True,timeout=210)
        if result.returncode:raise RuntimeError('Resource-controlled backend did not complete; not evidence of proof rejection')
        return json.loads(result.stdout)
    vk=work/'target/setup/vk'
    setup=run(['write_vk',*common,'-o',vk.parent],'setup')
    if setup['result']['exitCode']!=0:raise RuntimeError('Recursive setup failed; inspect private research log')
    result_cases=[]
    variants=[('Valid',inputs,True)]
    changed=copy.deepcopy(inputs);changed['proofs'][0][200]=str(int(changed['proofs'][0][200])^1)
    variants.append(('BadInnerProof',changed,False))
    changed=copy.deepcopy(inputs);changed['expected'][0][0]=str(int(changed['expected'][0][0])+1)
    variants.append(('BadInnerPublicInput',changed,False))
    for label,values,expected in variants:
        checks.toml(work/(label+'.toml'),values)
        witness,_=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,cases.TOOLS/'noir/nargo','execute',label,'--prover-name',label],work)
        folder=work/'target'/('proof-'+label)
        if folder.exists():raise ValueError('Existing proof directory is never replaced')
        timing=run(['prove',*common,'-w',work/'target'/(label+'.gz'),'-k',vk,'-o',folder],label)
        exit_code=timing['result']['exitCode'];verified=False;verification_exit=None
        if exit_code==0:
            checked=subprocess.run([str(x) for x in [*OFFLINE,cases.TOOLS/'bb/bb','verify','-p',folder/'proof',
                '-i',folder/'public_inputs','-k',vk,'-t','noir-recursive','-c',cases.ROOT/'build/research/noir-crs']],
                env=cases.budget.ENV,capture_output=True,timeout=20)
            verification_exit=checked.returncode
            if verification_exit not in [0,1]:raise RuntimeError('Verifier crashed; negative result is inconclusive')
            verified=verification_exit==0
            raw=(folder/'public_inputs').read_bytes()
            expected_inputs=b''.join(int(n).to_bytes(32,'big') for row in values['expected'] for n in row)
            if raw!=expected_inputs:raise ValueError('Recursive public statement differs from the original child inputs')
        elif expected:
            raise RuntimeError('Valid recursive component failed to prove; inspect research log')
        else:
            # No generic failure/timeout/crash is counted as a successful negative.
            diagnostic=(work/(label+'-backend.log')).read_text(errors='replace')
            if not any(word in diagnostic for word in ['sumcheck verification failed','Sumcheck verification failed','Failed constraint','Assertion failed']):
                raise RuntimeError('Hostile input stopped the backend inconclusively; inspect research log')
        if verified!=expected:raise AssertionError(label+': wrong final cryptographic result')
        case=dict(name=label,witnessAccepted=True,expectedFinalVerified=expected,finalVerified=verified,
            proofGenerated=exit_code==0,backendExit=exit_code,verificationExit=verification_exit,
            witness=witness,proveMs=timing['elapsedMs'])
        result_cases.append(case);print(json.dumps(case),flush=True)
    if hashlib.sha256(artifact.read_bytes()).hexdigest()!=artifact_hash:raise ValueError('Frozen circuit changed')
    report=dict(kind='huma-recursive-component-proof-v1',softwareFixturesOnly=True,ownerIdentityUsed=False,
        completeHumaSessionProof=False,tenThousandCharactersSupported=False,appChanged=False,
        allCasesMatchExpected=True,artifactSha256=artifact_hash,keySha256=hashlib.sha256(vk.read_bytes()).hexdigest(),
        setupMs=setup['elapsedMs'],threads=2,nice=10,cases=result_cases)
    cases.write(report_path,report);print(json.dumps(report),flush=True)

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--backend':backend()
    else:main()
