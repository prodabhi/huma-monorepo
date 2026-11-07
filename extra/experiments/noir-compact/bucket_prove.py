#!/usr/bin/env python3
"""Bounded research proofs of full signed sessions, after policy/boundary checks."""
import argparse,base64,copy,hashlib,json,os,subprocess,time
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks

OFFLINE=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network-outbound)']

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work',type=Path);parser.add_argument('--name',required=True)
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--capture',type=Path)
    source.add_argument('--boundary-case',choices=['FullAscii','FullUnicode','DeleteAllUnicode'])
    args=parser.parse_args();os.umask(0o077);work=args.work.resolve()
    if not args.name.replace('-','').isalnum():raise ValueError('Use a local experiment name')
    target=work/'target';artifact=target/'huma_compact_experiment.json'
    artifact_hash=hashlib.sha256(artifact.read_bytes()).hexdigest()
    sizing=json.loads((work/'results.json').read_text());limits=sizing['limits']
    if sizing['gates']['functions'][0]['circuit_size']>524288:raise ValueError('Candidate exceeds the half-size research budget')
    if hashlib.sha256(json.loads(artifact.read_text())['bytecode'].encode()).hexdigest()!=sizing['bytecodeSha256']:
        raise ValueError('Frozen circuit changed')
    for report_name,count in [('constraint-results.json',21),('boundary-results.json',5)]:
        report=json.loads((work/report_name).read_text())
        if report['artifactSha256']!=artifact_hash or len(report['cases'])!=count or any(c['accepted']!=c['expectedAccepted'] for c in report['cases']):
            raise ValueError('Complete policy and boundary checks are required before setup')
    output=target/('proof-'+args.name);result_path=work/('proof-results-'+args.name+'.json')
    if output.exists() or result_path.exists():raise ValueError('Existing proof output is never replaced')
    start=time.monotonic()
    if args.capture:
        allowed={cases.ROOT/'build/research/noir-assurance-native'/name/'document.huma'
            for name in ['live-v4-short-v2','live-cp32-boundary-v1']}
        if args.capture.resolve() not in allowed:raise ValueError('Only the two known disposable research captures are allowed')
        doc=json.loads(args.capture.read_bytes());session=doc['session'].copy()
        snapshot=json.loads(base64.b64decode(session.pop('experimentalCompactSnapshot')))
        request=json.dumps(dict(witness=dict(text=doc['text'],session=session),snapshot=snapshot)).encode()
        validated=subprocess.run([str(cases.NATIVE),'profile-fit'],input=request,capture_output=True,timeout=20)
        if validated.returncode:raise ValueError('Original complete signed input failed validation')
        candidate=next(c for c in json.loads(validated.stdout)['candidates'] if c['name']==sizing['bucket'])
        if not candidate['eligible'] or candidate['limits']!=limits:raise ValueError('Whole original capture does not fit this exact circuit')
        private=snapshot['result']['private'];capsule=snapshot['result']['capsule'];text=doc['text']
    else:
        fixture=next(c for c in json.loads((work/'boundary-fixtures.json').read_text()) if c['name']==args.boundary_case)
        private=fixture['private'];capsule=fixture['capsule'];text=fixture['text']
    values=cases.inputs(private,capsule,limits)
    if cases.project(copy.deepcopy(values['expected']))!=capsule['journal']:raise ValueError('Original signed journal changed')
    validation_ms=round((time.monotonic()-start)*1000,3)
    checks.toml(work/(args.name+'.toml'),values)
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    common=['-b',artifact,'-t','noir-recursive','-c',cases.ROOT/'build/research/noir-crs']
    def worker(command):
        result=subprocess.run([str(x) for x in [cases.TOOLS/'worker-bench',*OFFLINE,cases.TOOLS/'bb/bb',*command]],
            env=cases.budget.ENV,cwd=work,capture_output=True,timeout=210)
        if result.returncode:raise RuntimeError(result.stderr.decode()[-1500:])
        return json.loads(result.stdout)
    vk=target/'setup/vk';setup=None
    if not vk.exists():setup=worker(['write_vk',*common,'-o',vk.parent])
    before=time.monotonic()
    witness,_=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,cases.TOOLS/'noir/nargo','execute',args.name,'--prover-name',args.name],work)
    timing=worker(['prove',*common,'-w',target/(args.name+'.gz'),'-k',vk,'-o',output])
    before_verify=time.monotonic()
    key_hash=hashlib.sha256(bytes(capsule['public_key'])).hexdigest()
    verified=cases.verify(work,output,capsule,text,key_hash,tool_prefix=OFFLINE)
    stop=time.monotonic()
    if artifact_hash!=hashlib.sha256(artifact.read_bytes()).hexdigest():raise ValueError('Circuit changed during proof generation')
    report=dict(softwareFixtureOnly=True,ownerIdentityUsed=False,registeredForProving=False,proofGenerated=True,
        nativeZkAndAllSignaturesVerified=verified['verified'],fullSignedJournalPreserved=True,limits=limits,
        textScalars=len(text),textBytes=len(text.encode()),operations=len(private['replay']['words']),
        checkpointSignatures=len(capsule['signatures']),presenceSignatures=len(capsule['presence_signatures']),
        validationMs=validation_ms,warmWitness=witness,proveMs=timing['elapsedMs'],
        verifyMs=round((stop-before_verify)*1000,3),contiguousWitnessProveVerifyMs=round((stop-before)*1000,3),
        setupPerformed=setup is not None,setupExcludedFromProofTiming=True,threads=2,nice=10,
        artifactSha256=artifact_hash,programKeyHash=hashlib.sha256(vk.read_bytes()).hexdigest(),
        proofBytes=(output/'proof').stat().st_size,publicInputsBytes=(output/'public_inputs').stat().st_size,
        attestationVerified=False,trustedTime=False,appServiceMeasured=False)
    cases.write(result_path,report);print(json.dumps(report),flush=True)

if __name__=='__main__':main()
