#!/usr/bin/env python3
"""Measure complete-policy circuit optimizations with original signed captures."""
import argparse,base64,hashlib,json,os,subprocess,time
from pathlib import Path
import assurance_cases as v4
import limb_replay
import bounded_replay
import algebraic_replay

ROOT=v4.ROOT;HERE=v4.HERE;TOOLS=v4.TOOLS
OFFLINE=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network-outbound)']
def circuit(public_text=True,limbs=False,bounded=False,algebraic=False):
    source=(HERE/'candidates/assurance-v4.nr').read_text()
    def once(old,new):
        nonlocal source
        if source.count(old)!=1:raise ValueError('V4 source changed; review the complete transformation')
        source=source.replace(old,new)
    if public_text:
        once('mod assurance;','mod assurance;\nmod public_text;')
        once('fn time(previous:Field,delta:u64)->Field',
            'struct PublicJournal {capture:Journal,text_commitment:Field}\n\nfn time(previous:Field,delta:u64)->Field')
        once('expected:pub Journal)','expected:pub PublicJournal)')
        source=source.replace('expected.','expected.capture.')
        once('let text_hash=Bytes {data:text.data,len:canonical_len}.hash();',
            '// SHA-256 is checked by the complete reader against the same public text.\n'
            '    let text_hash=expected.capture.replay.text_hash;\n'
            '    assert(expected.text_commitment==public_text::commitment(text.data,canonical_len));')
        once('assert(expected.capture.replay.text_hash==text_hash);','')
    for name,old in dict(OPS=256,SCALARS=64,BYTES=128,CPS=2,SAMPLES=80,PRES=2).items():
        once(f'global {name}:u32={old};',f'global {name}:u32={v4.PROFILES["cast256"][name]};')
    if limbs:source=limb_replay.optimize(source)
    if algebraic:return algebraic_replay.optimize(source)
    return bounded_replay.optimize(source) if bounded else source

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--name',required=True);p.add_argument('--prove',action='store_true')
    p.add_argument('--capture',type=Path,default=ROOT/'build/research/noir-assurance-native/live-v4-250-v2/document.huma')
    p.add_argument('--relation',choices=['public-text','limbs','limbs-public-text','bounded','bounded-public-text','algebraic','algebraic-public-text'],default='public-text')
    a=p.parse_args();os.umask(0o077)
    if a.prove and a.relation!='algebraic':raise ValueError('Only the tested algebraic relation is eligible for proving; other candidates are sizing experiments')
    if not a.name.replace('-','').isalnum():raise ValueError('Use a local experiment name')
    work=ROOT/'build/research/noir-publictext'/a.name
    doc=json.loads(a.capture.read_text());session=doc['session'];snapshot=json.loads(base64.b64decode(session.pop('experimentalCompactSnapshot')))
    raw=json.dumps(dict(witness=dict(text=doc['text'],session=session),snapshot=snapshot)).encode()
    public_text='public-text' in a.relation;limbs=a.relation.startswith('limbs');bounded=a.relation.startswith('bounded');algebraic=a.relation.startswith('algebraic')
    prepared=subprocess.run([str(v4.NATIVE),'assurance-publictext-input' if public_text else 'assurance-worker-input'],input=raw,capture_output=True,timeout=20)
    if prepared.returncode:raise ValueError('Original signed capture did not validate')
    prepared=json.loads(prepared.stdout);inputs=prepared['inputs'];capsule=snapshot['result']['capsule']
    if limbs:limb_replay.inputs(inputs)
    sources={'main.nr':circuit(public_text,limbs,bounded,algebraic),'public_text.nr':(HERE/'src/public_text.nr').read_text(),
        'bytes.nr':(ROOT/'extra/experiments/noir-replay/src/bytes.nr').read_text(),
        'commit.nr':(HERE/'src/commit.nr').read_text(),'assurance.nr':(HERE/'src/assurance.nr').read_text()}
    (work/'src').mkdir(parents=True,exist_ok=True)
    for name,body in sources.items():
        path=work/'src'/name
        if (work/'target/setup/vk').exists() and path.read_text()!=body:raise ValueError('Use a new name for circuit changes')
        path.write_text(body)
    (work/'Nargo.toml').write_text((HERE/'Nargo.toml').read_text().replace('../../../build/research/noir-sha256',str(ROOT/'build/research/noir-sha256')))
    input_hash=hashlib.sha256(raw).hexdigest()
    if (work/'input-hash.txt').exists() and (work/'input-hash.txt').read_text()!=input_hash:raise ValueError('Use a new name for another recording')
    (work/'input-hash.txt').write_text(input_hash)
    v4.write(work/'inputs.json',inputs);v4.write(work/'capsule.json',capsule);v4.write(work/'prepared.json',prepared)
    (work/'Prover.toml').write_text('\n'.join(k+' = '+v4.fixture.toml(v) for k,v in inputs.items())+'\n')
    v4.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    witness,_=v4.budget.limited(['/usr/bin/nice','-n','10',TOOLS/'noir/nargo','execute'],work)
    _,gates_raw=v4.budget.limited(['/usr/bin/nice','-n','10',TOOLS/'bb/bb','gates','-b',work/'target/huma_compact_experiment.json','-t','noir-recursive'],work)
    gates=json.loads(gates_raw)
    artifact=work/'target/huma_compact_experiment.json';program=json.loads(artifact.read_text())
    public=[x for x in program['abi']['parameters'] if x['visibility']=='public']
    if len(public)!=1 or public[0]['name']!='expected':raise ValueError('Unexpected public ABI')
    abi=public[0]['type'];old=json.loads((HERE/'browser/assets/assurance-abi.json').read_text())
    expected_abi=dict(kind='struct',path='PublicJournal',fields=[dict(name='capture',type=old),dict(name='text_commitment',type=dict(kind='field'))]) if public_text else old
    if abi!=expected_abi:raise ValueError('V4 public journal changed')
    (work/'reader-abi.json').write_text(json.dumps(abi,separators=(',',':')))
    report=dict(softwareFixtureOnly=True,experimental=True,relation=a.relation,completePublicTextVerifierRequired=public_text,proofGenerated=False,
        signaturesPreserved=True,checkpointSignatures=len(capsule['signatures']),presenceSignatures=len(capsule['presence_signatures']),
        gates=gates,compileAndWitness=witness,bytecodeSha256=hashlib.sha256(program['bytecode'].encode()).hexdigest(),
        sourceSha256={name:hashlib.sha256(body.encode()).hexdigest() for name,body in sources.items()})
    if a.prove:
        if gates['functions'][0]['circuit_size']>1_050_000:raise ValueError('Candidate exceeds reviewed V4 gate budget')
        common=['-b',artifact,'-t','noir-recursive','-c',ROOT/'build/research/noir-crs']
        def worker(args):
            result=subprocess.run([str(x) for x in [TOOLS/'worker-bench',*OFFLINE,TOOLS/'bb/bb',*args]],env=v4.budget.ENV,capture_output=True,timeout=210)
            if result.returncode:raise RuntimeError('Bounded native prover did not complete')
            return json.loads(result.stdout)
        vk=work/'target/setup/vk'
        if not vk.exists():worker(['write_vk',*common,'-o',vk.parent])
        proof=work/'target/proof-2-threads'
        if proof.exists():raise ValueError('Existing proof was not replaced')
        warm,_=v4.budget.limited(['/usr/bin/nice','-n','10',TOOLS/'noir/nargo','execute'],work)
        timing=worker(['prove',*common,'-w',work/'target/huma_compact_experiment.gz','-k',vk,'-o',proof])
        raw_inputs=(proof/'public_inputs').read_bytes()
        if raw_inputs.hex()!=prepared['publicInputsHex']:raise ValueError('Public proof differs from the complete original capture')
        checked=subprocess.run([str(x) for x in [TOOLS/'bb/bb','verify','-p',proof/'proof','-i',proof/'public_inputs','-k',vk,'-t','noir-recursive']],env=v4.budget.ENV,capture_output=True,timeout=20)
        if checked.returncode:raise ValueError('Native ZK verification failed')
        identity=hashlib.sha256(b'HUMA_COMPACT_ASSURANCE_ID_V5\0'+bytes.fromhex(hashlib.sha256(vk.read_bytes()).hexdigest())+raw_inputs+bytes(capsule['public_key'])).hexdigest()
        public=dict(kind='huma-compact-assurance-public-proof-v5',profile='assurance256-publictext-v1' if public_text else 'assurance256-v2',
            proof=base64.b64encode((proof/'proof').read_bytes()).decode(),publicInputs=base64.b64encode(raw_inputs).decode(),
            publicKey=base64.b64encode(bytes(capsule['public_key'])).decode(),
            signatures=[base64.b64encode(bytes(s)).decode() for s in capsule['signatures']],
            presenceSignatures=[base64.b64encode(bytes(s)).decode() for s in capsule['presence_signatures']],text=doc['text'])
        v4.write(work/'public.json',public)
        report.update(proofGenerated=True,nativeZkVerified=True,proveMs=timing['elapsedMs'],warmWitness=warm,
            programKeyHash=hashlib.sha256(vk.read_bytes()).hexdigest(),proofIdentity=identity)
    v4.write(work/'results.json',report);print(json.dumps(report),flush=True)
if __name__=='__main__':main()
