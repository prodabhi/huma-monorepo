#!/usr/bin/env python3
"""Bounded media membership prototype. Not physical-policy or decoder ZK."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import protocol

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'extra/experiments/noir-replay'))
import fixture as toml_fixture
import size
sys.path.insert(0,str(ROOT/'extra/experiments/noir-compact'))
from verify import decode
TOOLS=ROOT/'build/research/noir-tools'

def write(path,value):
    path.write_text(value);path.chmod(0o600)
def command(args,cwd=None):
    p=subprocess.run([str(x) for x in args],cwd=cwd,text=True,capture_output=True,timeout=60)
    if p.returncode:raise RuntimeError(p.stderr[-1800:])
    return p.stdout
def prepare_media(work):
    media=work/'media';media.mkdir(exist_ok=True)
    image=media/'image.png';audio=media/'audio.flac';video=media/'video.mp4'
    ppm=media/'image.ppm'
    if not image.exists():
        pixels=b''.join(struct.pack('>HHH',x*2114,y*2114,(x+y)*1057) for y in range(32) for x in range(32))
        ppm.write_bytes(b'P6\n32 32\n65535\n'+pixels)
        command(['ffmpeg','-v','error','-y','-threads','2','-i',ppm,'-frames:v','1','-c:v','png','-pix_fmt','rgb48be',image])
    if not audio.exists():
        command(['ffmpeg','-v','error','-y','-f','lavfi','-i','sine=frequency=431:sample_rate=48000:duration=0.2',
            '-threads','2','-c:a','flac','-sample_fmt','s32','-bits_per_raw_sample','24',audio])
    if not video.exists():
        command(['ffmpeg','-v','error','-y','-f','lavfi','-i','testsrc2=size=64x64:rate=30:duration=0.2',
            '-threads','2','-c:v','libsvtav1','-pix_fmt','yuv420p10le','-preset','12','-crf','18','-g','30',
            '-svtav1-params','lp=2:film-grain=0',video])
    outputs=[]
    for kind,path,options,layout in [
        (1,image,['-f','rawvideo','-pix_fmt','rgb48le'],dict(codec='png',bitDepth=16,width=32,height=32,format='rgb48le',fallback=True)),
        (2,audio,['-f','s24le','-acodec','pcm_s24le'],dict(codec='flac',bitDepth=24,sampleRate=48000,channels=1,format='s24le')),
        (3,video,['-f','rawvideo','-pix_fmt','yuv420p10le'],dict(codec='av1',bitDepth=10,width=64,height=64,fps=30,format='yuv420p10le',filmGrain=False)),
    ]:
        decoded=media/(path.stem+'.raw')
        if not decoded.exists():command(['ffmpeg','-v','error','-y','-threads','2','-i',path,*options,decoded])
        raw=decoded.read_bytes();leaves=[raw[i:i+protocol.LEAF_BYTES] for i in range(0,len(raw),protocol.LEAF_BYTES)]
        layout_bytes=json.dumps(layout,sort_keys=True,separators=(',',':')).encode()
        values=protocol.fixture(kind,path.read_bytes(),leaves,layout_bytes,
            protocol.digest(b'PUBLIC-MEDIA-NONCE'+bytes([kind])),protocol.digest(b'PUBLIC-LOCAL-CHALLENGE'+bytes([kind])))
        outputs.append((path.stem,path,layout,values))
    return outputs

def verify_case(work,proof_dir,capsule,expected_master=None,expected_key=None,expected_challenge=None):
    if set(capsule)!=set(['kind','journal','publicKey','signature']) or capsule['kind']!='huma-media-membership-experiment-v1':raise ValueError('Unsupported capsule')
    artifact=work/'target/huma_media_membership.json'
    abi=json.loads(artifact.read_text())['abi'];public=[p for p in abi['parameters'] if p['visibility']=='public']
    if len(public)!=1 or public[0]['name']!='expected':raise ValueError('Unexpected public schema')
    raw=(proof_dir/'public_inputs').read_bytes()
    if len(raw)%32 or len(raw)>32768:raise ValueError('Invalid public input size')
    values=iter(int.from_bytes(raw[i:i+32],'big') for i in range(0,len(raw),32))
    journal=decode(public[0]['type'],values)
    if next(values,None) is not None or journal!=capsule['journal']:raise ValueError('Capsule differs from proven journal')
    command([TOOLS/'bb/bb','verify','-p',proof_dir/'proof','-i',proof_dir/'public_inputs','-k',work/'target/setup/vk',
        '-t','noir-recursive','-c',ROOT/'build/research/noir-crs'])
    cp=work/(str(journal['kind'])+'-verify-capsule.json');write(cp,json.dumps(capsule))
    checked=json.loads(command(['node',HERE/'verify-signature.mjs',cp]))
    if expected_key is not None and checked['keyHash']!=expected_key:raise ValueError('Unexpected signing key')
    if expected_challenge is not None and bytes(journal['challenge'])!=expected_challenge:raise ValueError('Unexpected sampling challenge')
    if expected_master is not None:
        if expected_master.stat().st_size!=journal['encoded_length']:raise ValueError('Master length differs')
        h=hashlib.sha256()
        with expected_master.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
        if list(h.digest())!=journal['encoded_hash']:raise ValueError('Master differs from signed commitment')
    return dict(verified=True,allSignaturesVerified=True,keyHash=checked['keyHash'],kind=journal['kind'],
        sealHash=bytes(journal['sealed_root']).hex(),decodingProven=False,scenePolicyChecked=False,
        manufacturerAttestation=False,masterCompared=expected_master is not None,
        samplingFreshness='local-unattested-fixture',expectedChallengeMatched=expected_challenge is not None)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',default='membership-v1')
    parser.add_argument('--prove',action='store_true')
    parser.add_argument('--threads',type=int,choices=[2,8],default=2)
    a=parser.parse_args()
    if not a.name.replace('-','').isalnum():parser.error('Use an alphanumeric experiment name')
    work=ROOT/'build/research/noir-media'/a.name;(work/'src').mkdir(parents=True,exist_ok=True)
    if '1.0.0-beta.25' not in command([TOOLS/'noir/nargo','--version']) or command([TOOLS/'bb/bb','--version']).strip()!='5.2.1':parser.error('Pinned tools required')
    source=(HERE/'src/main.nr').read_text()
    if (work/'target/setup/vk').exists() and (work/'src/main.nr').read_text()!=source:raise RuntimeError('Use a new name for changed circuits')
    write(work/'src/main.nr',source)
    write(work/'Nargo.toml','[package]\nname="huma_media_membership"\ntype="bin"\nauthors=[]\n[dependencies]\n'+f'sha256={{path="{ROOT}/build/research/noir-sha256"}}\n')
    signer=work/'fixture-signer'
    if not signer.exists():command(['swiftc',HERE/'sign.swift','-o',signer])
    cases=prepare_media(work)
    size.ENV.update(HARDWARE_CONCURRENCY=str(a.threads),RAYON_NUM_THREADS='2')
    artifact=work/'target/huma_media_membership.json';results=[]
    for name,path,layout,values in cases:
        capsule_path=work/(name+'-capsule.json')
        if capsule_path.exists():
            capsule=json.loads(capsule_path.read_text())
            if capsule['journal']!=values['expected']:raise RuntimeError('Frozen media fixture changed')
        else:
            signed=subprocess.run([str(signer)],input=bytes(values['expected']['sealed_root']),capture_output=True,timeout=15)
            if signed.returncode:raise RuntimeError('Software fixture signing failed')
            capsule=dict(kind='huma-media-membership-experiment-v1',journal=values['expected'],**json.loads(signed.stdout))
            write(capsule_path,json.dumps(capsule))
        write(work/(name+'.toml'),'\n'.join(k+' = '+toml_fixture.toml(v) for k,v in values.items())+'\n')
        start=time.monotonic()
        compile_stats,_=size.limited(['/usr/bin/nice','-n','10',TOOLS/'noir/nargo','execute',name,'--prover-name',name],work)
        gate_stats,out=size.limited(['/usr/bin/nice','-n','10',TOOLS/'bb/bb','gates','-b',artifact,'-t','noir-recursive'],work)
        gates=json.loads(out)['functions'][0]['circuit_size']
        result=dict(case=name,experimental=True,softwareKeysOnly=True,proofGenerated=False,gates=gates,
            compileAndWitness=compile_stats,encodedBytes=path.stat().st_size,leafCount=values['expected']['leaf_count'],
            decodedBytes=values['expected']['decoded_length'],sampleCount=protocol.SAMPLES,leafCapacity=protocol.LEAF_BYTES,
            treeDepth=protocol.DEPTH,layout=layout,threads=a.threads)
        if a.prove:
            if gates>2100000:raise RuntimeError('Proof exceeds reviewed gate budget')
            common=['-b',artifact,'-t','noir-recursive','-c',ROOT/'build/research/noir-crs']
            env=dict(os.environ,HARDWARE_CONCURRENCY=str(a.threads),RAYON_NUM_THREADS='2')
            def worker(args):
                p=subprocess.run([str(x) for x in [TOOLS/'worker-bench',TOOLS/'bb/bb',*args]],env=env,cwd=work,text=True,capture_output=True,timeout=195)
                if p.returncode:raise RuntimeError(p.stderr[-1500:])
                return json.loads(p.stdout)
            if not (work/'target/setup/vk').exists():worker(['write_vk',*common,'-o',work/'target/setup'])
            outdir=work/'target'/('proof-'+name+'-'+str(a.threads))
            timing=worker(['prove',*common,'-w',work/'target'/(name+'.gz'),'-k',work/'target/setup/vk','-o',outdir])
            before=time.monotonic();checked=verify_case(work,outdir,capsule,expected_master=path)
            public=dict(kind='huma-media-public-proof-v1',profile='media-membership-v1',
                proof=base64.b64encode((outdir/'proof').read_bytes()).decode(),
                publicInputs=base64.b64encode((outdir/'public_inputs').read_bytes()).decode(),
                publicKey=capsule['publicKey'],signature=capsule['signature'])
            write(work/(name+'-public.json'),json.dumps(public,separators=(',',':'))+'\n')
            result.update(proofGenerated=True,verification=checked,proveMs=timing['elapsedMs'],verifyMs=round((time.monotonic()-before)*1000,2),
                vkSha256=hashlib.sha256((work/'target/setup/vk').read_bytes()).hexdigest())
        result['contiguousMs']=round((time.monotonic()-start)*1000,2)
        results.append(result);write(work/'results.json',json.dumps(results,indent=2)+'\n');print(json.dumps(result),flush=True)
