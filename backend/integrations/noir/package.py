#!/usr/bin/env python3
"""Stage the pinned, offline Mac Noir worker; never launch or authenticate."""
import hashlib,json,os,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
BUILD=ROOT/'build/research'
PROGRAM=BUILD/'noir-assurance/assurance-typed250-v1/target/huma_compact_experiment.json'
BYTECODE='15d6b3c7d5db15310f56452b0d5808444daf166c6a610daffdd7ddf682c8b1c5'
CRS_POINTS=1<<21
CRS_SHA256='3e1ac09652ee9df779a4955fb8f7050620c7b1ee7f18566581bd00326b06be37'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def manifest(destination):
    values={str(p.relative_to(destination)):digest(p) for p in destination.rglob('*') if p.is_file() and p.name!='manifest.json'}
    (destination/'manifest.json').write_text(json.dumps(values,indent=2)+'\n')
def main():
    if len(sys.argv)==3 and sys.argv[1]=='--refresh-manifest':
        manifest(Path(sys.argv[2]).resolve());return
    destination=Path(sys.argv[1]).resolve()
    if destination.exists():raise SystemExit('Use a new or empty staging destination')
    program=json.loads(PROGRAM.read_text());assert hashlib.sha256(program['bytecode'].encode()).hexdigest()==BYTECODE
    program5=json.loads((BUILD/'noir-publictext/algebraic-v1/target/huma_compact_experiment.json').read_text())
    assert hashlib.sha256(program5['bytecode'].encode()).hexdigest()=='64c7bee1b03e1538c1f86784afe1bc108df3cf603ea8628bf0e436bd197ca1c3'
    assert program5['abi']['parameters']==program['abi']['parameters'],'Optimized input/public ABI changed'
    program32=json.loads((BUILD/'noir-capacity/cp32-pres8-v1/target/huma_compact_experiment.json').read_text())
    assert hashlib.sha256(program32['bytecode'].encode()).hexdigest()=='d2816750fd1278beb70c16743e4851561f9d5b30c57770f1a707a4d16ef2d2bc'
    abi32=json.loads((ROOT/'extra/experiments/noir-compact/browser/assets/assurance-cp32-abi.json').read_text())
    assert [p['type'] for p in program32['abi']['parameters'] if p['visibility']=='public']==[abi32]
    small_programs=[]
    for directory,name,key,bytecode,abi in [
        ('short64-cp8-v2','program64.json','assurance64.vk','c282b242a8ba73bf03b889ec4e512287f9a746ec4fdf5bd47555cd12666f04ec',program['abi']['parameters'][-1]['type']),
        ('short128-cp32-v2','program128.json','assurance128-cp32.vk','6cb951178bc0530e85d7826e3720a641d2580015577b515aa950b960e0e3bb61',abi32),
    ]:
        candidate=json.loads((BUILD/'noir-capacity'/directory/'target/huma_compact_experiment.json').read_text())
        assert hashlib.sha256(candidate['bytecode'].encode()).hexdigest()==bytecode
        assert [p['type'] for p in candidate['abi']['parameters'] if p['visibility']=='public']==[abi]
        for filename,minimum in [('constraint-results.json',21),('boundary-results.json',5)]:
            report=json.loads((BUILD/'noir-capacity'/directory/filename).read_text())
            assert len(report['cases'])>=minimum and all(c['accepted']==c['expectedAccepted'] for c in report['cases'])
            assert report['artifactSha256']==digest(BUILD/'noir-capacity'/directory/'target/huma_compact_experiment.json')
        assert (ROOT/'extra/experiments/noir-compact/browser/assets'/key).read_bytes()==(BUILD/'noir-capacity'/directory/'target/setup/vk').read_bytes()
        small_programs.append((name,candidate))
    node=BUILD/'noir-tools/node24/node'
    assert subprocess.check_output([str(node),'--version'],text=True).strip()=='v24.22.1'
    archive=BUILD/'noir-tools/node-v24.22.1-darwin-arm64.tar.gz'
    assert digest(archive)=='89c682593d76cd44233fa53b1563264e7de9cbb189cad169135c5b4fadfbc0a7'
    # Verify the executable still matches the checked official archive.
    import tarfile
    with tarfile.open(archive) as t:assert t.extractfile('node-v24.22.1-darwin-arm64/bin/node').read()==node.read_bytes()
    bb=BUILD/'noir-tools/bb/bb'
    assert subprocess.check_output([str(bb),'--version'],text=True).strip()=='5.2.1'
    bb_archive=BUILD/'noir-tools/v5.2.1-barretenberg-arm64-darwin.tar.gz'
    assert digest(bb_archive)=='7a648eb578ea34d224357aba3e81df6b294fe23caf89f22ec9ad7536fbcc8a28'
    with tarfile.open(bb_archive) as t:
        members=[m for m in t.getmembers() if m.isfile() and Path(m.name).name=='bb']
        assert len(members)==1 and t.extractfile(members[0]).read()==bb.read_bytes()
    # Witnesses come from Noir's own solver built natively (backend/integrations/noir/witness, scripts/build.sh builds it).
    witness=ROOT/'build/witness-target/release/witness'
    assert witness.is_file(),'Build integrations/noir/witness first (backend/scripts/build.sh does).'
    node_engine=os.environ.get('HUMA_NODE_ENGINE')=='1'
    destination.mkdir(parents=True)
    def copy(src,target):
        out=destination/target;out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,out)
    copy(Path(__file__).with_name('worker.mjs'),'worker.mjs')
    with tarfile.open(archive) as t:
        license=destination/'licenses/node-LICENSE';license.parent.mkdir()
        license.write_bytes(t.extractfile('node-v24.22.1-darwin-arm64/LICENSE').read())
    for src,target in [(node,'node'),(bb,'bb'),(BUILD/'noir-compact-native-target/release/huma-compact-experiment','capture-input'),(witness,'witness')]:copy(src,target)
    (destination/'licenses/noir-NOTICE.txt').write_text("witness: built from noir-lang/noir v1.0.0-beta.25 (acvm, acir, brillig_vm, "
        "bn254_blackbox_solver, noirc_abi), MIT OR Apache-2.0, https://github.com/noir-lang/noir. Its other Rust crates "
        "and their licenses are listed in integrations/noir/witness/Cargo.lock.\n")
    (destination/'program.json').write_text(json.dumps({k:program[k] for k in ['noir_version','bytecode','abi']}))
    (destination/'program-v5.json').write_text(json.dumps({k:program5[k] for k in ['noir_version','bytecode','abi']}))
    (destination/'program-cp32.json').write_text(json.dumps({k:program32[k] for k in ['noir_version','bytecode','abi']}))
    for name,candidate in small_programs:(destination/name).write_text(json.dumps({k:candidate[k] for k in ['noir_version','bytecode','abi']}))
    reader=ROOT/'extra/experiments/noir-compact/browser'
    for name in ['assurance-core.mjs','assurance-profile.mjs','core.mjs','profile.mjs','assets/assurance256.vk','assets/assurance256-v2.vk','assets/assurance-abi.json','assets/assurance256-cp32.vk','assets/assurance-cp32-abi.json','assets/assurance64.vk','assets/assurance128-cp32.vk']:copy(reader/name,'reader/'+name)
    for name in ['core.mjs','contract.mjs']:copy(ROOT/'frontend/verify-core'/name,'evidence/'+name)
    # Long drafts (assurance-long-v3): one part and one final program per text tier from
    # integrations/noir/long3/prover.mjs build, pinned by the worker and reader. The v1 and v2 keys stay so
    # proofs made before v3 still verify; their programs are no longer shipped.
    for name in ['chunk','final1024','final4096','final10000']:copy(reader/f'assets/long-{name}.vk',f'reader/assets/long-{name}.vk')
    for name in ['final1024','final4096','final10000']:copy(reader/f'assets/long2-{name}.vk',f'reader/assets/long2-{name}.vk')
    for name in [kind+str(tier) for tier in [1024,4096,10000] for kind in ['chunk','final']]:
        program=json.loads((BUILD/'noir-long3'/name/f'target/huma_long3_{name}.json').read_text())
        (destination/f'long3-{name}.json').write_text(json.dumps({k:program[k] for k in ['noir_version','bytecode','abi']}))
        assert (BUILD/'noir-long3'/name/'target/vk').read_bytes()==(reader/f'assets/long3-{name}.vk').read_bytes()
        copy(reader/f'assets/long3-{name}.vk',f'reader/assets/long3-{name}.vk')
    copy(reader/'final-text.mjs','reader/final-text.mjs')
    source=(ROOT/'backend/integrations/noir/long/reader.mjs').read_text()
    source=source.replace("'../../../../extra/experiments/noir-compact/browser/core.mjs'","'./core.mjs'").replace("'../../../../extra/experiments/noir-compact/browser/final-text.mjs'","'./final-text.mjs'")
    (destination/'reader/long.mjs').write_text(source[:source.index('// Node adapter:')])
    # The points the largest program needed (v2's final1024: 2,060,088), rounded up to 2^21 at 32 bytes each. v3's
    # largest (final10000: 1,027,301) needs half; the file stays the same so installed Macs keep theirs.
    # bb unpacks them once into the user's cache. Release builds leave them out (64 MB that don't compress): the app
    # downloads them once and checks this fingerprint (HumaCore ProvingSetup, scripts/upload-engine.mjs).
    with open(BUILD/'noir-crs'/'bn254_g1_compressed.dat','rb') as source:points=source.read(CRS_POINTS*32)
    assert len(points)==CRS_POINTS*32 and hashlib.sha256(points).hexdigest()==CRS_SHA256
    if os.environ.get('HUMA_EXTERNAL_SETUP')!='1':
        (destination/'crs').mkdir(exist_ok=True)
        (destination/'crs'/'bn254_g1_compressed.dat').write_bytes(points)
    # Release engines run the worker on macOS's own JavaScriptCore (extra/Sources/HumaScriptHost) instead of Node.js: one
    # bundled worker.js replaces node (116 MB).
    # HUMA_NODE_ENGINE=1 keeps Node.js, for engines that run elsewhere (the server prover, prover/src/page.rs).
    if not node_engine:
        host=Path(os.environ.get('HUMA_SCRIPT_HOST',''))
        assert host.is_file(),'Set HUMA_SCRIPT_HOST to the built HumaScriptHost (backend/scripts/build.sh does).'
        subprocess.run([str(node),str(ROOT/'backend/integrations/noir/jsc/bundle.mjs'),str(destination)],check=True)
        copy(host,'HumaScriptHost')
        # The bundle carries code from these packages; their licenses travel with it.
        web=ROOT/'frontend/node_modules'
        for name,src in [('buffer-LICENSE',web/'buffer/LICENSE'),('base64-js-LICENSE',web/'base64-js/LICENSE'),
                         ('ieee754-LICENSE',web/'ieee754/LICENSE')]:copy(src,'licenses/'+name)
        (destination/'node').unlink();(destination/'licenses/node-LICENSE').unlink()
    manifest(destination)
    print('Staged offline Noir engine; no proof, key use or authentication started.')
if __name__=='__main__':main()
