#!/usr/bin/env python3
"""Real Mac service/local sharing tests, with a temporary software-only probe."""
import argparse,json,os,plistlib,shutil,subprocess,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',required=True)
    parser.add_argument('--variants',nargs='+',choices=['short','medium','boundary','full','cached-cp32','cached-v5','legacy'],default=['short','medium','boundary','full'])
    args=parser.parse_args()
    if not args.run.replace('-','').isalnum():raise ValueError('Use a local run name')
    os.umask(0o077)
    env=dict(os.environ,CLANG_MODULE_CACHE_PATH=str(ROOT/'build/swift-module-cache'),
        SWIFTPM_MODULECACHE_OVERRIDE=str(ROOT/'build/swift-module-cache'))
    def run(command,**kwargs):return subprocess.run([str(x) for x in command],cwd=ROOT,env=env,check=True,**kwargs)
    bin_dir=Path(subprocess.check_output(['swift','build','--show-bin-path'],cwd=ROOT,env=env,text=True).strip())
    temp=Path(tempfile.mkdtemp(prefix='huma-adaptive-acceptance-'))
    try:
        app=temp/'HumaNoirPublicationProbe.app';contents=app/'Contents';binary=contents/'MacOS/HumaNoirProbe';binary.parent.mkdir(parents=True)
        resources=contents/'Resources';resources.mkdir()
        with (contents/'Info.plist').open('wb') as file:
            plistlib.dump(dict(CFBundleExecutable='HumaNoirProbe',CFBundleIdentifier='dev.swayam.huma.noir-probe',CFBundlePackageType='APPL'),file)
        run(['swiftc','-parse-as-library','-I',bin_dir,'-module-cache-path',env['CLANG_MODULE_CACHE_PATH'],
            ROOT/'extra/Sources/Huma/ReplayProofService.swift',ROOT/'backend/integrations/noir/acceptance.swift',bin_dir/'HumaCore.o','-o',binary])
        run(['python3',ROOT/'backend/integrations/noir/package.py',resources/'NoirEngine'])
        for name in ['node','bb','capture-input']:run(['codesign','--force','--sign','-',resources/'NoirEngine'/name])
        run(['python3',ROOT/'backend/integrations/noir/package.py','--refresh-manifest',resources/'NoirEngine'])
        run(['codesign','--force','--sign','-',app])
        run(['codesign','--verify','--deep','--strict',app])
        fixture=temp/'live-assurance'
        run(['swiftc','-parse-as-library','-I',bin_dir,'-module-cache-path',env['CLANG_MODULE_CACHE_PATH'],
            ROOT/'extra/experiments/noir-compact/live-assurance.swift',bin_dir/'HumaCore.o','-o',fixture])
        library=ROOT/'build/research/noir-compact-native-target/release/libhuma_compact_experiment.dylib'
        env['HUMA_NOIR_ACCEPTANCE_PROBE']=str(binary)
        for variant in args.variants:
            if variant in ['short','medium']:
                directory=ROOT/'build/research/noir-assurance-native'/('live-adaptive-'+variant+'-v1')
                if not directory.exists():
                    directory.mkdir(parents=True,mode=0o700)
                    run([fixture,library,directory,'--adaptive-'+variant])
            flags={'short':['--adaptive-short'],'medium':['--adaptive-medium'],'boundary':['--adaptive-boundary'],
                'full':['--extended'],
                'cached-cp32':['--boundary','--reuse'],'cached-v5':['--reuse'],'legacy':['--legacy','--reuse']}[variant]
            run(['node',ROOT/'frontend/test/native-noir-publication.mjs','--run='+args.run,*flags])
    finally:
        shutil.rmtree(temp)
    print(json.dumps(dict(temporaryProbeRemoved=True,ownerKeysOrBiometricsUsed=False,variants=args.variants)))

if __name__=='__main__':main()
