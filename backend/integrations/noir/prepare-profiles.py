#!/usr/bin/env python3
"""Prepare the two current small circuits from disposable software fixtures."""
import hashlib,json,os,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def main():
    os.umask(0o077)
    env=dict(os.environ,DEVELOPER_DIR='/Library/Developer/CommandLineTools',
        CARGO_TARGET_DIR=str(ROOT/'build/research/noir-compact-native-target'))
    def run(command,**kwargs):return subprocess.run([str(x) for x in command],cwd=ROOT,env=env,check=True,**kwargs)
    run(['cargo','build','--release','--manifest-path','extra/experiments/noir-compact/native/Cargo.toml',
        '--bin','huma-compact-experiment','--example','bucket_boundaries','--locked','--jobs','2'])
    capture=ROOT/'build/research/noir-assurance-native/live-v4-short-v2/document.huma'
    if not capture.is_file():
        bin_dir=Path(subprocess.check_output(['swift','build','--show-bin-path'],cwd=ROOT,env=env,text=True).strip())
        tool=ROOT/'build/research/noir-tools/live-assurance'
        run(['swiftc','-parse-as-library','-I',bin_dir,'extra/experiments/noir-compact/live-assurance.swift',bin_dir/'HumaCore.o','-o',tool])
        capture.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        run([tool,ROOT/'build/research/noir-compact-native-target/release/libhuma_compact_experiment.dylib',capture.parent,'--short'])
    for name,bucket,checkpoints,bytecode,key in [
        ('short64-cp8-v2','short64',8,'c282b242a8ba73bf03b889ec4e512287f9a746ec4fdf5bd47555cd12666f04ec','assurance64.vk'),
        ('short128-cp32-v2','short128',32,'6cb951178bc0530e85d7826e3720a641d2580015577b515aa950b960e0e3bb61','assurance128-cp32.vk'),
    ]:
        work=ROOT/'build/research/noir-capacity'/name
        if not work.exists():run(['python3','extra/experiments/noir-compact/capacity_cases.py','--name',name,'--bucket',bucket,'--checkpoints',checkpoints,'--capture',capture])
        program=work/'target/huma_compact_experiment.json'
        if hashlib.sha256(json.loads(program.read_text())['bytecode'].encode()).hexdigest()!=bytecode:
            raise ValueError('Circuit differs from the pinned current profile; use a new experiment directory')
        if not (work/'constraint-results.json').is_file():run(['python3','extra/experiments/noir-compact/assurance_checks.py','--name',name,'--work-dir',work])
        if not (work/'boundary-results.json').is_file():run(['python3','extra/experiments/noir-compact/bucket_checks.py',work])
        if not (work/'target/setup/vk').is_file():run(['python3','extra/experiments/noir-compact/bucket_prove.py',work,'--name','prepare','--capture',capture])
        if (work/'target/setup/vk').read_bytes()!=(ROOT/'extra/experiments/noir-compact/browser/assets'/key).read_bytes():
            raise ValueError('Generated verification key differs from the pinned public key')
    print('Current small circuits prepared; no owner key, authentication or app launch used.')

if __name__=='__main__':main()
