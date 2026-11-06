#!/usr/bin/env python3
"""Resource-bounded sizing of a 50-edit replay or a 10KB hash-only component."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import fixture

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
TOOLS = ROOT / "build/research/noir-tools"
ENV = dict(os.environ, RAYON_NUM_THREADS="2", HARDWARE_CONCURRENCY="2")


def limited(args, cwd):
    """Only compiler/gate commands: owned group, 90s and 6GiB RSS stop."""
    lock_path = Path(tempfile.gettempdir()) / f"huma-{os.getuid()}-proving.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    start = time.monotonic(); peak = 0
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        p = subprocess.Popen([str(x) for x in args], cwd=cwd, env=ENV,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             start_new_session=True)
        try:
            while True:
                try:
                    out, err = p.communicate(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    raw = subprocess.check_output(["/bin/ps", "-axo", "pgid=,rss="], text=True)
                    rss = sum(int(row.split()[1]) for row in raw.splitlines()
                              if len(row.split()) == 2 and int(row.split()[0]) == p.pid)
                    peak = max(peak, rss * 1024)
                    if peak > 6*1024**3 or time.monotonic()-start > 90:
                        reason = "rss" if peak > 6*1024**3 else "deadline"
                        stats = dict(stopped=True, reason=reason, peakSampledRSS=peak,
                                     wallMs=round((time.monotonic()-start)*1000,2), proofAttempted=False)
                        (cwd / "limit-stop.json").write_text(json.dumps(stats,indent=2)+'\n')
                        raise RuntimeError(f"Sizing stopped at its {reason} budget; no proof attempted")
            if p.returncode:
                raise RuntimeError(err[-1500:] + out[-500:])
            return dict(wallMs=round((time.monotonic()-start)*1000,2), peakSampledRSS=peak), out
        finally:
            # The PID is an owned, unreaped session leader until communicate/wait.
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
    finally:
        os.close(fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=["typing50-current","typing50-legacy","text10000"])
    parser.add_argument("--prove", action="store_true", help="Only allowed for the hash-only 10KB component")
    parser.add_argument("--threads", type=int, choices=[2,8], default=2)
    args = parser.parse_args()
    ENV["HARDWARE_CONCURRENCY"] = str(args.threads)
    if subprocess.check_output([str(TOOLS/'bb/bb'),'--version'],text=True).strip() != '5.2.1':
        parser.error('Run the pinned tool preparer first')
    if '1.0.0-beta.25' not in subprocess.check_output([str(TOOLS/'noir/nargo'),'--version'],text=True):
        parser.error('Unexpected Noir compiler version')
    if args.prove and args.case != "text10000":
        parser.error("Large full replay is sizing-only until its resource budget is reviewed")
    work = ROOT / "build/research/noir-sizing" / args.case
    shutil.copytree(HERE / "src", work / "src", dirs_exist_ok=True)
    if args.case == "text10000":
        # This proves one SHA preimage. It does NOT prove capture, authorship,
        # signatures, UTF-8 validity, edit replay or the Huma character policy.
        text = (b"Public synthetic 10KB capacity fixture. " * 300)[:10000]
        assert len(text) == 10000
        values = dict(text=list(text), expected=list(hashlib.sha256(text).digest()))
        source = "fn main(text: [u8;10000], expected: pub [u8;32]) { assert(sha256::digest(text) == expected); }\n"
    else:
        suffix = "-current" if args.case.endswith("current") else ""
        witness = json.loads((ROOT / f"build/research/noir-typing-fixtures/typing-50{suffix}.json").read_text())
        checkpoints = len(witness['session']['signedCheckpoints'])
        reference = fixture.native(witness)
        values = fixture.convert(witness,reference['journal'],counts=(50,100,150,checkpoints),
                                 insert_capacity=4,edit_payload_capacity=320)
        source = (HERE / "src/main.nr").read_text()
        for old,new in [("EDITS: u32 = 5;","EDITS: u32 = 50;"),
                        ("SAMPLES: u32 = 10;","SAMPLES: u32 = 100;"),
                        ("CAPTURES: u32 = 15;","CAPTURES: u32 = 150;"),
                        ("CHECKPOINTS: u32 = 3;",f"CHECKPOINTS: u32 = {checkpoints};"),
                        ("inserted: Bytes<32>","inserted: Bytes<4>"),
                        ("payload_bytes: Bytes<448>","payload_bytes: Bytes<320>")]:
            assert source.count(old) == 1
            source = source.replace(old,new)
    (work / "src/main.nr").write_text(source)
    (work / "Nargo.toml").write_text('[package]\nname="sizing"\ntype="bin"\nauthors=[]\n'
        f'[dependencies]\nsha256={{path="{ROOT / "build/research/noir-sha256"}"}}\n')
    (work / "Prover.toml").write_text("\n".join(k+" = "+fixture.toml(v) for k,v in values.items())+"\n")
    compiler,_ = limited(["/usr/bin/nice","-n","10",TOOLS/"noir/nargo","execute"],work)
    gate_cost,raw = limited(["/usr/bin/nice","-n","10",TOOLS/"bb/bb","gates",
                             "-b",work/"target/sizing.json","-t","noir-recursive"],work)
    gates = json.loads(raw)
    result = dict(case=args.case,experimental=True,proofGenerated=False,
                  noir='1.0.0-beta.25',bb='5.2.1',verifierTarget='noir-recursive',zeroKnowledge=True,
                  statement="SHA-256 preimage only, NOT Huma replay" if args.case == "text10000" else "Full native V2 replay in exact 50-edit bucket; sizing only",
                  compiler=compiler,gateCounter=gate_cost,gates=gates,threads=args.threads,nice=10)
    print(json.dumps(result),flush=True)
    if args.prove:
        if gates['functions'][0]['circuit_size'] > 2_100_000:
            raise RuntimeError("Hash-only proof exceeds the reviewed experiment size")
        target = work/'target'; proof = target/f'proof-{args.threads}-threads'
        common = ['-b',target/'sizing.json','-t','noir-recursive','-c',ROOT/'build/research/noir-crs']
        def worker(command):
            p = subprocess.run([str(x) for x in [TOOLS/'worker-bench',TOOLS/'bb/bb',*command]],
                               cwd=work,env=ENV,text=True,capture_output=True,timeout=195)
            if p.returncode: raise RuntimeError(p.stderr[-1000:])
            return json.loads(p.stdout)
        worker(['write_vk',*common,'-o',target/'setup'])
        timing = worker(['prove',*common,'-w',target/'sizing.gz','-k',target/'setup/vk','-o',proof])
        verified = subprocess.run([str(x) for x in [TOOLS/'bb/bb','verify','-p',proof/'proof',
            '-i',proof/'public_inputs','-k',target/'setup/vk','-t','noir-recursive','-c',ROOT/'build/research/noir-crs']],
            env=ENV,text=True,capture_output=True,timeout=15)
        public = (proof/'public_inputs').read_bytes()
        expected = b''.join(x.to_bytes(32,'big') for x in values['expected'])
        if verified.returncode or public != expected: raise RuntimeError('Component proof/public digest rejected')
        result.update(proofGenerated=True,verified=True,proveMs=timing['elapsedMs'],
                      proofBytes=(proof/'proof').stat().st_size,publicInputsBytes=len(public),
                      vkSha256=hashlib.sha256((target/'setup/vk').read_bytes()).hexdigest(),
                      artifactSha256=hashlib.sha256((target/'sizing.json').read_bytes()).hexdigest())
    result['sourceSha256'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (work/'src').glob('*.nr')}
    (work/f'results-{args.threads}-threads.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
