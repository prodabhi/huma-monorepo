#!/usr/bin/env python3
"""Check optimized constrained SHA against hashlib and official Noir SHA at boundaries."""
import copy
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import fixture

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
WORK = ROOT / "build/research/noir-sha256-checks"
NARGO = ROOT / "build/research/noir-tools/noir/nargo"


def check(work, case, values, accepted):
    (work / f"{case}.toml").write_text("\n".join(k + " = " + fixture.toml(v) for k,v in values.items()) + "\n")
    p = subprocess.run(["/usr/bin/nice", "-n", "10", str(NARGO), "execute", case,
                        "--prover-name", case], cwd=work, env=dict(os.environ, RAYON_NUM_THREADS="2"),
                       capture_output=True, text=True, timeout=45)
    if accepted:
        valid = p.returncode == 0 and "Circuit witness successfully solved" in p.stdout
    else:
        valid = p.returncode != 0 and any(x in p.stderr for x in ["Failed constraint", "Assertion failed"])
    if not valid:
        raise RuntimeError(case + ": " + p.stderr[-1200:] + p.stdout[-500:])
    return dict(case=case, accepted=accepted)


if __name__ == "__main__":
    rng = random.Random(20261022)
    results = []
    for capacity in [1,55,56,63,64,65,160,448,640,768]:
        work = WORK / str(capacity)
        (work / "src").mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE / "candidates/bounded_sha256.nr", work / "src/bounded_sha256.nr")
        (work / "src/main.nr").write_text(f"""mod bounded_sha256;
fn main(data: [u8;{capacity}], len: u32, expected: pub [u8;32]) {{
    assert(bounded_sha256::digest(data,len) == expected);
    assert(sha256::sha256_var(data,len) == expected);
}}
""")
        (work / "Nargo.toml").write_text('[package]\nname = "sha_check"\ntype = "bin"\nauthors = []\n'
            f'[dependencies]\nsha256 = {{ path = "{ROOT / "build/research/noir-sha256"}" }}\n')
        data = list(rng.randbytes(capacity))
        lengths = sorted({0,capacity} | {x for x in [1,54,55,56,57,63,64,65,118,119,120,121,127,128,129,447,448,511,512,631,632,639,640,767,768] if x <= capacity})
        for length in lengths:
            values = dict(data=data, len=length, expected=list(hashlib.sha256(bytes(data[:length])).digest()))
            results.append(dict(capacity=capacity, **check(work, f"Length{length}", values, True)))
        good = dict(data=data, len=capacity, expected=list(hashlib.sha256(bytes(data)).digest()))
        changed = copy.deepcopy(good); changed['expected'][0] ^= 1
        results.append(dict(capacity=capacity, **check(work, "BadDigest", changed, False)))
        changed = copy.deepcopy(good); changed['data'][0] ^= 1
        results.append(dict(capacity=capacity, **check(work, "BadPrefix", changed, False)))
        changed = copy.deepcopy(good); changed['len'] = capacity + 1
        results.append(dict(capacity=capacity, **check(work, "OverCapacity", changed, False)))
        changed = copy.deepcopy(good); changed['len'] = capacity - 1
        results.append(dict(capacity=capacity, **check(work, "BadLength", changed, False)))
        # An unused suffix is not part of the message, even when it is nonzero.
        length = capacity // 2
        suffix = dict(data=data.copy(),len=length,expected=list(hashlib.sha256(bytes(data[:length])).digest()))
        suffix['data'][-1] ^= 255
        results.append(dict(capacity=capacity, **check(work, "UnusedSuffix", suffix, True)))
        print(f"capacity {capacity}: {len(lengths)} boundary cases, 4 rejections, unused suffix pass", flush=True)
    report = dict(constraintChecksOnly=True, proofGenerated=False,
                  sourceSha256=hashlib.sha256((HERE / 'candidates/bounded_sha256.nr').read_bytes()).hexdigest(),
                  results=results)
    (WORK / "results.json").write_text(json.dumps(report, indent=2) + "\n")
