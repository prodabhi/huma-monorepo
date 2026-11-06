#!/usr/bin/env python3
"""Generate synthetic individual-key sessions and measure R0 execution, NOT proofs."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import fixture

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
WORK = ROOT / "build/research/noir-typing-fixtures"


def run(args):
    return subprocess.check_output([str(x) for x in args], cwd=ROOT,
                                   text=True, timeout=120)


if __name__ == "__main__":
    WORK.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, RAYON_NUM_THREADS="2")
    subprocess.run(["swift", "build", "--package-path", "extra", "--scratch-path", ".build", "--target", "HumaCore", "--jobs", "2"],
                   cwd=ROOT, env=env, check=True, timeout=120)
    bin_dir = Path(run(["swift", "build", "--package-path", "extra", "--scratch-path", ".build", "--show-bin-path"]).strip())
    generator = WORK / "generate-typing"
    run(["swiftc", "-parse-as-library", "-module-cache-path", ROOT / "build/module-cache",
         "-I", bin_dir, HERE / "generate-typing.swift", bin_dir / "HumaCore.o", "-o", generator])
    print(run([generator, WORK]), end="", flush=True)
    results = []
    for policy in ["legacy32", "current"]:
      for size in [50, 250, 1024]:
        suffix = "-current" if policy == "current" else ""
        path = WORK / f"typing-{size}{suffix}.json"
        witness = json.loads(path.read_text())
        started = time.monotonic()
        reference = fixture.native(witness)
        elapsed = round((time.monotonic() - started) * 1000, 2)
        session = witness["session"]
        counts = dict(edits=len(session["events"]), samples=len(session["inputSamples"]),
                      records=len(session["captureRecords"]), checkpoints=len(session["signedCheckpoints"]))
        expected_checkpoints = 2+(3*size)//32 if policy == "legacy32" else {50:2,250:5,1024:16}[size]
        assert counts == dict(edits=size, samples=2*size, records=3*size, checkpoints=expected_checkpoints)
        assert len(witness["text"].encode("utf-8")) == size
        assert reference["executionOnly"] is True
        result = dict(fixture=path.name, cadence=policy, fixtureSha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                      bytes=size, **counts, executeWallMs=elapsed,
                      cycles=reference["cycles"], segments=reference["segments"])
        results.append(result)
        print(json.dumps(result), flush=True)
    report = dict(synthetic=True, hardwareAttested=False, executionOnly=True,
                  proofGenerated=False, noirProofGenerated=False,
                  capture="one character/edit, down/edit/up; software P-256; legacy32 vs current 10s/256-record cadence",
                  sourceSha256=hashlib.sha256((HERE / "generate-typing.swift").read_bytes()).hexdigest(),
                  results=results)
    (WORK / "profile.json").write_text(json.dumps(report, indent=2) + "\n")
