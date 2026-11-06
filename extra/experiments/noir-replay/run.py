#!/usr/bin/env python3
"""Build, check, prove and verify the complete bounded public Swift V2 fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import fixture
import verify

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
WORK = ROOT / "build/research/noir-replay"
TOOLS = ROOT / "build/research/noir-tools"
NARGO = TOOLS / "noir/nargo"
BB = TOOLS / "bb/bb"
DRIVER = TOOLS / "worker-bench"


def call(args, env, timeout=195):
    start = time.monotonic()
    p = subprocess.run([str(a) for a in args], cwd=WORK, env=env,
                       text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(p.stdout[-1000:] + p.stderr[-2000:])
    return round((time.monotonic()-start)*1000, 2), p.stdout


def hashed(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive_built_circuit():
    target = WORK / "target"
    if not (target / "setup/vk").exists():
        return None
    previous = hashed(target / "setup/vk")
    archive = WORK / "archives" / previous
    for name in ["src", "Nargo.toml", "inputs.json", "reference.json"]:
        source = WORK / name; destination = archive / name
        if source.exists() and not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir(): shutil.copytree(source, destination)
            else: shutil.copy2(source, destination)
    for source in [target / "huma_replay_experiment.json", target / "setup", *target.glob("proof-*-threads")]:
        destination = archive / "target" / source.name
        if source.exists() and not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir(): shutil.copytree(source, destination)
            else: shutil.copy2(source, destination)
    return previous


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threads", type=int, choices=[2, 4, 8, 16], default=2)
    parser.add_argument("--checks", action="store_true", help="Run the private-witness mutation suite before proving")
    args = parser.parse_args()
    env = dict(os.environ, RAYON_NUM_THREADS="2", HARDWARE_CONCURRENCY=str(args.threads))
    if not BB.exists() or subprocess.check_output([str(BB), "--version"], text=True).strip() != "5.2.1":
        parser.error("Run experiments/noir-prover/prepare.py for patched tools first")
    WORK.mkdir(parents=True, exist_ok=True)
    previous_vk = archive_built_circuit()
    shutil.copytree(HERE / "src", WORK / "src", dirs_exist_ok=True)
    manifest = (HERE / "Nargo.toml").read_text().replace('../../../build/research/noir-sha256', '../noir-sha256')
    (WORK / "Nargo.toml").write_text(manifest)
    # Compile the worker driver against the current app's core resource controls.
    subprocess.run(["swift", "build", "--package-path", "extra", "--scratch-path", ".build", "--target", "HumaCore", "--jobs", "2"], cwd=ROOT, check=True, env=env)
    bin_dir = Path(subprocess.check_output(["swift", "build", "--package-path", "extra", "--scratch-path", ".build", "--show-bin-path"], cwd=ROOT, text=True).strip())
    subprocess.run(["swiftc", "-parse-as-library", "-module-cache-path", str(ROOT / "build/module-cache"),
                    "-I", str(bin_dir), str(HERE / "WorkerBench.swift"), str(bin_dir / "HumaCore.o"), "-o", str(DRIVER)],
                   cwd=ROOT, check=True, env=env)
    witness = json.loads((ROOT / "backend/zkvm/common/tests/fixtures/swift-timed.json").read_text())
    reference = fixture.native(witness)
    inputs = fixture.convert(witness, reference["journal"])
    fixture.write(inputs)
    (WORK / "inputs.json").write_text(json.dumps(inputs) + "\n")
    (WORK / "reference.json").write_text(json.dumps(reference, indent=2) + "\n")
    compile_ms, _ = call(["/usr/bin/nice", "-n", "10", NARGO, "execute"], env)
    if args.checks:
        call(["python3", HERE / "check.py"], env)
    target = WORK / "target"
    common = ["-b", target / "huma_replay_experiment.json", "-t", "noir-recursive"]
    _, raw = call([DRIVER, BB, "gates", *common], env)
    gates = json.loads(raw)
    common += ["-c", ROOT / "build/research/noir-crs"]
    _, raw = call([DRIVER, BB, "write_vk", *common, "-o", target / "setup"], env)
    setup = json.loads(raw)
    if previous_vk and previous_vk != hashed(target / "setup/vk"):
        # Every existing profile was archived with its own ABI/VK before compile.
        # Never leave an old proof beside a newly generated, incompatible key.
        for previous_proof in target.glob("proof-*-threads"):
            shutil.rmtree(previous_proof)
    out = target / f"proof-{args.threads}-threads"
    out.mkdir(parents=True, exist_ok=True)
    _, raw = call([DRIVER, BB, "prove", *common, "-w", target / "huma_replay_experiment.gz",
                   "-k", target / "setup/vk", "-o", out,
                   "--bench_out_hierarchical", out / "stages.json"], env)
    prove = json.loads(raw)
    started = time.monotonic()
    verified = verify.verify(out, witness["text"], reference["journal"]["captureKeyHash"])
    verification_ms = round((time.monotonic()-started)*1000, 2)
    result = dict(experimental=True, statement="Complete bounded native V2 replay; not app release",
                  fixture="swift-timed.json", fixtureSha256=hashed(ROOT / "backend/zkvm/common/tests/fixtures/swift-timed.json"),
                  noir="1.0.0-beta.25", bb="5.2.1", verifierTarget="noir-recursive", zeroKnowledge=True,
                  threads=args.threads, nice=10, compileAndWitnessMs=compile_ms,
                  gateCount=gates, setupMs=setup["elapsedMs"], proveMs=prove["elapsedMs"], verifyAndBindMs=verification_ms,
                  proofBytes=(out / "proof").stat().st_size, publicInputBytes=(out / "public_inputs").stat().st_size,
                  witnessSha256=hashed(target / "huma_replay_experiment.gz"), vkSha256=hashed(target / "setup/vk"),
                  artifactSha256=hashed(target / "huma_replay_experiment.json"),
                  sourceSha256={p.name: hashed(p) for p in sorted((HERE / "src").glob("*.nr"))},
                  referenceJournal=reference["journal"], publicFieldsMatch=verified == inputs["expected"], verified=True)
    if not result["publicFieldsMatch"]:
        raise RuntimeError("Proven public fields differ from native reference")
    (WORK / f"results-{args.threads}-threads.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
