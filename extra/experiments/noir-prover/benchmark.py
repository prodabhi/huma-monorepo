#!/usr/bin/env python3
"""Isolated native Noir microbenchmarks. Not an accepted Huma proof format."""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = ROOT / "build/research"
NARGO = BASE / "noir-tools/noir/nargo"
BB = BASE / "noir-tools/bb/bb"
CRS = BASE / "noir-crs"
SHA256 = BASE / "noir-sha256"
ENV = dict(os.environ, HARDWARE_CONCURRENCY="2")


def call(args, cwd, timeout=30, success=True):
    start = time.monotonic()
    p = subprocess.run([str(x) for x in args], cwd=cwd, env=ENV,
                       capture_output=True, text=True, timeout=timeout)
    elapsed = round((time.monotonic() - start) * 1000, 2)
    if (p.returncode == 0) != success:
        raise RuntimeError(f"{args[0]} unexpected status {p.returncode}: {p.stderr[-2000:]}")
    return elapsed, p.stdout


def run(variant, reps):
    count = 8 if variant == "p256-8" else 2
    hashed = variant == "checkpoint-2"
    work = BASE / "noir-bench" / variant
    (work / "src").mkdir(parents=True, exist_ok=True)
    dependencies = f'sha256 = {{ path = "{SHA256}" }}\n' if hashed else ""
    (work / "Nargo.toml").write_text(
        '[package]\nname = "benchmark"\ntype = "bin"\nauthors = []\n'
        'compiler_version = ">=1.0.0"\n[dependencies]\n' + dependencies)
    params = f"x: {'pub ' if not hashed else ''}[u8;32], y: {'pub ' if not hashed else ''}[u8;32], "
    params += f"digests: pub [[u8;32];{count}], signatures: [[u8;64];{count}]"
    preamble = ""
    digest = "digests[i]"
    if hashed:
        params += ", key_hash: pub [u8;32], payloads: [[u8;1024];2]"
        preamble = """
    let mut sec1 = [0u8;65]; sec1[0] = 4;
    for i in 0..32 { sec1[i+1] = x[i]; sec1[i+33] = y[i]; }
    assert(sha256::digest(sec1) == key_hash);
"""
        digest = "sha256::digest(payloads[i])"
    source = f"""fn main({params}) {{
    {preamble}
    for i in 0..{count} {{
        let digest = {digest};
        assert(digest == digests[i]);
        assert(std::ecdsa_secp256r1::verify_signature(x, y, signatures[i], digest));
    }}
}}
"""
    (work / "src/main.nr").write_text(source)
    _, raw = call(["swift", "-module-cache-path", ROOT / "build/module-cache",
                   HERE / "generate.swift", count, 1024 if hashed else 32], ROOT)
    inputs = json.loads(raw)
    fields = ["x", "y", "digests", "signatures"] + (["key_hash", "payloads"] if hashed else [])

    def write_inputs(values, name="Prover"):
        (work / (name + ".toml")).write_text("\n".join(
            f"{field} = {json.dumps(values[field])}" for field in fields) + "\n")

    write_inputs(inputs)
    compile_ms, _ = call([NARGO, "execute"], work)
    t = work / "target"
    common = ["-t", "noir-recursive", "-c", CRS]
    args = [BB, "prove", "-b", t / "benchmark.json", "-w", t / "benchmark.gz"]
    # Asset download, VK construction and first proof are setup, timed separately.
    setup_ms, _ = call(["/usr/bin/nice", "-n", "10", *args, "-o", t / "setup",
                        "--write_vk", "--verify", *common], work, timeout=120)
    vk = t / "setup/vk"
    samples = []
    for i in range(reps):
        witness_ms, _ = call([NARGO, "execute"], work)
        out = t / f"run-{i}"
        prove_ms, _ = call(["/usr/bin/nice", "-n", "10", *args, "-o", out, "-k", vk, *common], work)
        verify_args = [BB, "verify", "-p", out / "proof", "-k", vk,
                       "-i", out / "public_inputs", *common]
        verify_ms, _ = call(verify_args, work)
        samples.append(dict(witnessMs=witness_ms, proveMs=prove_ms, verifyMs=verify_ms,
                            proofBytes=(out / "proof").stat().st_size))
        print(variant, samples[-1], flush=True)
    public = bytearray((out / "public_inputs").read_bytes())
    public[-1] ^= 1
    (t / "changed-inputs").write_bytes(public)
    call([BB, "verify", "-p", out / "proof", "-k", vk, "-i", t / "changed-inputs", *common],
         work, success=False)
    invalid = json.loads(json.dumps(inputs))
    invalid["signatures"][0][-1] ^= 1
    write_inputs(invalid, "Invalid")
    call([NARGO, "execute", "--prover-name", "Invalid"], work, success=False)
    if hashed:
        invalid = json.loads(json.dumps(inputs))
        invalid["payloads"][0][0] ^= 1
        write_inputs(invalid, "ChangedPayload")
        call([NARGO, "execute", "--prover-name", "ChangedPayload"], work, success=False)
    _, gates = call([BB, "gates", "-b", t / "benchmark.json", "-t", "noir-recursive"], work)
    result = dict(variant=variant, statement="Synthetic P-256/SHA-256 microbenchmark, not Huma replay",
                  noir="1.0.0-beta.25", bb="5.2.1", verifierTarget="noir-recursive", zeroKnowledge=True,
                  threads=2, nice=10, crs="cached for samples", vk="precomputed for samples",
                  initialCompileAndWitnessMs=compile_ms, setupAndFirstProofMs=setup_ms,
                  samples=samples, medianProveMs=statistics.median(x["proveMs"] for x in samples),
                  medianWitnessProveVerifyMs=statistics.median(sum(x[k] for k in ["witnessMs", "proveMs", "verifyMs"]) for x in samples),
                  gates=json.loads(gates), invalidSignatureRejected=True, tamperedPublicInputRejected=True,
                  changedPayloadRejected=True if hashed else None)
    (work / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=["p256-2", "p256-8", "checkpoint-2", "all"], default="all")
    parser.add_argument("--reps", type=int, default=3)
    a = parser.parse_args()
    if not 1 <= a.reps <= 20:
        parser.error("reps must be 1–20")
    for tool in [NARGO, BB]:
        if not tool.is_file():
            parser.error("Run prepare.py first")
    assert "1.0.0-beta.25" in call([NARGO, "--version"], ROOT)[1]
    assert call([BB, "--version"], ROOT)[1].strip() == "5.2.1"
    variants = ["p256-2", "checkpoint-2", "p256-8"] if a.variant == "all" else [a.variant]
    for v in variants:
        print(json.dumps(run(v, a.reps), indent=2), flush=True)
