#!/usr/bin/env python3
"""Verify the local experimental circuit, then bind public fields to a reader's text/key."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / "build/research/noir-replay"
BB = ROOT / "build/research/noir-tools/bb/bb"


def decode(kind, values):
    if kind["kind"] == "array":
        return [decode(kind["type"], values) for _ in range(kind["length"])]
    if kind["kind"] == "struct":
        return {field["name"]: decode(field["type"], values) for field in kind["fields"]}
    value = next(values)
    if kind["kind"] == "boolean":
        if value not in [0, 1]:
            raise ValueError("Noncanonical public boolean")
        return bool(value)
    if kind["kind"] != "integer" or not 0 <= value < 2**kind["width"]:
        raise ValueError("Public value outside its declared integer range")
    return value


def verify(proof_dir, text=None, expected_key=None, *, trusted_circuit_dir=WORK):
    # Trust the locally built source/ABI/VK, never a VK supplied by a proof bundle.
    abi = json.loads((trusted_circuit_dir / "target/huma_replay_experiment.json").read_text())["abi"]
    public = [p for p in abi["parameters"] if p["visibility"] == "public"]
    if len(public) != 1 or public[0]["name"] != "expected":
        raise ValueError("Unexpected local experimental circuit ABI")
    proof = proof_dir / "proof"
    inputs = proof_dir / "public_inputs"
    if not 0 < proof.stat().st_size <= 65536 or not 0 < inputs.stat().st_size <= 16384:
        raise ValueError("Experimental proof exceeds bounds")
    raw = inputs.read_bytes()
    if len(raw) % 32:
        raise ValueError("Truncated public input")
    values = iter(int.from_bytes(raw[i:i+32], "big") for i in range(0, len(raw), 32))
    journal = decode(public[0]["type"], values)
    if next(values, None) is not None:
        raise ValueError("Unexpected extra public inputs")
    env = dict(os.environ, HARDWARE_CONCURRENCY="2")
    version = subprocess.check_output([str(BB), "--version"], text=True, env=env).strip()
    if version != "5.2.1":
        raise ValueError("Expected patched Barretenberg 5.2.1")
    p = subprocess.run([str(BB), "verify", "-p", str(proof), "-i", str(inputs),
                        "-k", str(trusted_circuit_dir / "target/setup/vk"), "-t", "noir-recursive",
                        "-c", str(ROOT / "build/research/noir-crs")],
                       capture_output=True, text=True, env=env, timeout=15)
    if p.returncode != 0:
        raise ValueError("Cryptographic proof verification failed")
    if text is not None:
        canonical = text.rstrip(" \t").encode("utf-8")
        if hashlib.sha256(canonical).digest() != bytes(journal["verified_text_hash"]) or len(canonical) != journal["byte_length"]:
            raise ValueError("Reader text differs from proven text")
    if expected_key is not None:
        if not re.fullmatch("[0-9a-f]{64}", expected_key) or expected_key != bytes(journal["key_hash"]).hex():
            raise ValueError("Capture key differs from reader's expected key")
    return journal


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof-dir", type=Path, default=WORK / "target/proof")
    parser.add_argument("--text-file", type=Path)
    parser.add_argument("--expected-key-hash")
    parser.add_argument("--trusted-circuit-dir", type=Path, default=WORK,
                        help="Reader-chosen locally built ABI/VK directory, never a key from the proof file")
    a = parser.parse_args()
    try:
        text = a.text_file.read_bytes().decode("utf-8") if a.text_file else None
        journal = verify(a.proof_dir.resolve(), text, a.expected_key_hash,
                         trusted_circuit_dir=a.trusted_circuit_dir.resolve())
        print(json.dumps({"verified": True, "experimental": True, "journal": journal,
                          "trustedCalendarTime": False, "manufacturerAttestation": False}, indent=2))
    except (ValueError, OSError, subprocess.SubprocessError, StopIteration) as error:
        parser.exit(1, str(error) + "\n")
