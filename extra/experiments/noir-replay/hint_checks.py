#!/usr/bin/env python3
"""Show that malicious decimal hints cannot bypass the constrained validator."""
import json
import os
from pathlib import Path
import subprocess
import fixture

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent / "src/bytes.nr"
WORK = ROOT / "build/research/noir-decimal-hint-tests"
NARGO = ROOT / "build/research/noir-tools/noir/nargo"
ENV = dict(os.environ, RAYON_NUM_THREADS="2")


def test(value, digits, length, accepted, label):
    inputs = {"value": value, "expected": digits, "len": length}
    (WORK / "Prover.toml").write_text("\n".join(k + " = " + fixture.toml(v) for k, v in inputs.items()))
    p = subprocess.run([str(NARGO), "execute"], cwd=WORK, env=ENV, text=True, capture_output=True, timeout=30)
    if accepted:
        if p.returncode != 0:
            raise RuntimeError(p.stderr[-1000:])
    elif p.returncode == 0 or not any(x in p.stderr for x in ["Failed constraint", "Assertion failed"]):
        raise RuntimeError("Expected validator constraint rejection: " + p.stderr[-1000:])
    print(label, "accepted" if accepted else "rejected", flush=True)
    return {"case": label, "accepted": accepted}


if __name__ == "__main__":
    (WORK / "src").mkdir(parents=True, exist_ok=True)
    (WORK / "Nargo.toml").write_text('[package]\nname="decimal_hint_checks"\ntype="bin"\nauthors=[]\ncompiler_version=">=1.0.0"\n[dependencies]\nsha256={path="../noir-sha256"}\n')
    (WORK / "src/main.nr").write_text('mod bytes;\nfn main(value: u64, expected: pub [u8;20], len: pub u32) { let result = bytes::decimal(value); assert(result.data == expected); assert(result.len == len); }\n')
    source = SOURCE.read_text()
    (WORK / "src/bytes.nr").write_text(source)
    results = []
    for value in [0, 1, 9, 10, 253402300799999, 18446744073709551615]:
        digits = list(str(value).encode())
        results.append(test(value, digits+[0]*(20-len(digits)), len(digits), True, str(value)))
    # Only replace the untrusted hint, leaving every constraint unchanged. Match
    # the outer public expectation to the bad hint so rejection tests the inner
    # validator, rather than an unrelated output comparison.
    start = source.index("unconstrained fn decimal_hint(")
    end = source.index("\npub fn decimal(", start)
    malicious = [(9, b"8", 1, "WrongValue"), (9, b"09", 2, "LeadingZero"),
                 (49, b"a", 1, "NonDigit"), (0, b"", 0, "Empty"),
                 (9, b"9\x01", 1, "NonzeroPadding"),
                 (0, b"18446744073709551616", 20, "AboveU64")]
    for value, raw, length, label in malicious:
        data = list(raw)+[0]*(20-len(raw))
        hint = f"unconstrained fn decimal_hint(_value: u64) -> Bytes<20> {{ Bytes {{ data: {json.dumps(data)}, len: {length} }} }}\n"
        (WORK / "src/bytes.nr").write_text(source[:start] + hint + source[end:])
        results.append(test(value, data, length, False, label))
    (WORK / "src/bytes.nr").write_text(source)
    (WORK / "results.json").write_text(json.dumps(results, indent=2)+"\n")
