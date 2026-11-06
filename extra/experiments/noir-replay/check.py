#!/usr/bin/env python3
"""Exercise the full V2 replay relation's private-witness constraints."""
import copy
import json
import os
from pathlib import Path
import subprocess
import time
import fixture

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "build/research/noir-replay"
NARGO = ROOT / "build/research/noir-tools/noir/nargo"
ENV = dict(os.environ, RAYON_NUM_THREADS="2")


def execute(values, name, accepted):
    fixture.write(values, name)
    started = time.monotonic()
    p = subprocess.run(["/usr/bin/nice", "-n", "10", str(NARGO), "execute", name,
                        "--prover-name", name], cwd=WORK, env=ENV, text=True,
                       capture_output=True, timeout=45)
    if accepted:
        if p.returncode != 0 or "Circuit witness successfully solved" not in p.stdout:
            raise RuntimeError(p.stdout[-1000:] + p.stderr[-1000:])
    elif p.returncode == 0 or not any(x in p.stderr for x in ["Failed constraint", "Assertion failed"]):
        raise RuntimeError("Expected a constraint rejection: " + p.stdout[-1000:] + p.stderr[-1000:])
    result = dict(case=name, accepted=accepted, elapsedMs=round((time.monotonic()-started)*1000, 2))
    print(json.dumps(result), flush=True)
    return result


if __name__ == "__main__":
    original = json.loads((WORK / "inputs.json").read_text())
    results = [execute(original, "Valid", True)]
    cases = []

    def mutate(name, change):
        values = copy.deepcopy(original)
        change(values)
        cases.append((name, values))

    mutate("SplitSurrogate", lambda v: v["edits"][3].update(location=19))
    mutate("ChangedEdit", lambda v: v["edits"][1]["inserted"]["data"].__setitem__(0, 88))
    mutate("ChangedKeyTiming", lambda v: v["samples"][0].update(elapsed=999))
    mutate("WrongCaptureIndex", lambda v: v["captures"][0].update(index=1))
    mutate("WrongCaptureSequence", lambda v: v["captures"][1].update(sequence=0))
    mutate("WrongCheckpointPrefix", lambda v: v["checkpoints"][1].update(capture_count=10))
    mutate("ChangedClock", lambda v: v["checkpoints"][1].update(unix=1))
    mutate("ChangedKey", lambda v: v["checkpoints"][1]["public_key"].__setitem__(1, 0))
    mutate("ChangedDER", lambda v: v["checkpoints"][1]["signature"]["data"].__setitem__(10, 0))
    mutate("ChangedSignedBytes", lambda v: v["checkpoints"][2]["signed_bytes"]["data"].__setitem__(10, 0))
    mutate("MissingSeal", lambda v: v["checkpoints"][2].update(final_seal=False))
    mutate("ChangedPublicTextHash", lambda v: v["expected"]["verified_text_hash"].__setitem__(0, 0))
    mutate("ChangedPublicCounts", lambda v: v["expected"].update(paste_edits=0))

    def slash(v):
        b = v["edits"][2]["payload_bytes"]
        data = bytes(b["data"][:b["len"]])
        changed = data.replace(b"\\/", b"/", 1)
        assert changed != data
        b.update(fixture.packed(changed, 448))

    mutate("ChangedJSONEscaping", slash)
    for name, values in cases:
        results.append(execute(values, name, False))
    (WORK / "constraint-results.json").write_text(json.dumps(results, indent=2) + "\n")
