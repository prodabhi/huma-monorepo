#!/usr/bin/env python3
"""Size existing replay components. These isolated relations are NOT Huma proofs."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import fixture

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
WORK = ROOT / "build/research/noir-replay-components"
TOOLS = ROOT / "build/research/noir-tools"


def digest(data):
    return list(hashlib.sha256(bytes(data)).digest())


def call(args, cwd, env):
    start = time.monotonic()
    p = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                       capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise RuntimeError(p.stderr[-2000:] + p.stdout[-1000:])
    return round((time.monotonic()-start)*1000, 2), p.stdout


if __name__ == "__main__":
    inputs = json.loads((ROOT / "build/research/noir-replay/inputs.json").read_text())
    main = (HERE / "src/main.nr").read_text().split("fn main(", 1)[0]
    sample = inputs["samples"][0]
    edit = inputs["edits"][0]
    capture = inputs["captures"][0]
    checkpoint = inputs["checkpoints"][1]
    definitions = {
        "sample": ("fn main(s: Sample, expected: pub [u8;32]) { assert(sample_digest(s) == expected); }",
                   dict(s=sample, expected=digest(sample["payload_bytes"]["data"][:sample["payload_bytes"]["len"]]))),
        "capture": ("fn main(c: Capture, expected: pub [u8;32]) { assert(capture_digest(c) == expected); }",
                    dict(c=capture, expected=capture["head"])),
        "edit_json": ("fn main(e: Edit, expected: pub [u8;32]) { assert(edit_digest(e) == expected); }",
                      dict(e=edit, expected=edit["head"])),
        "text_edit": ("""fn main(before: Bytes<64>, e: Edit, expected: pub [u8;32]) {
            utf8(before); utf8(e.inserted);
            assert(replace(before, e.location, e.removed, e.inserted).hash() == expected);
        }""", dict(before=inputs["initial"], e=edit, expected=edit["text_hash"])),
        "checkpoint": ("""fn main(c: Checkpoint, id: Bytes<36>, expected: pub [u8;32]) {
            utf8(id); utf8(c.challenge); assert(c.public_key[0] == 4);
            let payload = checkpoint_payload(c, id, false, base64_key(c.public_key));
            let mut x = [0u8;32]; let mut y = [0u8;32];
            for i in 0..32 { x[i] = c.public_key[i+1]; y[i] = c.public_key[i+33]; }
            assert(std::ecdsa_secp256r1::verify_signature(x,y,signature::normalized(c.signature),payload.hash()));
            concatenated(c.signed_bytes, payload, c.signature);
            assert(c.signed_bytes.hash() == expected);
        }""", dict(c=checkpoint, id=inputs["id"], expected=digest(checkpoint["signed_bytes"]["data"][:checkpoint["signed_bytes"]["len"]]))),
    }
    env = dict(os.environ, RAYON_NUM_THREADS="2", HARDWARE_CONCURRENCY="2")
    assert call([TOOLS / "bb/bb", "--version"], ROOT, env)[1].strip() == "5.2.1"
    results = []
    for name, (entry, data) in definitions.items():
        parsed = re.fullmatch(r"fn main\((.*?)\) \{(.*)\}", entry, re.S)
        if parsed is None:
            raise ValueError("Invalid component wrapper")
        fields = [arg.strip().split(": ", 1) for arg in parsed[1].split(",")]
        for count in [1, 8]:
            params = ", ".join(f"{key}: {'pub ' if kind.startswith('pub ') else ''}[{kind.removeprefix('pub ')};{count}]" for key,kind in fields)
            locals_ = " ".join(f"let {key} = {key}[i];" for key,_ in fields)
            wrapper = f"fn main({params}) {{ for i in 0..{count} {{ {locals_} {parsed[2]} }} }}"
            values = {key: [value] * count for key,value in data.items()}
            work = WORK / f"{name}-{count}"
            shutil.copytree(HERE / "src", work / "src", dirs_exist_ok=True)
            (work / "src/main.nr").write_text(main + "\n" + wrapper + "\n")
            (work / "Nargo.toml").write_text('[package]\nname = "component"\ntype = "bin"\nauthors = []\n'
                f'[dependencies]\nsha256 = {{ path = "{ROOT / "build/research/noir-sha256"}" }}\n')
            (work / "Prover.toml").write_text("\n".join(k + " = " + fixture.toml(v) for k,v in values.items()) + "\n")
            compile_ms, _ = call(["/usr/bin/nice", "-n", "10", TOOLS / "noir/nargo", "execute"], work, env)
            gates_ms, raw = call([TOOLS / "worker-bench", TOOLS / "bb/bb", "gates",
                                  "-b", work / "target/component.json", "-t", "noir-recursive"], work, env)
            gate_report = json.loads(raw)["result"]
            result = dict(component=name, multiplicity=count, compileAndWitnessMs=compile_ms,
                          gateCounterWallMs=gates_ms, gates=gate_report)
            results.append(result)
            print(json.dumps(result), flush=True)
    report = dict(experimental=True, componentSizingOnly=True, proofGenerated=False,
                  note="Isolated component circuits; gate costs are not additive because shared checks/overhead differ.",
                  bb="5.2.1", noir="1.0.0-beta.25", threads=2, nice=10,
                  sourceSha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE / "src").glob('*.nr')},
                  results=results)
    (WORK / "results.json").write_text(json.dumps(report, indent=2) + "\n")
