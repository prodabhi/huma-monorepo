#!/usr/bin/env python3
"""Black-box proof/verification checks using public software-key Swift fixtures."""
import copy
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
WORKER = ROOT / "backend/zkvm/target/release/huma-replay"
ENV = os.environ.copy()
ENV["HUMA_R0VM"] = str(ROOT / "build/toolchains/risc0/bin/r0vm")
ENV.pop("RISC0_DEV_MODE", None)

def call(request, success=True, env=ENV):
    proc = subprocess.run([str(WORKER)], input=json.dumps(request), text=True,
                          capture_output=True, env=env, timeout=1800)
    response = json.loads(proc.stdout)
    assert response["ok"] is success and (proc.returncode == 0) is success, proc.stderr
    return response.get("result", response)

witness = json.loads((ROOT / "backend/zkvm/common/tests/fixtures/swift-timed.json").read_text())
info = call({"command": "info"})
assert info["localOnly"] and not info["trustedCalendarTime"]
executed = call({"command": "execute", "witness": witness})
assert executed["executionOnly"] and not executed["verified"]
print("Guest executed:", executed["cycles"], "cycles; generating real local proof", flush=True)
started = time.monotonic()
proved = call({"command": "prove", "witness": witness})
bundle = proved["bundle"]
assert proved["verified"] and "Fake" not in bundle["receipt"]["inner"]
assert proved["journal"] == executed["journal"]
assert proved["journal"]["deviceReportedTime"]["elapsedMilliseconds"] == 15
request = {"command": "verify", "text": witness["text"], "bundle": bundle,
           "expectedCaptureKeyHash": proved["journal"]["captureKeyHash"]}
assert call(request)["verified"]
revealed = copy.deepcopy(request)
revealed["capturePublicKey"] = {"format": "p256-x963-base64", "value": witness["session"]["signedCheckpoints"][0]["publicKey"]}
revealed["session"] = witness["session"]
checks = call(revealed)["checks"]
assert checks["revealedKey"] and checks["revealedHistory"]
changed = copy.deepcopy(revealed); changed["capturePublicKey"]["value"] = witness["session"]["signedCheckpoints"][0]["signature"]; call(changed, False)
changed = copy.deepcopy(revealed); changed["session"]["events"][0]["insertedText"] += "!"; call(changed, False)
changed = copy.deepcopy(request); changed["text"] += " \t"
assert call(changed)["verified"]
changed = copy.deepcopy(request); changed["text"] += "!"; call(changed, False)
changed = copy.deepcopy(request); changed["expectedCaptureKeyHash"] = "0" * 64; call(changed, False)
changed = copy.deepcopy(request); changed["bundle"]["imageId"] = "0" * 64; call(changed, False)
changed = copy.deepcopy(request); changed["bundle"]["receipt"]["journal"]["bytes"][0] ^= 1; call(changed, False)
changed = copy.deepcopy(request)
inner = changed["bundle"]["receipt"]["inner"]
assert "Succinct" in inner
changed["bundle"]["receipt"]["inner"] = {"Fake": {"claim": inner["Succinct"]["claim"]}}
call(changed, False)
call({"command": "info"}, False, dict(ENV, RISC0_DEV_MODE="1"))
changed = copy.deepcopy(witness); changed["session"]["signedCheckpoints"][-1]["signature"] = "AA=="
call({"command": "prove", "witness": changed}, False)
# Only public text, public journal and the zero-knowledge receipt are exported.
output = ROOT / "build/Huma-replay-public.json"
output.write_text(json.dumps({"text": witness["text"], "bundle": bundle}, separators=(",", ":")))
print("PASS: local proof, known-key match, trailing policy, text/key/image/journal/fake/dev/tamper rejection", flush=True)
print("Elapsed:", round(time.monotonic() - started, 1), "seconds; public bundle:", output.stat().st_size, "bytes", flush=True)
