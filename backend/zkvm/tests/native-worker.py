#!/usr/bin/env python3
"""Test the Mac's real service adapters in an app bundle with external networking denied."""
import json
import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser()
cached = parser.add_mutually_exclusive_group()
cached.add_argument('--reuse-proof', action='store_true')
cached.add_argument('--proof', type=Path)
parser.add_argument('--registry', action='store_true')
parser.add_argument('--publication', action='store_true')
parser.add_argument('--draft', type=Path, default=ROOT / 'backend/zkvm/common/tests/fixtures/swift-timed.json')
parser.add_argument('--output', type=Path, default=ROOT / 'build/Huma-mac-replay-public.json')
parser.add_argument('--app', type=Path, default=ROOT / 'build/Huma-next.app')
parser.add_argument('--probe', type=Path, default=ROOT / 'build/HumaReplayProbe.app')
options = parser.parse_args()
PROFILE = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
APP = options.app.resolve()
assert (APP / "Contents/Resources/ReplayEngine/huma-replay").is_file(), "Stage Huma-next.app first"
bin_dir = Path(subprocess.check_output(["swift", "build", "--package-path", "extra", "--scratch-path", ".build", "--show-bin-path"], cwd=ROOT, text=True).strip())
probe = options.probe.resolve()
exe = probe / "Contents/MacOS/HumaReplayProbe"
exe.parent.mkdir(parents=True, exist_ok=True)
resources = probe / "Contents/Resources"
if resources.is_symlink() and resources.resolve() != APP / "Contents/Resources": resources.unlink()
if not resources.exists(): resources.symlink_to(APP / "Contents/Resources", target_is_directory=True)
(probe / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "HumaReplayProbe",
    "CFBundleIdentifier": "dev.swayam.huma.replay-probe", "CFBundlePackageType": "APPL"}))
subprocess.run(["swiftc", "-parse-as-library", "-I", str(bin_dir),
    "extra/Sources/Huma/ReplayProofService.swift", "backend/zkvm/tests/native-worker.swift",
    str(bin_dir / "HumaCore.o"), "-o", str(exe)], cwd=ROOT, check=True)
# Prove the test profile is active before relying on an 'offline' success.
control = subprocess.run(["/usr/bin/sandbox-exec", "-p", PROFILE, "/usr/bin/python3", "-c",
    'import socket; s=socket.socket(); s.connect(("1.1.1.1",443))'], capture_output=True, text=True)
assert control.returncode != 0 and "Operation not permitted" in control.stderr, control.stderr
print("External network blocked; running native bundled-service proof test", flush=True)
env = os.environ.copy(); env.pop("HUMA_R0VM", None); env.pop("RISC0_DEV_MODE", None)
if not options.registry: env.pop("HUMA_TEST_REGISTRY", None)
if not options.publication: env.pop("HUMA_TEST_PUBLICATION", None)
arguments = ["/usr/bin/sandbox-exec", "-p", PROFILE, str(exe),
    str(options.draft.resolve()), str(options.output.resolve())]
if options.proof: arguments.append(str(options.proof.resolve()))
elif options.reuse_proof: arguments.append(str(ROOT / "build/Huma-replay-public.json"))
result = subprocess.run(arguments,
    env=env, cwd=ROOT, capture_output=not options.publication, text=True, timeout=1800)
if result.stdout: print(result.stdout, end="", flush=True)
if result.returncode:
    if result.stderr: print(result.stderr[:6000], flush=True)
    raise SystemExit(result.returncode)
