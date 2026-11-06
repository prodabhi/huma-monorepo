#!/usr/bin/env python3
"""Fetch pinned official experiment tools. No global installation or shell scripts."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request

BASE = Path(__file__).resolve().parents[2] / "build/research"
TOOLS = BASE / "noir-tools"
RELEASES = [
    ("noir-lang/noir", "v1.0.0-beta.25", "noir-aarch64-apple-darwin.tar.gz", "noir", "nargo",
     "5ddb45016c8e100d7e03d10e106803111c71a07a920441006cb4816d4a94f624"),
    ("AztecProtocol/aztec-packages", "v5.2.1", "barretenberg-arm64-darwin.tar.gz", "bb", "bb",
     "7a648eb578ea34d224357aba3e81df6b294fe23caf89f22ec9ad7536fbcc8a28"),
]
SHA_REV = "50f5fda729d94848aabcd9d54dc7751460e9143a"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Huma-local-benchmark"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


TOOLS.mkdir(parents=True, exist_ok=True)
for repo, tag, archive, folder, executable, expected in RELEASES:
    url = f"https://github.com/{repo}/releases/download/{tag}/{archive}"
    target = TOOLS / (tag + "-" + archive)
    if not target.exists():
        target.write_bytes(fetch(url))
    assert hashlib.sha256(target.read_bytes()).hexdigest() == expected, "Release checksum mismatch"
    destination = TOOLS / folder / executable
    destination.parent.mkdir(exist_ok=True)
    with tarfile.open(target) as files:
        candidates = [m for m in files.getmembers() if m.isfile() and PurePosixPath(m.name).name == executable]
        assert len(candidates) == 1
        destination.write_bytes(files.extractfile(candidates[0]).read())
    destination.chmod(0o755)
    print(tag, expected, flush=True)

# Immutable library revision; validate each downloaded source against its Git blob ID.
tree = json.loads(fetch(f"https://api.github.com/repos/noir-lang/sha256/git/trees/{SHA_REV}?recursive=1"))
assert not tree.get("truncated")
for item in tree["tree"]:
    path = PurePosixPath(item["path"])
    if item["type"] != "blob" or not (str(path) == "Nargo.toml" or (path.parts[0] == "src" and path.suffix == ".nr")):
        continue
    assert not path.is_absolute() and ".." not in path.parts
    destination = BASE / "noir-sha256" / path
    data = fetch(f"https://raw.githubusercontent.com/noir-lang/sha256/{SHA_REV}/{path}")
    assert hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest() == item["sha"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
print("SHA-256 library", SHA_REV)
