#!/usr/bin/env python3
"""Download the pinned official Node runtime locally; no global installation."""
import hashlib,tarfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
VERSION='24.22.1'
ARCHIVE=f'node-v{VERSION}-darwin-arm64.tar.gz'
SHA256='89c682593d76cd44233fa53b1563264e7de9cbb189cad169135c5b4fadfbc0a7'
base=ROOT/'build/research/noir-tools';base.mkdir(parents=True,exist_ok=True)
archive=base/ARCHIVE
if not archive.exists():
    request=urllib.request.Request(f'https://nodejs.org/dist/v{VERSION}/{ARCHIVE}',headers={'User-Agent':'Huma-build'})
    with urllib.request.urlopen(request,timeout=45) as response:data=response.read(64*1024*1024+1)
    if len(data)>64*1024*1024:raise SystemExit('Runtime archive exceeds build limit')
    if hashlib.sha256(data).hexdigest()!=SHA256:raise SystemExit('Official runtime checksum mismatch')
    archive.write_bytes(data)
if hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA256:raise SystemExit('Runtime archive checksum mismatch')
with tarfile.open(archive) as t:
    data=t.extractfile(f'node-v{VERSION}-darwin-arm64/bin/node').read()
out=base/'node24/node';out.parent.mkdir(exist_ok=True);out.write_bytes(data);out.chmod(0o755)
print(f'Prepared official Node {VERSION}, checksum verified; no app or account started.')
