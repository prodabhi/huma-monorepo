#!/usr/bin/env python3
"""Prepare only public synthetic proofs for the independent reader acceptance suite."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMPACT = ROOT / 'extra/experiments/noir-compact'
import sys
sys.path.insert(0, str(COMPACT))
spec = importlib.util.spec_from_file_location('compact_export', COMPACT / 'export.py')
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)
work = ROOT / 'build/research/noir-compact/cast256'
out = ROOT / 'build/research/noir-compact-browser/fixtures'
out.mkdir(parents=True, exist_ok=True)
manifest = []
for name, origin in [
    ('Bucket50', 'build/research/noir-typing-fixtures/typing-50-current.json'),
    ('Bucket250', 'build/research/noir-typing-fixtures/typing-250-current.json'),
    ('BucketUnicode', 'backend/zkvm/common/tests/fixtures/swift-timed.json'),
]:
    text = json.loads((ROOT / origin).read_bytes())['text']
    public, checked = exporter.public_export(work, work / f'target/{name}-8-threads', work / f'{name}-capsule.json', text)
    (out / f'{name}.json').write_text(json.dumps(public, ensure_ascii=False) + '\n')
    manifest.append(dict(name=name, proofIdentity=checked['proofIdentity'], keyHash=checked['keyHash'], signatures=len(public['signatures']), elapsedMillis=str(checked['journal']['elapsed'])))
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(dict(prepared=len(manifest), nativeVerified=True, publicFixturesOnly=True)))
