#!/usr/bin/env python3
"""Translate a bounded public native V2 fixture without re-signing or dropping records."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / "build/research/noir-replay"


def bounded(text, capacity):
    data = list(text.encode("utf-8"))
    if len(data) > capacity:
        raise ValueError(f"Fixture exceeds byte capacity {capacity}")
    return {"data": data + [0] * (capacity - len(data)), "len": len(data)}


def digest(text):
    if not re.fullmatch("[0-9a-f]{64}", text):
        raise ValueError("Expected canonical SHA-256 digest")
    return list(bytes.fromhex(text))


def binary(text):
    data = base64.b64decode(text, validate=True)
    if base64.b64encode(data).decode() != text:
        raise ValueError("Noncanonical base64")
    return list(data)


def packed(data, capacity):
    if len(data) > capacity: raise ValueError("Serialized payload exceeds bucket capacity")
    return {"data": list(data) + [0]*(capacity-len(data)), "len": len(data)}


def array(values):
    return json.dumps([str(x).lower() if isinstance(x, bool) else str(x) for x in values], ensure_ascii=False, separators=(",", ":")).replace("/", "\\/").encode()


def native(witness):
    worker = ROOT / "backend/zkvm/target/release/huma-replay"
    env = dict(os.environ, HUMA_R0VM=str(ROOT / "build/toolchains/risc0/bin/r0vm"), RAYON_NUM_THREADS="2")
    p = subprocess.run([str(worker)], input=json.dumps({"command": "execute", "witness": witness}),
                       text=True, capture_output=True, env=env, timeout=30)
    r = json.loads(p.stdout)
    if p.returncode != 0 or not r["ok"]:
        raise ValueError("Native reference rejected fixture")
    return r["result"]


def convert(w, journal, *, counts=(5,10,15,3), insert_capacity=32, edit_payload_capacity=448):
    s = w["session"]
    if tuple(len(s[k]) for k in ["events", "inputSamples", "captureRecords", "signedCheckpoints"]) != counts:
        raise ValueError(f"Fixture does not match exact-count circuit bucket {counts}")
    edits = [{"sequence": e["sequence"], "elapsed": e["elapsedMilliseconds"], "source": bounded(e["source"], 8),
              "location": e["location"], "removed": e["removedLength"], "inserted": bounded(e["insertedText"], insert_capacity),
              "payload_bytes": packed(array([e[k] for k in ["sequence", "elapsedMilliseconds", "source", "location", "removedLength", "insertedText", "previousHead", "textHash"]]), edit_payload_capacity), "previous": digest(e["previousHead"]), "text_hash": digest(e["textHash"]), "head": digest(e["head"])} for e in s["events"]]
    samples = []
    for x in s["inputSamples"]:
        if x["kind"] not in ["down", "up"]:
            raise ValueError("Unknown sample kind")
        samples.append({"down": x["kind"] == "down", "key_code": x["keyCode"], "modifiers": x["modifiers"], "elapsed": x["elapsedMilliseconds"], "payload_bytes": packed(array([x[k] for k in ["kind", "keyCode", "modifiers", "elapsedMilliseconds"]]), 64)})
    captures = []
    for c in s["captureRecords"]:
        if c["kind"] not in ["key", "edit"]:
            raise ValueError("Unknown capture kind")
        captures.append({"sequence": c["sequence"], "is_edit": c["kind"] == "edit", "index": c["index"],
                         "payload_bytes": packed(array([c[k] for k in ["sequence", "kind", "index", "payloadHash", "previousHead"]]), 160), "payload": digest(c["payloadHash"]), "previous": digest(c["previousHead"]), "head": digest(c["head"])})
    checkpoints = []
    for c in s["signedCheckpoints"]:
        if c["version"] != 2 or c["kind"] != "unattested-p256" or c["sessionID"] != s["id"]:
            raise ValueError("Expected matching native V2 checkpoint")
        sig = binary(c["signature"])
        if len(sig) > 72:
            raise ValueError("DER exceeds P-256 capacity")
        key = binary(c["publicKey"])
        if len(key) != 65:
            raise ValueError("SEC1 key must be 65 bytes")
        payload = array(["huma-signed-checkpoint-v2", c["kind"], c["sessionID"], c["sequence"], c["isFinal"], c["captureCount"], c["editCount"], c["sampleCount"], c["captureHead"], c["editHead"], c["textHash"], c["previousCheckpoint"], c["challenge"], c["publicKey"], "device-clock-v1", c["reportedTime"]["unixMilliseconds"], c["reportedTime"]["elapsedMilliseconds"]])
        checkpoints.append({"payload_bytes": packed(payload, 640), "signed_bytes": packed(payload + bytes(sig), 768),"sequence": c["sequence"], "final_seal": c["isFinal"], "capture_count": c["captureCount"],
                            "edit_count": c["editCount"], "sample_count": c["sampleCount"], "capture_head": digest(c["captureHead"]),
                            "edit_head": digest(c["editHead"]), "text_hash": digest(c["textHash"]),
                            "previous": digest(c["previousCheckpoint"]) if c["previousCheckpoint"] else [0]*32,
                            "challenge": bounded(c["challenge"], 32), "public_key": key,
                            "signature": {"data": sig + [0]*(72-len(sig)), "len": len(sig)},
                            "unix": c["reportedTime"]["unixMilliseconds"], "elapsed": c["reportedTime"]["elapsedMilliseconds"]})
    expected = {dest: digest(journal[src]) for dest, src in {
        "raw_text_hash": "rawTextHash", "verified_text_hash": "verifiedTextHash", "session_id_hash": "sessionIDHash",
        "edit_head": "editHead", "capture_head": "captureHead", "checkpoint_hash": "checkpointHash", "key_hash": "captureKeyHash"}.items()}
    t = journal["deviceReportedTime"]
    expected.update(start_unix=t["startUnixMilliseconds"], end_unix=t["endUnixMilliseconds"], elapsed=t["elapsedMilliseconds"],
                    clock_moved_backwards=t["clockMovedBackwards"])
    expected.update({dest: journal[src] for dest, src in {
        "byte_length": "byteLength", "raw_byte_length": "rawByteLength", "initial_byte_length": "initialByteLength",
        "edit_count": "editCount", "sample_count": "boundInputSamples", "capture_count": "captureRecordCount",
        "checkpoint_count": "signedCheckpointCount", "paste_edits": "pasteEditCount", "typing_edits": "typingLabeledEdits"}.items()})
    return dict(id=bounded(s["id"], 36), initial=bounded(s["initialText"], 64), text=bounded(w["text"], 64), edits=edits,
                samples=samples, captures=captures, checkpoints=checkpoints, expected=expected)


def toml(value):
    if isinstance(value, dict):
        return "{ " + ", ".join(k + " = " + toml(v) for k, v in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ",".join(toml(v) for v in value) + "]"
    if isinstance(value, int) and not isinstance(value, bool) and value > 2**63-1:
        return json.dumps(str(value))
    return json.dumps(value)


def write(value, name="Prover"):
    (WORK / (name + ".toml")).write_text("\n".join(k + " = " + toml(v) for k, v in value.items()) + "\n")


if __name__ == "__main__":
    witness = json.loads((ROOT / "backend/zkvm/common/tests/fixtures/swift-timed.json").read_text())
    reference = native(witness)
    WORK.mkdir(parents=True, exist_ok=True)
    inputs = convert(witness, reference["journal"])
    write(inputs)
    (WORK / "reference.json").write_text(json.dumps(reference, indent=2) + "\n")
    (WORK / "inputs.json").write_text(json.dumps(inputs) + "\n")
    print("Converted complete public signed Swift fixture; original DER and every capture retained")
