mod bytes;
mod signature;
use bytes::{Bytes, hex, decimal, boolean, field, base64_key, utf8, replace, canonical_length, json_start, json_end, concatenated, plain_field, base64_field};

// First bounded feasibility bucket, matching the public Swift regression fixture.
global EDITS: u32 = 5;
global SAMPLES: u32 = 10;
global CAPTURES: u32 = 15;
global CHECKPOINTS: u32 = 3;

struct Edit {
    sequence: u32, elapsed: u64, source: Bytes<8>, location: u32, removed: u32,
    inserted: Bytes<32>, payload_bytes: Bytes<448>, previous: [u8;32], text_hash: [u8;32], head: [u8;32],
}
struct Sample { down: bool, key_code: u16, modifiers: u64, elapsed: u64, payload_bytes: Bytes<64> }
struct Capture { sequence: u32, is_edit: bool, index: u32, payload: [u8;32], previous: [u8;32], head: [u8;32], payload_bytes: Bytes<160> }
struct Checkpoint {
    sequence: u32, final_seal: bool, capture_count: u32, edit_count: u32, sample_count: u32,
    capture_head: [u8;32], edit_head: [u8;32], text_hash: [u8;32], previous: [u8;32],
    challenge: Bytes<32>, public_key: [u8;65], signature: Bytes<72>, payload_bytes: Bytes<640>, signed_bytes: Bytes<768>, unix: u64, elapsed: u64,
}
struct Journal {
    raw_text_hash: [u8;32], verified_text_hash: [u8;32], session_id_hash: [u8;32],
    edit_head: [u8;32], capture_head: [u8;32], checkpoint_hash: [u8;32], key_hash: [u8;32],
    start_unix: u64, end_unix: u64, elapsed: u64, clock_moved_backwards: bool,
    byte_length: u32, raw_byte_length: u32, initial_byte_length: u32,
    edit_count: u32, sample_count: u32, capture_count: u32, checkpoint_count: u32,
    paste_edits: u32, typing_edits: u32,
}

fn edit_digest(e: Edit) -> [u8;32] {
    let out = e.payload_bytes; let mut cursor = json_start(out);
    cursor = plain_field(out, cursor, decimal(e.sequence as u64), true);
    cursor = plain_field(out, cursor, decimal(e.elapsed), false);
    cursor = field(out, cursor, e.source, false);
    cursor = plain_field(out, cursor, decimal(e.location as u64), false);
    cursor = plain_field(out, cursor, decimal(e.removed as u64), false);
    cursor = field(out, cursor, e.inserted, false);
    cursor = plain_field(out, cursor, hex(e.previous), false);
    cursor = plain_field(out, cursor, hex(e.text_hash), false); json_end(out, cursor); out.hash()
}
fn sample_digest(s: Sample) -> [u8;32] {
    let kind = if s.down { Bytes::<4>::fixed("down".as_bytes()) }
        else { Bytes::<4>::empty().add(Bytes::fixed("up".as_bytes())) };
    let out = s.payload_bytes; let mut cursor = plain_field(out, json_start(out), kind, true);
    cursor = plain_field(out, cursor, decimal(s.key_code as u64), false);
    cursor = plain_field(out, cursor, decimal(s.modifiers), false);
    cursor = plain_field(out, cursor, decimal(s.elapsed), false); json_end(out, cursor); out.hash()
}
fn capture_digest(c: Capture) -> [u8;32] {
    let kind = if c.is_edit { Bytes::<4>::fixed("edit".as_bytes()) }
        else { Bytes::<4>::empty().add(Bytes::fixed("key".as_bytes())) };
    let out = c.payload_bytes; let mut cursor = plain_field(out, json_start(out), decimal(c.sequence as u64), true);
    cursor = plain_field(out, cursor, kind, false);
    cursor = plain_field(out, cursor, decimal(c.index as u64), false);
    cursor = plain_field(out, cursor, hex(c.payload), false);
    cursor = plain_field(out, cursor, hex(c.previous), false); json_end(out, cursor); out.hash()
}
fn checkpoint_payload(c: Checkpoint, id: Bytes<36>, first: bool, key_b64: Bytes<88>) -> Bytes<640> {
    let out = c.payload_bytes; let mut cursor = plain_field(out, json_start(out), Bytes::fixed("huma-signed-checkpoint-v2".as_bytes()), true);
    cursor = plain_field(out, cursor, Bytes::fixed("unattested-p256".as_bytes()), false);
    cursor = field(out, cursor, id, false);
    cursor = plain_field(out, cursor, decimal(c.sequence as u64), false);
    cursor = plain_field(out, cursor, boolean(c.final_seal), false);
    cursor = plain_field(out, cursor, decimal(c.capture_count as u64), false);
    cursor = plain_field(out, cursor, decimal(c.edit_count as u64), false);
    cursor = plain_field(out, cursor, decimal(c.sample_count as u64), false);
    cursor = plain_field(out, cursor, hex(c.capture_head), false);
    cursor = plain_field(out, cursor, hex(c.edit_head), false);
    cursor = plain_field(out, cursor, hex(c.text_hash), false);
    cursor = plain_field(out, cursor, if first { Bytes::<64>::empty() } else { hex(c.previous) }, false);
    cursor = field(out, cursor, c.challenge, false);
    cursor = base64_field(out, cursor, key_b64);
    cursor = plain_field(out, cursor, Bytes::fixed("device-clock-v1".as_bytes()), false);
    cursor = plain_field(out, cursor, decimal(c.unix), false);
    cursor = plain_field(out, cursor, decimal(c.elapsed), false); json_end(out, cursor); out
}

fn main(id: Bytes<36>, initial: Bytes<64>, text: Bytes<64>, edits: [Edit;EDITS],
    samples: [Sample;SAMPLES], captures: [Capture;CAPTURES], checkpoints: [Checkpoint;CHECKPOINTS],
    expected: pub Journal) {
    utf8(id); assert(id.len > 0); utf8(initial); utf8(text);
    let initial_head = Bytes::<128>::empty().add(Bytes::fixed("huma-session-v1:".as_bytes()))
        .add(id).push(58).add(initial).hash();
    let seed = Bytes::<128>::empty().add(Bytes::fixed("huma-capture-v1:".as_bytes()))
        .add(id).push(58).add(hex(initial_head)).hash();
    let mut edit_heads = [[0u8;32];EDITS+1]; edit_heads[0] = initial_head;
    let mut text_hashes = [[0u8;32];EDITS+1]; text_hashes[0] = initial.hash();
    let mut edit_times = [0u64;EDITS];
    let mut previous_elapsed = 0;
    let mut current_text = initial;
    let mut paste_edits = 0;
    let mut typing_edits = 0;
    for i in 0..EDITS {
        let e = edits[i]; utf8(e.source); utf8(e.inserted);
        assert(e.sequence == i); assert(e.previous == edit_heads[i]);
        assert(e.elapsed >= previous_elapsed); previous_elapsed = e.elapsed;
        current_text = replace(current_text, e.location, e.removed, e.inserted);
        assert(e.text_hash == current_text.hash());
        assert(e.head == edit_digest(e));
        edit_heads[i+1] = e.head; text_hashes[i+1] = e.text_hash;
        edit_times[i] = e.elapsed;
        paste_edits += e.source.equals(Bytes::fixed("paste".as_bytes())) as u32;
        typing_edits += e.source.equals(Bytes::fixed("typing".as_bytes())) as u32;
    }
    assert(current_text.equals(text));
    let mut sample_hashes = [[0u8;32];SAMPLES];
    let mut sample_times = [0u64;SAMPLES];
    for i in 0..SAMPLES {
        sample_hashes[i] = sample_digest(samples[i]);
        sample_times[i] = samples[i].elapsed;
    }
    let mut capture_heads = [[0u8;32];CAPTURES+1]; capture_heads[0] = seed;
    let mut edit_counts = [0u32;CAPTURES+1];
    let mut sample_counts = [0u32;CAPTURES+1];
    let mut capture_times = [0u64;CAPTURES+1];
    for i in 0..CAPTURES {
        let c = captures[i];
        assert(c.sequence == i); assert(c.previous == capture_heads[i]);
        let mut edit_count = edit_counts[i]; let mut sample_count = sample_counts[i];
        let mut elapsed = 0;
        if c.is_edit {
            assert((c.index == edit_count) & (edit_count < EDITS));
            assert(c.payload == edit_heads[edit_count+1]);
            elapsed = edit_times[edit_count]; edit_count += 1;
        } else {
            assert((c.index == sample_count) & (sample_count < SAMPLES));
            assert(c.payload == sample_hashes[sample_count]);
            elapsed = sample_times[sample_count]; sample_count += 1;
        }
        assert(elapsed >= capture_times[i]);
        assert(c.head == capture_digest(c)); capture_heads[i+1] = c.head;
        edit_counts[i+1] = edit_count; sample_counts[i+1] = sample_count; capture_times[i+1] = elapsed;
    }
    assert(edit_counts[CAPTURES] == EDITS); assert(sample_counts[CAPTURES] == SAMPLES);
    let key = checkpoints[0].public_key; assert(key[0] == 4);
    let mut x = [0u8;32]; let mut y = [0u8;32];
    for i in 0..32 { x[i] = key[i+1]; y[i] = key[i+33]; }
    let key_b64 = base64_key(key);
    let mut previous = [0u8;32];
    let mut previous_count = 0;
    let mut previous_time = 0;
    let mut previous_unix = 0;
    let mut rollback = false;
    for i in 0..CHECKPOINTS {
        let c = checkpoints[i]; utf8(c.challenge);
        assert(c.sequence == i); assert(c.previous == previous); assert(c.public_key == key);
        assert((c.capture_count >= previous_count) & (c.capture_count <= CAPTURES));
        let edit_count = edit_counts[c.capture_count];
        assert(c.edit_count == edit_count); assert(c.sample_count == sample_counts[c.capture_count]);
        assert(c.capture_head == capture_heads[c.capture_count]); assert(c.edit_head == edit_heads[edit_count]);
        assert(c.text_hash == text_hashes[edit_count]);
        assert((c.unix <= 253402300799999) & (c.elapsed >= previous_time));
        assert(c.elapsed >= capture_times[c.capture_count]);
        if i == 0 { assert((c.capture_count == 0) & (c.elapsed == 0)); }
        else { rollback |= c.unix < previous_unix; }
        let payload = checkpoint_payload(c, id, i == 0, key_b64);
        assert(std::ecdsa_secp256r1::verify_signature(x, y, signature::normalized(c.signature), payload.hash()));
        concatenated(c.signed_bytes, payload, c.signature);
        previous = c.signed_bytes.hash();
        previous_count = c.capture_count; previous_time = c.elapsed; previous_unix = c.unix;
    }
    let last = checkpoints[CHECKPOINTS-1];
    assert(last.final_seal & (last.capture_count == CAPTURES) & (last.text_hash == text.hash()));
    let canonical_len = canonical_length(text); assert(canonical_len > 0);
    let canonical = Bytes { data: text.data, len: canonical_len };
    assert(expected.raw_text_hash == text.hash()); assert(expected.verified_text_hash == canonical.hash());
    assert(expected.session_id_hash == id.hash()); assert(expected.edit_head == edit_heads[EDITS]);
    assert(expected.capture_head == capture_heads[CAPTURES]); assert(expected.checkpoint_hash == previous);
    assert(expected.key_hash == sha256::digest(key));
    assert(expected.start_unix == checkpoints[0].unix); assert(expected.end_unix == last.unix);
    assert(expected.elapsed == last.elapsed); assert(expected.clock_moved_backwards == rollback);
    assert(expected.byte_length == canonical_len); assert(expected.raw_byte_length == text.len);
    assert(expected.initial_byte_length == initial.len); assert(expected.edit_count == EDITS);
    assert(expected.sample_count == SAMPLES); assert(expected.capture_count == CAPTURES);
    assert(expected.checkpoint_count == CHECKPOINTS); assert(expected.paste_edits == paste_edits);
    assert(expected.typing_edits == typing_edits);
}
