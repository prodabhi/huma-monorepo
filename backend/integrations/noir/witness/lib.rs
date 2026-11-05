//! Noir's own solver (v1.0.0-beta.25) for Huma's programs: inputs as JSON in, the gzipped witness stack bb reads out.
//! Same steps and output bytes as noir_js's `execute` (abiEncode, executeProgram, compressWitnessStack). The Mac
//! engine runs it as the `witness` tool (main.rs); browsers run it as WebAssembly (`huma_witness`, below).
//! No foreign calls and no network. Errors name only the step, never inputs or values.
use std::collections::BTreeMap;
use std::io::Read;

use acvm::acir::circuit::{Circuit, Program};
use acvm::acir::native_types::{WitnessMap, WitnessStack};
use acvm::acir::SerializationFormat;
use acvm::pwg::{ACVMStatus, ACVM};
use acvm::FieldElement;
use base64::Engine;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use noirc_abi::input_parser::{json::JsonTypes, InputValue};
use noirc_abi::Abi;

// The largest input the worker sends (a part, 4 MB base64) with room; programs are under 20 MB.
pub const MAX_INPUT: u64 = 64 << 20;
pub const MAX_PROGRAM: u64 = 64 << 20;

#[derive(serde::Deserialize)]
struct Artifact {
    bytecode: String,
    abi: Abi,
}

pub fn read_limited(reader: impl Read, limit: u64, step: &'static str) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes).map_err(|_| step)?;
    if bytes.len() as u64 > limit {
        return Err(step);
    }
    Ok(bytes)
}

/// Solves `circuit` and every circuit it calls, pushing each call's witness the way acvm_js does.
fn solve(
    program: &Program<FieldElement>,
    index: usize,
    initial: WitnessMap<FieldElement>,
    stack: &mut WitnessStack<FieldElement>,
) -> Result<WitnessMap<FieldElement>, &'static str> {
    let circuit: &Circuit<FieldElement> = program.functions.get(index).ok_or("call")?;
    let mut acvm = ACVM::new(
        &Bn254BlackBoxSolver,
        &circuit.opcodes,
        initial,
        &program.unconstrained_functions,
        &circuit.assert_messages,
    );
    loop {
        match acvm.solve() {
            ACVMStatus::Solved => break,
            // Huma's programs make no oracle calls (noir_js's handler refused them too).
            ACVMStatus::RequiresForeignCall(_) => return Err("foreign calls disabled"),
            ACVMStatus::RequiresAcirCall(call) => {
                let id = call.id.as_usize();
                let solved = solve(program, id, call.initial_witness, stack)?;
                let callee = &program.functions[id];
                let outputs = callee
                    .return_values
                    .indices()
                    .into_iter()
                    .map(|w| solved.get_index(w).copied().ok_or("call output"))
                    .collect::<Result<Vec<_>, _>>()?;
                acvm.resolve_pending_acir_call(outputs);
                stack.push(call.id.as_u32(), solved);
            }
            ACVMStatus::Failure(_) => return Err("unsatisfied constraint"),
            ACVMStatus::InProgress => return Err("solver"),
        }
    }
    Ok(acvm.finalize())
}

/// The compressed witness stack for `program` (a compiled program's JSON) run on `input` (its inputs as JSON).
pub fn witness(program: &[u8], input: &[u8]) -> Result<Vec<u8>, &'static str> {
    if program.len() as u64 > MAX_PROGRAM || input.len() as u64 > MAX_INPUT {
        return Err("size");
    }
    let artifact: Artifact = serde_json::from_slice(program).map_err(|_| "program")?;
    let bytecode =
        base64::engine::general_purpose::STANDARD.decode(artifact.bytecode).map_err(|_| "program")?;
    let program = Program::<FieldElement>::deserialize_program(&bytecode).map_err(|_| "program")?;

    // abiEncode: every parameter present, each value checked against its declared type.
    let given: BTreeMap<String, JsonTypes> = serde_json::from_slice(input).map_err(|_| "input")?;
    let mut inputs = BTreeMap::new();
    for (name, typ) in artifact.abi.to_btree_map() {
        let value = given.get(&name).cloned().ok_or("input")?;
        inputs.insert(name.clone(), InputValue::try_from_json(value, &typ, &name).map_err(|_| "input")?);
    }
    let initial = artifact.abi.encode(&inputs, None).map_err(|_| "input")?;

    let mut stack = WitnessStack::default();
    let main = solve(&program, 0, initial, &mut stack)?;
    stack.push(0, main);
    // The default format, whatever NOIR_SERIALIZATION_FORMAT says: the bytes bb 5.2.1 reads.
    stack.serialize_with_format(SerializationFormat::default()).map_err(|_| "witness")
}

/// WebAssembly entry points for a browser worker, without wasm-bindgen: the caller copies the program and the input
/// into memory from `huma_alloc`, calls `huma_witness`, and reads the reply it points to: a little-endian u32 length,
/// then the witness, or (with the length's top bit set) the failing step's name. It frees both with `huma_free`.
#[cfg(target_arch = "wasm32")]
mod wasm {
    // Every buffer is an exact-length boxed slice, so freeing it needs only its length.
    fn leak(bytes: Vec<u8>) -> *mut u8 {
        Box::into_raw(bytes.into_boxed_slice()) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn huma_alloc(len: usize) -> *mut u8 {
        leak(vec![0; len.max(1)])
    }
    /// # Safety
    /// `pointer` came from `huma_alloc(len)` or is a reply `len` bytes long, and isn't used afterwards.
    #[no_mangle]
    pub unsafe extern "C" fn huma_free(pointer: *mut u8, len: usize) {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer, len.max(1))));
    }
    /// # Safety
    /// Both buffers came from `huma_alloc` with these lengths, and are freed by the caller afterwards.
    #[no_mangle]
    pub unsafe extern "C" fn huma_witness(program: *const u8, program_len: usize, input: *const u8, input_len: usize) -> *mut u8 {
        let result = super::witness(std::slice::from_raw_parts(program, program_len), std::slice::from_raw_parts(input, input_len));
        let (flag, body) = match &result { Ok(witness) => (0, witness.as_slice()), Err(step) => (1u32 << 31, step.as_bytes()) };
        let mut reply = Vec::with_capacity(4 + body.len());
        reply.extend_from_slice(&(body.len() as u32 | flag).to_le_bytes());
        reply.extend_from_slice(body);
        // The caller frees the reply with huma_free(pointer, 4 + length).
        leak(reply)
    }
}
