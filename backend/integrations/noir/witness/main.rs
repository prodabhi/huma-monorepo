//! The Mac engine's witness tool: `witness <program.json> <out.gz>`, with the program's inputs as JSON on stdin. A
//! 600-operation part takes about 0.6 s, where noir_js on JavaScriptCore took 44 s.
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;

use huma_witness::{read_limited, witness, MAX_INPUT, MAX_PROGRAM};

fn run(program_path: &str, out_path: &str) -> Result<(), &'static str> {
    let program = read_limited(std::fs::File::open(program_path).map_err(|_| "program")?, MAX_PROGRAM, "program")?;
    let input = read_limited(std::io::stdin().lock(), MAX_INPUT, "input")?;
    let compressed = witness(&program, &input)?;
    // A new private file, never one that's already there.
    let mut out = OpenOptions::new().write(true).create_new(true).mode(0o600).open(out_path).map_err(|_| "output")?;
    out.write_all(&compressed).map_err(|_| "output")?;
    out.sync_all().map_err(|_| "output")
}
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: witness <program.json> <out.gz>  (inputs as JSON on stdin)");
        return ExitCode::from(64);
    }
    match run(&args[1], &args[2]) {
        Ok(()) => ExitCode::SUCCESS,
        Err(step) => {
            eprintln!("witness: {step}");
            ExitCode::FAILURE
        }
    }
}
