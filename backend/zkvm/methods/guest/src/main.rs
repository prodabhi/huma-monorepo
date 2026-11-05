#![no_main]
use huma_replay_core::{replay, Witness};
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);
fn main() {
    let witness: Witness = env::read();
    let journal = replay(&witness).expect("Native history replay rejected");
    env::commit_slice(&serde_json::to_vec(&journal).unwrap());
}
