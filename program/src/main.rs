//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use fibonacci_lib::{
    compute_global_commitment, compute_local_commitment, compute_new_state, CheckpointUpdates,
    GlobalState,
};

use sha2::{Digest, Sha256};

pub fn main() {
    // Read an input to the program.
    println!("cycle-tracker-start: input-entire-state");
    let v_prev = sp1_zkvm::io::read::<GlobalState>();
    println!("cycle-tracker-end: input-entire-state");

    println!("cycle-tracker-start: input-others");
    let l = sp1_zkvm::io::read::<CheckpointUpdates>();

    // Read the verification key
    let vkey = sp1_zkvm::io::read::<Option<[u32; 8]>>();

    // Read the last local commitment
    let last_local_commitment = sp1_zkvm::io::read::<[u8; 32]>();
    println!("cycle-tracker-end: input-others");

    // println!("Checkpoint updates: {:?}", 1);
    // println!("Current state: {:?}", 2);
    println!("cycle-tracker-start: recursion");
    if let Some(vkey) = vkey {
        let last_global_commitment = compute_global_commitment(&v_prev);
        let mut public_values = Vec::new();
        public_values.extend_from_slice(&last_global_commitment);
        public_values.extend_from_slice(&last_local_commitment);
        let public_values_digest = Sha256::digest(&public_values);
        println!("cycle-tracker-start: recursion-core");
        sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &public_values_digest.into());
        println!("cycle-tracker-end: recursion-core");
    }
    println!("cycle-tracker-end: recursion");

    let v_next = compute_new_state(&l, &v_prev);
    let global_commitment = compute_global_commitment(&v_next);
    let local_commitment = compute_local_commitment(&l, &last_local_commitment);

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    println!("cycle-tracker-start: output");
    sp1_zkvm::io::commit(&global_commitment);
    sp1_zkvm::io::commit(&local_commitment);
    println!("cycle-tracker-end: output");
}
