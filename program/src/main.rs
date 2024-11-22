#![no_main]
sp1_zkvm::entrypoint!(main);

use minnow_lib::{
    commit_batch_checkpoint_updates, compute_global_commitment, process_batch_checkpoint_updates,
    BatchCheckpointUpdates, GlobalState,
};

use sha2::{Digest, Sha256};

pub fn main() {
    // Read an input to the program.
    println!("cycle-tracker-start: input-state");
    let v_prev = sp1_zkvm::io::read::<GlobalState>();
    println!("cycle-tracker-end: input-state");

    println!("cycle-tracker-start: input-updates");
    let batch_checkpoint_updates = sp1_zkvm::io::read::<BatchCheckpointUpdates>();
    println!("cycle-tracker-end: input-updates");

    println!("cycle-tracker-start: input-others");
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

    let v_next = process_batch_checkpoint_updates(&batch_checkpoint_updates, &v_prev);
    let global_commitment = compute_global_commitment(&v_next);
    let local_commitment =
        commit_batch_checkpoint_updates(&batch_checkpoint_updates, &last_local_commitment);

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    println!("cycle-tracker-start: output");
    sp1_zkvm::io::commit(&global_commitment);
    sp1_zkvm::io::commit(&local_commitment);
    println!("cycle-tracker-end: output");
}
