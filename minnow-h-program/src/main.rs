#![no_main]
sp1_zkvm::entrypoint!(main);

use minnow_lib::{
    commit_batch_updates,
    minnow_h::{HintsBatch, MinnowHServiceState},
    BatchCheckpointUpdates,
};
use rkyv::{from_bytes, rancor::Error};
use sha2::{Digest, Sha256};

pub fn main() {
    // Read an input to the program.
    println!("cycle-tracker-start: input-state");

    let serialized_v_prev = sp1_zkvm::io::read_vec();
    let v_prev = from_bytes::<MinnowHServiceState, Error>(&serialized_v_prev).unwrap();
    println!("cycle-tracker-end: input-state");

    println!("cycle-tracker-start: input-updates");
    let serialized_batch_checkpoint_updates = sp1_zkvm::io::read_vec();
    let batch_checkpoint_updates =
        from_bytes::<BatchCheckpointUpdates, Error>(&serialized_batch_checkpoint_updates).unwrap();

    let serialized_hints = sp1_zkvm::io::read_vec();
    let hints = from_bytes::<HintsBatch, Error>(&serialized_hints).unwrap();
    println!("cycle-tracker-end: input-updates");

    println!("cycle-tracker-start: input-others");
    // Read the last local commitment
    let last_local_commitment = sp1_zkvm::io::read::<[u8; 32]>();

    // Read the verification key
    let vkey = sp1_zkvm::io::read::<Option<[u32; 8]>>();
    println!("cycle-tracker-end: input-others");

    // println!("Checkpoint updates: {:?}", 1);
    // println!("Current state: {:?}", 2);
    println!("cycle-tracker-start: recursion");
    if let Some(vkey) = vkey {
        let last_global_commitment = v_prev.compute_global_commitment();
        let mut public_values = Vec::new();
        public_values.extend_from_slice(&last_global_commitment);
        public_values.extend_from_slice(&last_local_commitment);
        let public_values_digest = Sha256::digest(&public_values);
        println!("cycle-tracker-start: recursion-core");
        sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &public_values_digest.into());
        println!("cycle-tracker-end: recursion-core");
    }
    println!("cycle-tracker-end: recursion");

    let mut global_state = v_prev;
    global_state.process_batch_updates_with_hints(&batch_checkpoint_updates, &hints);
    let global_commitment = global_state.compute_global_commitment();
    let local_commitment = commit_batch_updates(&batch_checkpoint_updates, &last_local_commitment);

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    println!("cycle-tracker-start: output");
    sp1_zkvm::io::commit(&global_commitment);
    sp1_zkvm::io::commit(&local_commitment);
    println!("cycle-tracker-end: output");
}
