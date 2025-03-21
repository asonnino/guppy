#![no_main]
sp1_zkvm::entrypoint!(main);

use minnow_lib::{
    commit_batch_updates,
    commit_stream_ids,
    minnow_mt::BatchMinnowMTStateUpdates,
    BatchCheckpointUpdates,
    Digest,
};
use rkyv::{from_bytes, rancor::Error};
use sha2::{Digest as _, Sha256};

pub fn main() {
    // Read the previous global commitment.
    println!("cycle-tracker-start: input-global-commitment");
    let last_global_commitment = sp1_zkvm::io::read::<Digest>();
    println!("cycle-tracker-end: input-global-commitment");

    println!("cycle-tracker-start: input-updates");
    let serialized_batch_checkpoint_updates = sp1_zkvm::io::read_vec();
    let batch_checkpoint_updates =
        from_bytes::<BatchCheckpointUpdates, Error>(&serialized_batch_checkpoint_updates).unwrap();
    println!("cycle-tracker-end: input-updates");

    println!("cycle-tracker-start: input-stream-ids");
    let serialized_stream_ids = sp1_zkvm::io::read_vec();
    let stream_ids: Vec<u32> = from_bytes::<Vec<u32>, Error>(&serialized_stream_ids).unwrap();
    println!("cycle-tracker-end: input-stream-ids");

    // Read the update proofs.
    println!("cycle-tracker-start: input-state-updates");
    let serialized_state_updates = sp1_zkvm::io::read_vec();
    let state_updates =
        from_bytes::<BatchMinnowMTStateUpdates, Error>(&serialized_state_updates).unwrap();
    println!("cycle-tracker-end: input-state-updates");

    println!("cycle-tracker-start: input-others");
    // Read the last local commitment
    let last_local_commitment = sp1_zkvm::io::read::<[u8; 32]>();

    // Read the verification key
    let vkey = sp1_zkvm::io::read::<Option<[u32; 8]>>();
    println!("cycle-tracker-end: input-others");

    // Commit to the stream IDs. This value should not change from the previous one.
    // TODO: eventually allow for changes in the set of stream IDs.
    println!("cycle-tracker-start: commit-stream-ids");
    let stream_ids_commitment = commit_stream_ids(&stream_ids);
    println!("cycle-tracker-end: commit-stream-ids");

    println!("cycle-tracker-start: recursion");
    if let Some(vkey) = vkey {
        let mut public_values = Vec::new();
        public_values.extend_from_slice(&last_global_commitment);
        public_values.extend_from_slice(&last_local_commitment);
        public_values.extend_from_slice(&stream_ids_commitment);
        let public_values_digest = Sha256::digest(&public_values);
        println!("cycle-tracker-start: recursion-core");
        sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &public_values_digest.into());
        println!("cycle-tracker-end: recursion-core");
    }
    println!("cycle-tracker-end: recursion");

    let local_commitment = commit_batch_updates(&batch_checkpoint_updates, &last_local_commitment);

    // Update the global commitment with the state updates.
    println!("cycle-tracker-start: update-global-commitment");
    let global_commitment = state_updates.process_batch_checkpoint_updates(
        &stream_ids,
        &last_global_commitment,
        &batch_checkpoint_updates,
    );
    println!("cycle-tracker-end: update-global-commitment");

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    println!("cycle-tracker-start: output");
    sp1_zkvm::io::commit(&global_commitment);
    sp1_zkvm::io::commit(&local_commitment);
    sp1_zkvm::io::commit(&stream_ids_commitment);
    println!("cycle-tracker-end: output");
}
