use minnow_lib::{
    commit_batch_updates,
    minnow_mt::{BatchMinnowMTStateUpdates, MinnowMTServiceState},
    BatchCheckpointUpdates,
    Digest,
    StreamID,
    StreamPoint,
};
use rkyv::{rancor::Error, to_bytes};
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Proof, SP1Stdin, SP1VerifyingKey};

use crate::common::{generate_sample_batch_updates, ProverEnv};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
#[allow(unused)]
pub const MINNOW_MT_ELF: &[u8] = include_elf!("minnow-mt-program");

fn write_all_inputs(
    stdin: &mut SP1Stdin,
    global_state_commitment: &Digest,
    batch_updates: &BatchCheckpointUpdates,
    tracked_stream_ids: &Vec<StreamID>,
    state_update_proofs: &BatchMinnowMTStateUpdates,
    local_commitment: &Digest,
    vk_and_proof: Option<(SP1VerifyingKey, SP1Proof)>,
) {
    // 1. Write the service's global state
    stdin.write(global_state_commitment);

    // 2. Write the batch of checkpoint updates
    let serialized_batch_updates = to_bytes::<Error>(batch_updates).unwrap();
    stdin.write_slice(&serialized_batch_updates);

    // 3a. Write the tracked stream IDs
    let serialized_tracked_stream_ids = to_bytes::<Error>(tracked_stream_ids).unwrap();
    stdin.write_slice(&serialized_tracked_stream_ids);

    // 3b. Write the state update proofs
    let serialized_state_update_proofs = to_bytes::<Error>(state_update_proofs).unwrap();
    stdin.write_slice(&serialized_state_update_proofs);

    // 4. Write the validator-computed local commitment
    stdin.write(local_commitment);

    // 5. Write the verification key and proof (if provided)
    if let Some((vk, proof)) = vk_and_proof {
        stdin.write(&Some(vk.hash_u32()));

        let SP1Proof::Compressed(proof) = proof else {
            panic!("proof is not compressed")
        };
        stdin.write_proof(*proof, vk.vk);
    } else {
        stdin.write(&None::<[u32; 8]>);
    }
}

pub fn run(
    state_size: usize,
    num_checkpoint_updates: usize,
    num_checkpoints: usize,
) -> anyhow::Result<ProverEnv<'static>> {
    let client = ProverClient::new();
    let (pk, vk) = client.setup(MINNOW_MT_ELF);

    // For all supported streams, initialize the global state with a value of 0.
    let global_state: Vec<StreamPoint> = (0..state_size)
        .map(|i| StreamPoint::new(i.try_into().unwrap(), [0u8; 32]))
        .collect();
    let tracked_streams: Vec<StreamID> = global_state.iter().map(|sp| sp.id).collect();
    let mut global_state = MinnowMTServiceState::new(global_state);
    let global_state_commitment = *global_state.global_commitment();

    let first_checkpoint_updates = (0..num_checkpoint_updates)
        .map(|i| StreamPoint::new(i.try_into().unwrap(), [i as u8; 32]))
        .collect();
    let first_batch_updates = BatchCheckpointUpdates(vec![first_checkpoint_updates]);

    let mut local_commitment = [0u8; 32];

    let state_update_proofs = global_state.process_batch_checkpoint_updates(&first_batch_updates);

    // Genesis proof
    let starter_proof = tracing::info_span!("generate starter proof").in_scope(|| {
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        // Write the global state and the first batch of updates
        // Set vk to None to skip proof verification
        write_all_inputs(
            &mut stdin,
            &global_state_commitment,
            &first_batch_updates,
            &tracked_streams,
            &state_update_proofs,
            &local_commitment,
            None,
        );

        client.prove(&pk, stdin).compressed().run()
    })?;

    // Apply the first batch of updates
    local_commitment = commit_batch_updates(&first_batch_updates, &local_commitment);
    let global_state_commitment = *global_state.global_commitment();

    // Sample updates simulating changes in the next c checkpoints
    let second_batch_updates =
        generate_sample_batch_updates(num_checkpoints, num_checkpoint_updates, 2);
    let state_update_proofs = global_state.process_batch_checkpoint_updates(&second_batch_updates);

    let mut stdin = SP1Stdin::new();
    write_all_inputs(
        &mut stdin,
        &global_state_commitment,
        &second_batch_updates,
        &tracked_streams,
        &state_update_proofs,
        &local_commitment,
        Some((vk.clone(), starter_proof.proof)),
    );

    Ok(ProverEnv {
        client,
        proving_key: pk,
        verifying_key: vk,
        stdin,
        elf: MINNOW_MT_ELF,
    })
}
