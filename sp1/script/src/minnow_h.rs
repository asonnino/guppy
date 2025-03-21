use minnow_lib::{
    commit_batch_updates,
    minnow_h::{HintsBatch, MinnowHServiceState},
    BatchCheckpointUpdates,
    CheckpointUpdates,
    StreamPoint,
};
use rkyv::{rancor::Error, to_bytes};
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Proof, SP1Stdin, SP1VerifyingKey};

use crate::common::{generate_sample_batch_updates, ProverEnv};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const MINNOW_H_ELF: &[u8] = include_elf!("minnow-h-program");

fn write_all_inputs(
    stdin: &mut SP1Stdin,
    global_state: &MinnowHServiceState,
    batch_updates: &BatchCheckpointUpdates,
    hints: &HintsBatch,
    vk_and_proof: Option<(SP1VerifyingKey, SP1Proof)>,
    local_commitment: &[u8; 32],
) {
    // 1. Write the service's global state
    let serialized_global_state = to_bytes::<Error>(global_state).unwrap();
    stdin.write_slice(&serialized_global_state);

    // 2. Write the batch of checkpoint updates
    let serialized_batch_updates = to_bytes::<Error>(batch_updates).unwrap();
    stdin.write_slice(&serialized_batch_updates);

    // 2b. Write the hints
    let serialized_hints = to_bytes::<Error>(hints).unwrap();
    stdin.write_slice(&serialized_hints);

    // 3. Write the validator-computed local commitment
    stdin.write(local_commitment);

    // 4. Write the verification key and proof (if provided)
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
    let (pk, vk) = client.setup(MINNOW_H_ELF);

    let mut global_state = Vec::new();
    // For all supported streams, initialize the global state with a value of 0.
    for i in 0..state_size {
        global_state.push(StreamPoint::new(i.try_into().unwrap(), [0u8; 32]));
    }
    let mut prev_global_state: MinnowHServiceState = global_state.into();
    let mut new_global_state = prev_global_state.clone();
    let mut first_checkpoint_updates = CheckpointUpdates::new();
    for i in 0..num_checkpoint_updates {
        first_checkpoint_updates.push(StreamPoint::new(i.try_into().unwrap(), [i as u8; 32]));
    }
    let first_batch_updates = BatchCheckpointUpdates(vec![first_checkpoint_updates]);
    let hints =
        new_global_state.generate_hints_batch_and_process_batch_updates(&first_batch_updates);

    let mut local_commitment = [0u8; 32];

    // Genesis proof
    let starter_proof = tracing::info_span!("generate starter proof").in_scope(|| {
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        // Write the global state and the first batch of updates
        // Set vk to None to skip proof verification
        write_all_inputs(
            &mut stdin,
            &prev_global_state,
            &first_batch_updates,
            &hints,
            None,
            &local_commitment,
        );

        client.prove(&pk, stdin).compressed().run()
    })?;

    // Apply the first batch of updates
    local_commitment = commit_batch_updates(&first_batch_updates, &local_commitment);
    prev_global_state = new_global_state.clone();

    // Sample updates simulating changes in the next c checkpoints
    let second_batch_updates =
        generate_sample_batch_updates(num_checkpoints, num_checkpoint_updates, 2);
    let hints =
        new_global_state.generate_hints_batch_and_process_batch_updates(&second_batch_updates);

    let mut stdin = SP1Stdin::new();
    write_all_inputs(
        &mut stdin,
        &prev_global_state,
        &second_batch_updates,
        &hints,
        Some((vk.clone(), starter_proof.proof)),
        &local_commitment,
    );

    Ok(ProverEnv {
        client,
        proving_key: pk,
        verifying_key: vk,
        stdin,
        elf: MINNOW_H_ELF,
    })
}
