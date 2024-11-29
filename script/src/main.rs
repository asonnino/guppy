use clap::Parser;
use minnow_lib::{
    commit_batch_updates, process_batch_updates, BatchCheckpointUpdates, CheckpointUpdates, Digest,
    GlobalState,
};
use rkyv::{rancor::Error, to_bytes};
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1Stdin, SP1VerifyingKey};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const MINNOW_ELF: &[u8] = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,
}

const STATE_SIZE: usize = 1;
const NUM_CHECKPOINT_UPDATES: usize = 10;
const NUM_CHECKPOINTS: usize = 10;

fn generate_sample_batch_updates(start_idx: usize) -> BatchCheckpointUpdates {
    let mut all_checkpoint_updates = Vec::new();
    for i in 0..NUM_CHECKPOINTS {
        let mut next_checkpoint_updates = CheckpointUpdates::new();
        for j in 0..NUM_CHECKPOINT_UPDATES {
            next_checkpoint_updates.push((
                (i * NUM_CHECKPOINT_UPDATES + j).try_into().unwrap(),
                [(i + start_idx) as u8; 32],
            ));
        }
        all_checkpoint_updates.push(next_checkpoint_updates);
    }
    BatchCheckpointUpdates(all_checkpoint_updates)
}

fn write_all_inputs(
    stdin: &mut SP1Stdin,
    global_state: &GlobalState,
    batch_updates: &BatchCheckpointUpdates,
    vk_and_proof: Option<(SP1VerifyingKey, SP1Proof)>,
    local_commitment: &[u8; 32],
) {
    // 1. Write the service's global state
    stdin.write(global_state);

    // 2. Write the batch of checkpoint updates
    let serialized_batch_updates = to_bytes::<Error>(batch_updates).unwrap();
    stdin.write_slice(&serialized_batch_updates);

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

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let client = ProverClient::new();
    let (pk, vk) = client.setup(MINNOW_ELF);

    let mut global_state = GlobalState::new();
    // For all supported streams, initialize the global state with a value of 0.
    for i in 0..STATE_SIZE {
        global_state.push((i.try_into().unwrap(), [0u8; 32]));
    }
    let mut first_checkpoint_updates = CheckpointUpdates::new();
    for i in 0..NUM_CHECKPOINT_UPDATES {
        first_checkpoint_updates.push((i.try_into().unwrap(), [i as u8; 32]));
    }
    let first_batch_updates = BatchCheckpointUpdates(vec![first_checkpoint_updates]);

    let mut local_commitment = [0u8; 32];

    // Genesis proof
    let starter_proof = tracing::info_span!("generate starter proof").in_scope(|| {
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        // Write the global state and the first batch of updates
        // Set vk to None to skip proof verification
        write_all_inputs(
            &mut stdin,
            &global_state,
            &first_batch_updates,
            None,
            &local_commitment,
        );

        client
            .prove(&pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });
    // Apply the first batch of updates
    local_commitment = commit_batch_updates(&first_batch_updates, &local_commitment);
    global_state = process_batch_updates(&first_batch_updates, &global_state);

    // Sample updates simulating changes in the next c checkpoints
    let second_batch_updates = generate_sample_batch_updates(2);

    let mut stdin = SP1Stdin::new();
    write_all_inputs(
        &mut stdin,
        &global_state,
        &second_batch_updates,
        Some((vk.clone(), starter_proof.proof)),
        &local_commitment,
    );

    if args.execute {
        // Execute the program
        let (mut output, report) = client.execute(MINNOW_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let final_gc = output.read::<Digest>();
        println!("output: {:?}", hex::encode(final_gc));

        let final_lc = output.read::<Digest>();
        println!("output: {:?}", hex::encode(final_lc));

        // Print the total number of cycles executed and the full execution report with a breakdown of
        // the RISC-V opcode and syscall counts.
        println!(
            "Executed program with {} cycles",
            report.total_instruction_count() + report.total_syscall_count()
        );
        println!("Full execution report:\n{:?}", report);
    } else {
        // Generate the proof
        let proof = client
            .prove(&pk.clone(), stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client
            .verify(&proof, &vk.clone())
            .expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
