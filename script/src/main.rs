//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use minnow_lib::{
    commit_batch_updates, process_batch_updates, BatchCheckpointUpdates, CheckpointUpdates, Digest,
    GlobalState,
};
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1Stdin};

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
    all_checkpoint_updates
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
    let first_batch_updates = vec![first_checkpoint_updates];

    let mut local_commitment = [0u8; 32];

    // Genesis proof
    let starter_proof = tracing::info_span!("generate starter proof").in_scope(|| {
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        // Write the global state
        stdin.write(&global_state);

        // First checkpoint's updates
        stdin.write(&first_batch_updates);

        // The first vk input is no-op => this skips proof verification
        stdin.write(&None::<[u32; 8]>);

        // No previous local commitment (the starter for hash chain)
        stdin.write(&local_commitment);

        client
            .prove(&pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });
    let SP1Proof::Compressed(proof) = starter_proof.proof else {
        panic!()
    };

    // Apply the first batch of updates
    local_commitment = commit_batch_updates(&first_batch_updates, &local_commitment);
    global_state = process_batch_updates(&first_batch_updates, &global_state);

    // Sample updates simulating changes in the next c checkpoints
    let second_batch_updates = generate_sample_batch_updates(2);

    let mut stdin = SP1Stdin::new();
    stdin.write(&global_state);
    stdin.write(&second_batch_updates);
    stdin.write(&Some(vk.hash_u32()));
    stdin.write(&local_commitment);
    stdin.write_proof(*proof, vk.vk.clone());

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
