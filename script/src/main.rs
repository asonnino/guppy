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
use fibonacci_lib::{
    commit_single_checkpoint_updates, process_single_checkpoint_updates, CheckpointUpdates, Digest,
    GlobalState,
};
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,
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
    let (pk, vk) = client.setup(FIBONACCI_ELF);

    let mut global_state = GlobalState::new();
    let state_size = 1;
    // For all supported streams, initialize the global state with a value of 0.
    for i in 0..state_size {
        global_state.push((i, [0u8; 32]));
    }
    let num_checkpoint_updates = 10;
    let mut first_checkpoint_updates = CheckpointUpdates::new();
    for i in 0..num_checkpoint_updates {
        first_checkpoint_updates.push((i, [i as u8; 32]));
    }

    let first_local_commitment = [0u8; 32];

    // Genesis proof
    let starter_proof = tracing::info_span!("generate starter proof").in_scope(|| {
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        stdin.write(&global_state);

        // First checkpoint's updates
        stdin.write(&vec![first_checkpoint_updates.clone()]);

        // The first vk input is no-op => this skips proof verification
        stdin.write(&None::<[u32; 8]>);

        // No previous local commitment (the starter for hash chain)
        stdin.write(&first_local_commitment);

        client
            .prove(&pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });

    // Setup the first real prover client.
    let mut stdin = SP1Stdin::new();
    global_state = process_single_checkpoint_updates(&first_checkpoint_updates, &global_state);
    stdin.write(&global_state);

    let num_checkpoints = 100;
    let mut all_checkpoint_updates = Vec::new();
    for i in 0..num_checkpoints {
        let mut next_checkpoint_updates = CheckpointUpdates::new();
        for j in 0..num_checkpoint_updates {
            next_checkpoint_updates.push((i * num_checkpoint_updates + j, [i as u8; 32]));
        }
        all_checkpoint_updates.push(next_checkpoint_updates);
    }
    stdin.write(&all_checkpoint_updates);

    // From now on, we input the real verification key
    stdin.write(&Some(vk.hash_u32()));
    let second_local_commitment =
        commit_single_checkpoint_updates(&first_checkpoint_updates, &first_local_commitment);
    stdin.write(&second_local_commitment);

    let SP1Proof::Compressed(proof) = starter_proof.proof else {
        panic!()
    };
    stdin.write_proof(*proof, vk.vk.clone());

    if args.execute {
        // Execute the program
        let (mut output, report) = client.execute(FIBONACCI_ELF, stdin).run().unwrap();
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
