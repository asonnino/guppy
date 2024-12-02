use clap::Parser;
use minnow_lib::Digest;

mod common;
mod minnow_h;
mod minnow_mt;

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Execute the program without generating a proof.
    ///
    /// This is the default behaviour.
    #[clap(long, short, action, conflicts_with = "prove")]
    execute: bool,

    /// Generate a proof.
    #[clap(long, short, action, conflicts_with = "execute")]
    prove: bool,

    /// Use Minnow MT program instead of Minnow H program.
    #[clap(long, short, action)]
    merkle_tree: bool,
}

fn main() -> anyhow::Result<()> {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    let proof_env = if args.merkle_tree {
        minnow_mt::run()?
    } else {
        minnow_h::run()?
    };

    if args.prove {
        // Generate the proof
        let proof = proof_env.prove()?;
        println!("Successfully generated proof!");

        // Verify the proof.
        proof_env
            .client
            .verify(&proof, &proof_env.verifying_key)
            .expect("failed to verify proof");
        println!("Successfully verified proof!");
    } else {
        // Execute the program
        let (mut output, report) = proof_env.execute()?;
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
    }

    Ok(())
}
