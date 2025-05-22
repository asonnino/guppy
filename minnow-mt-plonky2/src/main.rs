use hashbrown::HashMap;
use minnow_lib::hash_commitment;
use minnow_lib::utils::generate_sample_checkpoint_updates;
use minnow_lib::utils::init_logging;
use minnow_lib::utils::{Digest, F};
use minnow_mt_plonky2::one_step_circuit::MinnowMTOneStepCircuit;
use minnow_mt_plonky2::MinnowMTServiceState;
use plonky2::field::types::Field;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use std::time::Instant;

use log::LevelFilter;
use log::{debug, info};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 2^log_state_size leaves in the Merkle tree
    #[arg(short, long, default_value_t = 10)]
    log_state_size: usize,

    /// Number of checkpoint updates
    #[arg(short, long, default_value_t = 300)]
    checkpoint_updates: usize,

    /// Logarithmic estimate of the number of gates
    #[arg(short = 'g', long)]
    degree_bits: Option<usize>,

    /// Build the circuit only, don't prove
    #[arg(short, long, default_value_t = false)]
    build_only: bool,

    /// Debug logs
    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

fn main() {
    // Parse the command line arguments.
    let args = Args::parse();
    info!("{:?}", args);
    if args.debug {
        init_logging(LevelFilter::Debug);
    } else {
        init_logging(LevelFilter::Info);
    }

    let log_state_size = args.log_state_size;
    let num_checkpoint_updates = args.checkpoint_updates;
    let degree_bits = args.degree_bits;
    let circuit = MinnowMTOneStepCircuit::new(log_state_size, num_checkpoint_updates, degree_bits);
    let verifier_data = &circuit.circuit_data.verifier_only;
    let common_data = &circuit.circuit_data.common;
    debug!("Degree: 2^{}", common_data.degree_bits());

    if args.build_only {
        return;
    }

    let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
    let mut proof = cyclic_base_proof(&common_data, verifier_data, HashMap::<usize, F>::new());
    let mut prev_head = Digest::ZERO;
    let num_checkpoints = 10;
    let all_checkpoint_updates =
        generate_sample_checkpoint_updates(num_checkpoints, num_checkpoint_updates);
    for c in 0..num_checkpoints {
        let checkpoint_updates = &all_checkpoint_updates[c];
        let new_head = hash_commitment(&checkpoint_updates, &prev_head);
        let pw = circuit.apply_checkpoint_updates_and_set_inputs(
            c,
            &checkpoint_updates,
            &mut zk_service_state,
            &proof,
            c == 0,
            verifier_data,
        );

        let start = Instant::now();
        proof = circuit.circuit_data.prove(pw).unwrap();
        let end = Instant::now();
        info!(
            "{}th recursive proof generation time: {:?}",
            c + 1,
            end.duration_since(start)
        );
        check_cyclic_proof_verifier_data(&proof, verifier_data, &common_data).unwrap();
        circuit.circuit_data.verify(proof.clone()).unwrap();

        // Tests checking the circuit logic
        assert_eq!(
            zk_service_state.get_root().elements,
            proof.public_inputs[0..4]
        );
        assert_eq!(new_head.elements, proof.public_inputs[4..8]);
        assert_eq!(
            F::from_canonical_u32((c + 1) as u32),
            proof.public_inputs[8]
        );
        assert_eq!(
            F::from_canonical_u32(zk_service_state.get_num_leaves() as u32),
            proof.public_inputs[9]
        );

        info!("{}th proof verified!", c + 1);

        prev_head = new_head;
    }
}
