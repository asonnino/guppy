use clap::Parser;
use hashbrown::HashMap;
use log::LevelFilter;
use log::info;

use minnow_h_plonky2::circuit::{build_circuit, AllTargets};
use minnow_h_plonky2::MinnowH;
use minnow_h_plonky2::MinnowHServiceState;
use minnow_lib::checkpoint_commitment::CommitmentStrategy;
use minnow_lib::checkpoint_commitment::HashCommitment;
use minnow_lib::usize_to_stream_id;
use minnow_lib::utils::{generate_sample_checkpoint_updates, init_logging};
use minnow_lib::utils::{Digest, C, D, F};
use minnow_lib::STREAM_ID_LEN;
use minnow_lib::{commit_single_update, CheckpointUpdates, StreamID};
use plonky2::field::types::Field;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 5)]
    state_size: usize,

    #[arg(short, long, default_value_t = 1000)]
    checkpoint_updates: usize,

    /// Logarithmic estimate of the number of gates
    #[arg(short = 'g', long)]
    degree_bits: Option<usize>,

    /// Build the circuit only, don't prove
    #[arg(short, long, default_value_t = false)]
    build_only: bool,

    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

fn set_witness<S: CommitmentStrategy>(
    checkpoint_number: usize,
    validator_state: &S::ValidatorState,
    zk_service_state: &MinnowHServiceState,
    all_targets: &AllTargets<S>,
    prev_proof: &ProofWithPublicInputs<F, C, D>,
    base_case: bool,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> PartialWitness<F> {
    info!(
        "apply_checkpoint_updates_and_set_witness: start ({})",
        checkpoint_number
    );
    let mut pw = PartialWitness::new();
    pw.set_bool_target(all_targets.condition, !base_case)
        .unwrap();
    pw.set_proof_with_pis_target(&all_targets.inner_cyclic_proof_with_pis, &prev_proof)
        .unwrap();
    pw.set_verifier_data_target(&all_targets.verifier_data_target, verifier_data)
        .unwrap();

    S::assign_targets(&all_targets.checkpoint_update_targets, validator_state, &mut pw);

    assert_eq!(zk_service_state.len(), all_targets.in_state_targets.len());
    for (stream_point, target) in zk_service_state
        .iter()
        .zip(all_targets.in_state_targets.iter())
    {
        target.set_proof_targets(&mut pw, &stream_point.encode());
    }

    pw
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

    let num_checkpoint_updates = args.checkpoint_updates;
    let degree_bits = args.degree_bits;
    let num_tracking_streams = args.state_size;
    let tracking_streams: Vec<StreamID> =
        (0..num_tracking_streams).map(|i| usize_to_stream_id(i)).collect();

    let minnow_h = MinnowH::<HashCommitment>::new();

    let (cyclic_circuit_data, all_targets) =
        build_circuit::<HashCommitment>(num_checkpoint_updates, &tracking_streams, degree_bits);
    let verifier_data = &cyclic_circuit_data.verifier_only;
    let common_data = &cyclic_circuit_data.common;

    let num_checkpoints = 10;
    let all_checkpoint_updates =
        generate_sample_checkpoint_updates(num_checkpoints, num_checkpoint_updates);

    let mut state = MinnowHServiceState::new(&tracking_streams);
    let mut prev_head = Digest::ZERO;
    let mut proof = cyclic_base_proof(&common_data, verifier_data, HashMap::<usize, F>::new());
    for c in 0..num_checkpoints {
        let checkpoint_updates = &all_checkpoint_updates[c];
        let validator_state = HashCommitment::init_validator_state(checkpoint_updates);

        let pw = set_witness(
            c,
            &validator_state,
            &state,
            &all_targets,
            &proof,
            c == 0,
            &verifier_data,
        );

        let start = Instant::now();
        proof = cyclic_circuit_data.prove(pw).unwrap();
        let end = Instant::now();
        info!(
            "{}th recursive proof generation time: {:?}",
            c + 1,
            end.duration_since(start)
        );
        check_cyclic_proof_verifier_data(&proof, verifier_data, &cyclic_circuit_data.common)
            .unwrap();
        cyclic_circuit_data.verify(proof.clone()).unwrap();

        // Tests
        let new_head = minnow_h.commit(&checkpoint_updates, &prev_head, num_checkpoint_updates);
        assert_eq!(new_head.elements, proof.public_inputs[0..4]);

        state.apply_checkpoint_updates(&checkpoint_updates);
        assert_eq!(state.commit().elements, proof.public_inputs[4..8]);

        assert_eq!(
            F::from_canonical_u32((c + 1) as u32),
            proof.public_inputs[8]
        );

        info!("{}th proof verified!", c + 1);

        prev_head = new_head;
    }
}
