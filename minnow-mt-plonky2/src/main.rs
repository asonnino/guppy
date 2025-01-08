use hashbrown::HashMap;
use minnow_mt_plonky2::circuit::build_circuit;
use minnow_mt_plonky2::circuit::AllTargets;
use minnow_mt_plonky2::circuit::Digest;
use minnow_mt_plonky2::commit_single_update;
use minnow_mt_plonky2::utils::init_logging;
use minnow_mt_plonky2::CheckpointUpdates;
use minnow_mt_plonky2::MinnowMTServiceState;
use minnow_mt_plonky2::StreamPoint;
use plonky2::field::types::Field;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use std::time::Instant;

use log::LevelFilter;
use log::{debug, info};

use clap::Parser;

use minnow_mt_plonky2::circuit::{C, D, F};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 11)]
    state_size: usize,

    #[arg(short, long, default_value_t = 300)]
    checkpoint_updates: usize,

    #[arg(short, long)]
    degree_bits: Option<usize>,

    /// Build the circuit only, don't prove
    #[arg(short, long, default_value_t = false)]
    build_only: bool,

    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

fn apply_checkpoint_updates_and_set_witness(
    checkpoint_number: usize,
    checkpoint_updates: &CheckpointUpdates,
    zk_service_state: &mut MinnowMTServiceState,
    all_targets: &AllTargets,
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

    for (i, update) in checkpoint_updates.iter().enumerate() {
        zk_service_state.add_proof_targets(&mut pw, &all_targets.prev_targets[i], &update.id);
        zk_service_state.update_leaf(&update);
        zk_service_state.add_proof_targets(&mut pw, &all_targets.new_targets[i], &update.id);
    }

    info!(
        "apply_checkpoint_updates_and_set_witness: end ({})",
        checkpoint_number
    );
    pw
}

// Test vector: All checkpoints update the same set of stream points
fn generate_sample_checkpoint_updates(
    num_checkpoints: usize,
    num_checkpoint_updates: usize,
) -> Vec<CheckpointUpdates> {
    let start_checkpoint_number = 0;
    let mut all_updates = Vec::new();
    let first_set = (0..num_checkpoint_updates)
        .map(|i| {
            StreamPoint::new_with_flag(
                i.try_into().unwrap(),
                [start_checkpoint_number as u8; 32],
                true,
            )
        })
        .collect();
    all_updates.push(first_set);
    for _ in 1..num_checkpoints {
        all_updates.push(
            (0..num_checkpoint_updates)
                .map(|i| {
                    StreamPoint::new_with_flag(
                        i.try_into().unwrap(),
                        [(start_checkpoint_number + i) as u8; 32],
                        false,
                    )
                })
                .collect(),
        );
    }
    all_updates
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

    let num_levels = args.state_size;
    let num_checkpoint_updates = args.checkpoint_updates;
    let degree_bits = args.degree_bits;
    let (cyclic_circuit_data, all_targets) =
        build_circuit(num_levels, num_checkpoint_updates, degree_bits);
    let verifier_data = &cyclic_circuit_data.verifier_only;
    let common_data = &cyclic_circuit_data.common;
    debug!("Degree: 2^{}", common_data.degree_bits());

    if args.build_only {
        return;
    }

    let mut zk_service_state = MinnowMTServiceState::new(&[], num_levels);
    let mut proof = cyclic_base_proof(&common_data, verifier_data, HashMap::<usize, F>::new());
    let mut prev_head = Digest::ZERO;
    let num_checkpoints = 10;
    let all_checkpoint_updates =
        generate_sample_checkpoint_updates(num_checkpoints, num_checkpoint_updates);
    for c in 0..num_checkpoints {
        let checkpoint_updates = &all_checkpoint_updates[c];
        let new_head = commit_single_update(&checkpoint_updates, &prev_head);
        let pw = apply_checkpoint_updates_and_set_witness(
            c,
            &checkpoint_updates,
            &mut zk_service_state,
            &all_targets,
            &proof,
            c == 0,
            verifier_data,
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
