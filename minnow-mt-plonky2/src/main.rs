use hashbrown::HashMap;
use minnow_mt_plonky2::circuit::build_circuit;
use minnow_mt_plonky2::circuit::Digest;
use minnow_mt_plonky2::circuit::PrivateInputs;
use minnow_mt_plonky2::commit_single_update;
use minnow_mt_plonky2::utils::generate_sample_checkpoint_updates;
use minnow_mt_plonky2::utils::init_logging;
use minnow_mt_plonky2::CheckpointUpdates;
use minnow_mt_plonky2::MinnowMTServiceState;
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
    /// 2^state_size leaves in the Merkle tree
    #[arg(short, long, default_value_t = 10)]
    state_size: usize,

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

fn apply_checkpoint_updates_and_set_witness(
    checkpoint_number: usize,
    checkpoint_updates: &CheckpointUpdates,
    zk_service_state: &mut MinnowMTServiceState,
    all_inputs: &PrivateInputs,
    prev_proof: &ProofWithPublicInputs<F, C, D>,
    base_case: bool,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> PartialWitness<F> {
    debug!(
        "apply_checkpoint_updates_and_set_witness: start ({})",
        checkpoint_number
    );
    let mut pw = PartialWitness::new();
    pw.set_bool_target(all_inputs.condition, !base_case)
        .unwrap();
    pw.set_proof_with_pis_target(&all_inputs.inner_cyclic_proof_with_pis, &prev_proof)
        .unwrap();
    pw.set_verifier_data_target(&all_inputs.verifier_data_target, verifier_data)
        .unwrap();

    for (i, update) in checkpoint_updates.iter().enumerate() {
        zk_service_state.add_proof_targets(&mut pw, &all_inputs.prev_targets[i], &update.id);
        zk_service_state.update_leaf(&update);
        zk_service_state.add_proof_targets(&mut pw, &all_inputs.new_targets[i], &update.id);
    }

    debug!(
        "apply_checkpoint_updates_and_set_witness: end ({})",
        checkpoint_number
    );
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

    let state_size = args.state_size;
    let num_checkpoint_updates = args.checkpoint_updates;
    let degree_bits = args.degree_bits;
    let circuit = build_circuit(state_size, num_checkpoint_updates, degree_bits);
    let verifier_data = &circuit.circuit_data.verifier_only;
    let common_data = &circuit.circuit_data.common;
    debug!("Degree: 2^{}", common_data.degree_bits());

    if args.build_only {
        return;
    }

    let mut zk_service_state = MinnowMTServiceState::new(&[], state_size);
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
            &circuit.private_inputs,
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn build(state_size: usize, num_checkpoint_updates: usize, degree_bits: Option<usize>) {
        init_logging(LevelFilter::Debug);
        println!("state_size: {}, num_checkpoint_updates: {}, degree_bits: {:?}", state_size, num_checkpoint_updates, degree_bits);
        let circuit = build_circuit(state_size, num_checkpoint_updates, degree_bits);
        assert_eq!(
            circuit.circuit_data.common.degree_bits(),
            degree_bits.unwrap()
        );
    }

    #[rstest]
    #[case(10, 350, 14)]
    #[case(10, 900, 15)]
    #[case(10, 2050, 16)]
    #[case(10, 4300, 17)]
    #[case(20, 200, 14)]
    #[case(20, 500, 15)]
    #[case(20, 1200, 16)]
    #[case(20, 2550, 17)]
    #[case(30, 100, 14)]
    #[case(30, 350, 15)]
    #[case(30, 850, 16)]
    #[case(30, 1800, 17)]
    fn test_limits_success(
        #[case] state_size: usize,
        #[case] num_checkpoint_updates: usize,
        #[case] degree_bits: usize,
    ) {
        build(state_size, num_checkpoint_updates, Some(degree_bits));
    }

    #[rstest]
    #[should_panic]
    #[case(10, 350, 14)]
    #[should_panic]
    #[case(10, 900, 15)]
    #[should_panic]
    #[case(10, 2050, 16)]
    #[should_panic]
    #[case(10, 4300, 17)]
    #[should_panic]
    #[case(20, 200, 14)]
    #[should_panic]
    #[case(20, 500, 15)]
    #[should_panic]
    #[case(20, 1200, 16)]
    #[should_panic]
    #[case(20, 2550, 17)]
    #[should_panic]
    #[case(30, 100, 14)]
    #[should_panic]
    #[case(30, 350, 15)]
    #[should_panic]
    #[case(30, 850, 16)]
    #[should_panic]
    #[case(30, 1800, 17)]
    fn test_limits_failure(
        #[case] state_size: usize,
        #[case] num_checkpoint_updates: usize,
        #[case] degree_bits: usize,
    ) {
        build(state_size, num_checkpoint_updates + 50, Some(degree_bits));
    }
}
