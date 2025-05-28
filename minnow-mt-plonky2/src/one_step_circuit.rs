use log::debug;
use minnow_lib::UpdateBatch;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::util::log2_ceil;
use plonky2::with_context;

use crate::merkle::get_initial_root;
use crate::merkle::MerkleProofTargets;
use crate::process_many_batches;
use crate::CircuitState;
use crate::MinnowMTServiceState;
use minnow_lib::utils::common_data_for_recursion;
use minnow_lib::utils::print_system_info;
use minnow_lib::utils::CircuitInfo;
use minnow_lib::utils::{Digest, C, D, F};

// Called Minnow-MT-A in the paper.
pub struct MinnowMTOneStepCircuit {
    pub circuit_data: CircuitData<F, C, D>,
    pub private_inputs: PrivateInputs,
    pub circuit_info: CircuitInfo,
}

pub struct PrivateInputs {
    pub condition: BoolTarget,
    pub inner_cyclic_proof_with_pis: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub prev_targets: Vec<MerkleProofTargets>,
    pub new_targets: Vec<MerkleProofTargets>,
}

// 2 m logn + 6300 (~6300 gates for the recursion)
fn estimate_degree_bits(max_levels: usize, num_checkpoint_updates: usize) -> usize {
    let num_gates = (2 * (max_levels + 1) * num_checkpoint_updates) + 6300;
    return log2_ceil(num_gates);
}

impl MinnowMTOneStepCircuit {
    pub fn new(
        state_size: usize,
        num_batches: usize,
        batch_size: usize,
        degree_bits: Option<usize>,
    ) -> Self {
        build_circuit(state_size, num_batches, batch_size, degree_bits)
    }

    pub fn apply_update_batch_and_set_inputs(
        &self,
        checkpoint_number: usize,
        update_batch: &UpdateBatch,
        zk_service_state: &mut MinnowMTServiceState,
        prev_proof: &ProofWithPublicInputs<F, C, D>,
        base_case: bool,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> PartialWitness<F> {
        debug!(
            "apply_checkpoint_updates_and_set_witness: start ({})",
            checkpoint_number
        );
        let mut pw = PartialWitness::new();
        pw.set_bool_target(self.private_inputs.condition, !base_case)
            .unwrap();
        pw.set_proof_with_pis_target(
            &self.private_inputs.inner_cyclic_proof_with_pis,
            &prev_proof,
        )
        .unwrap();
        pw.set_verifier_data_target(&self.private_inputs.verifier_data_target, verifier_data)
            .unwrap();

        for (i, update) in update_batch.iter().enumerate() {
            zk_service_state.add_proof_targets(
                &mut pw,
                &self.private_inputs.prev_targets[i],
                &update.id,
            );
            zk_service_state.update_leaf(&update);
            zk_service_state.add_proof_targets(
                &mut pw,
                &self.private_inputs.new_targets[i],
                &update.id,
            );
        }

        debug!(
            "apply_checkpoint_updates_and_set_witness: end ({})",
            checkpoint_number
        );
        pw
    }
}

fn build_circuit(
    log_state_size: usize,
    num_batches: usize,
    batch_size: usize,
    degree_bits: Option<usize>,
) -> MinnowMTOneStepCircuit {
    let num_levels = log_state_size + 1;
    print_system_info(num_levels, num_batches, batch_size);

    // Public inputs:
    // (i) zk service's state root,
    // (ii) checkpoint commitment,
    // (iii) counter / checkpoint number (NOTE: Probably not needed for any security purpose..),
    // (iv) verifier data
    // (v) num_leaves

    // Private inputs:
    // (i) total number of leaves,
    // (ii) condition

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let in_state_t = CircuitState::new(&mut builder);

    let (prev_targets, new_targets, out_state_t) = process_many_batches(
        &mut builder,
        num_batches,
        batch_size,
        num_levels,
        &in_state_t,
    );

    // Register the final root as a public input
    builder.register_public_inputs(&out_state_t.root_t.elements);

    builder.register_public_inputs(&out_state_t.checkpoint_head_t.elements);

    let counter = builder.add_virtual_public_input();

    builder.register_public_input(out_state_t.num_leaves_t);

    let expected_degree_bits =
        degree_bits.unwrap_or_else(|| estimate_degree_bits(num_levels, batch_size * num_batches));
    debug!("Expected degree: 2^{}", expected_degree_bits);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    let common_data = common_data_for_recursion(expected_degree_bits, builder.num_public_inputs());

    // Condition is false for the base case, true for the recursive case.
    let condition = builder.add_virtual_bool_target_safe();

    // Unpack inner proof's public inputs.
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_cyclic_latest_root = HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
    let inner_checkpoint_head = HashOutTarget::try_from(&inner_cyclic_pis[4..8]).unwrap();
    let inner_cyclic_counter = inner_cyclic_pis[8];
    let inner_num_leaves = inner_cyclic_pis[9];

    // Connect our initial root to that of our inner proof. (If there is no inner proof, the
    // initial hash will be unconstrained, which is intentional.)
    let inital_root_t = builder.constant_hash(get_initial_root(num_levels));

    // The input hash is the previous hash output if we have an inner proof, or the initial hash
    // if this is the base case.
    let actual_hash_in = HashOutTarget {
        elements: core::array::from_fn(|i| {
            builder.select(
                condition,
                inner_cyclic_latest_root.elements[i],
                inital_root_t.elements[i],
            )
        }),
    };
    builder.connect_hashes(in_state_t.root_t, actual_hash_in);

    let initial_head = builder.constant_hash(Digest::ZERO);
    let actual_head = HashOutTarget {
        elements: core::array::from_fn(|i| {
            builder.select(
                condition,
                inner_checkpoint_head.elements[i],
                initial_head.elements[i],
            )
        }),
    };

    builder.connect_hashes(in_state_t.checkpoint_head_t, actual_head);

    // Our chain length will be inner_counter + 1 if we have an inner proof, or 1 if not.
    let one = builder.one();
    let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
    builder.connect(counter, new_counter);

    let zero = builder.zero();
    let actual_in_num_leaves = builder.select(condition, inner_num_leaves, zero);
    builder.connect(in_state_t.num_leaves_t, actual_in_num_leaves);

    with_context!(builder, "verify inner proof", {
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                condition,
                &inner_cyclic_proof_with_pis,
                &common_data,
            )
            .unwrap();
    });

    let all_targets = PrivateInputs {
        condition,
        inner_cyclic_proof_with_pis,
        verifier_data_target,
        prev_targets,
        new_targets,
    };

    debug!("================================================");
    builder.print_gate_counts(0);
    debug!("================================================");

    let num_gates = builder.num_gates();
    let circuit_data = builder.build::<C>();
    let degree_bits = circuit_data.common.degree_bits();

    MinnowMTOneStepCircuit {
        circuit_data,
        private_inputs: all_targets,
        circuit_info: CircuitInfo {
            num_gates,
            degree_bits,
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::DEFAULT_BATCH_SIZE;

    use super::*;
    use minnow_lib::{flatten_checkpoint_updates, hash_commitment};
    use plonky2::field::types::Field;
    use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
    use plonky2::recursion::dummy_circuit::cyclic_base_proof;
    use rstest::rstest;

    use hashbrown::HashMap;
    use log::info;
    use minnow_lib::utils::generate_sample_updates;
    use std::time::Instant;

    fn build(
        state_size: usize,
        num_checkpoint_updates: usize,
        degree_bits: Option<usize>,
    ) -> MinnowMTOneStepCircuit {
        let batch_size = DEFAULT_BATCH_SIZE;
        let num_batches = num_checkpoint_updates / batch_size;
        assert!(num_batches * batch_size == num_checkpoint_updates);
        println!(
            "state_size: {}, num_batches: {}, batch_size: {}, degree_bits: {:?}",
            state_size, num_batches, batch_size, degree_bits
        );
        let circuit = MinnowMTOneStepCircuit::new(state_size, num_batches, batch_size, degree_bits);
        if let Some(degree_bits) = degree_bits {
            assert_eq!(circuit.circuit_data.common.degree_bits(), degree_bits);
        }
        circuit
    }

    #[test]
    fn test_e2e() {
        let state_size = 10;
        let num_batches = 5;
        let batch_size = DEFAULT_BATCH_SIZE; // same as batch size per checkpoint
        let num_checkpoint_updates = 250;
        let degree_bits = None;
        let circuit = build(state_size, num_checkpoint_updates, degree_bits);
        let verifier_data = &circuit.circuit_data.verifier_only;
        let common_data = &circuit.circuit_data.common;

        // Initialize the ZK service state.
        let mut zk_service_state = MinnowMTServiceState::new(&[], state_size);
        let mut proof = cyclic_base_proof(&common_data, verifier_data, HashMap::<usize, F>::new());
        let mut prev_head = Digest::ZERO;

        // A scenario where each checkpoint has num_batches batches and we have num_checkpoints checkpoints.
        let num_checkpoints = 5;
        let total_num_batches = num_checkpoints * num_batches;
        let all_updates = generate_sample_updates(total_num_batches, batch_size);
        for c in 0..num_checkpoints {
            let checkpoint_updates = all_updates[c * num_batches..(c + 1) * num_batches].to_vec();
            let new_head = hash_commitment(&checkpoint_updates, batch_size, &prev_head);
            let flattened_updates = flatten_checkpoint_updates(checkpoint_updates);
            let pw = circuit.apply_update_batch_and_set_inputs(
                c,
                &flattened_updates,
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

    // Quick tests that run by default
    #[rstest]
    #[case(10, 300, 14)]
    #[case(20, 200, 14)]
    fn test_limits_success_quick(
        #[case] state_size: usize,
        #[case] num_checkpoint_updates: usize,
        #[case] degree_bits: usize,
    ) {
        build(state_size, num_checkpoint_updates, Some(degree_bits));
    }

    // TODO: To be fixed after the change to stream ID.
    // Comprehensive tests that only run when explicitly requested
    #[cfg(feature = "comprehensive_tests")]
    mod comprehensive {
        use super::*;
        use rstest::rstest;

        #[rstest]
        #[case(10, 300, 14)]
        #[case(10, 850, 15)]
        #[case(10, 1950, 16)]
        #[case(10, 4100, 17)]
        #[case(20, 200, 14)]
        #[case(20, 500, 15)]
        #[case(20, 1150, 16)]
        #[case(20, 2450, 17)]
        #[case(30, 100, 14)]
        #[case(30, 350, 15)]
        #[case(30, 800, 16)]
        #[case(30, 1750, 17)]
        fn test_limits_success(
            #[case] state_size: usize,
            #[case] num_checkpoint_updates: usize,
            #[case] degree_bits: usize,
        ) {
            build(state_size, num_checkpoint_updates, Some(degree_bits));
        }

        #[rstest]
        #[should_panic]
        #[case(10, 300, 14)]
        #[should_panic]
        #[case(10, 850, 15)]
        #[should_panic]
        #[case(10, 1950, 16)]
        #[should_panic]
        #[case(10, 4100, 17)]
        #[should_panic]
        #[case(20, 200, 14)]
        #[should_panic]
        #[case(20, 500, 15)]
        #[should_panic]
        #[case(20, 1150, 16)]
        #[should_panic]
        #[case(20, 2450, 17)]
        #[should_panic]
        #[case(30, 100, 14)]
        #[should_panic]
        #[case(30, 350, 15)]
        #[should_panic]
        #[case(30, 800, 16)]
        #[should_panic]
        #[case(30, 1750, 17)]
        fn test_limits_failure(
            #[case] state_size: usize,
            #[case] num_checkpoint_updates: usize,
            #[case] degree_bits: usize,
        ) {
            build(state_size, num_checkpoint_updates + 50, Some(degree_bits));
        }
    }
}
