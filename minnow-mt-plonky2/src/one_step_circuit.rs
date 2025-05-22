use log::debug;
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

use crate::merkle::add_merkle_proof_verification_to_circuit;
use crate::merkle::get_initial_root;
use crate::merkle::MerkleProofTargets;
use crate::MinnowMTServiceState;
use minnow_lib::utils::common_data_for_recursion;
use minnow_lib::utils::print_system_info;
use minnow_lib::utils::CircuitInfo;
use minnow_lib::utils::{Digest, C, D, F, H};
use minnow_lib::CheckpointUpdates;
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
        num_checkpoint_updates: usize,
        degree_bits: Option<usize>,
    ) -> Self {
        build_circuit(state_size, num_checkpoint_updates, degree_bits)
    }

    pub fn apply_checkpoint_updates_and_set_inputs(
        &self,
        checkpoint_number: usize,
        checkpoint_updates: &CheckpointUpdates,
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

        for (i, update) in checkpoint_updates.iter().enumerate() {
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
    num_checkpoint_updates: usize,
    degree_bits: Option<usize>,
) -> MinnowMTOneStepCircuit {
    let num_levels = log_state_size + 1;
    print_system_info(num_levels, num_checkpoint_updates);

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

    // For the base case, in_root_t is the initial root. Otherwise, it is the previous root.
    let in_root_t = builder.add_virtual_hash();
    let mut out_root_t = in_root_t;

    let mut prev_targets = vec![];
    let mut new_targets = vec![];
    let mut checkpoint_commitment_inputs = vec![];

    // num_leaves_start will be connected to the number of leaves from the previous circuit.
    let in_num_leaves_t = builder.add_virtual_target();
    let mut out_num_leaves_t = in_num_leaves_t;

    let one = builder.one();
    let zero = builder.zero();

    with_context!(builder, "process checkpoint updates", {
        for _ in 0..num_checkpoint_updates {
            let t_cur: MerkleProofTargets;
            let t_new: MerkleProofTargets;
            // i) Check inclusion proof
            t_cur = add_merkle_proof_verification_to_circuit(&mut builder, num_levels);
            builder.connect_hashes(t_cur.root_t, out_root_t);
            prev_targets.push(t_cur.clone());

            // ii) Check inclusion proof after update
            t_new = add_merkle_proof_verification_to_circuit(&mut builder, num_levels);
            new_targets.push(t_new.clone());

            // iii) Connect the siblings
            assert_eq!(t_cur.proof_t.siblings.len(), t_new.proof_t.siblings.len());
            for i in 0..t_cur.proof_t.siblings.len() {
                builder.connect_hashes(t_cur.proof_t.siblings[i], t_new.proof_t.siblings[i]);
            }

            // (iv) Logic: If old leaf, check that stream IDs match. If new leaf, check that index is incremented.
            // if t_new.leaf_t.new_flag_t
            //  then assert (t_new.index_t == num_leaves) && (num_leaves += 1)
            // else assert (t_new.index_t == t_cur.index_t) && (t_new.leaf_t.stream_id_t == t_cur.leaf_t.stream_id_t)
            let b1 = builder.is_equal(t_new.index_t, out_num_leaves_t);
            let b2 = builder.is_equal(t_new.leaf_t.stream_id_t, t_cur.leaf_t.stream_id_t);
            let b3 = builder.is_equal(t_new.index_t, t_cur.index_t);
            let new_flag = t_new.leaf_t.new_flag_t;

            // if new_flag then b1 = true
            let b5 = builder.select(new_flag, b1.target, one);
            builder.assert_one(b5);

            let next_index = builder.add(out_num_leaves_t, one);
            out_num_leaves_t = builder.select(new_flag, next_index, out_num_leaves_t);

            // if not new_flag then b2 = true
            let b6 = builder.select(new_flag, one, b2.target);
            builder.assert_one(b6);

            // if not new_flag then b3 = true
            let b7 = builder.select(new_flag, one, b3.target);
            builder.assert_one(b7);

            // v) MerkleLeaf === StreamPoint, so we can use the same targets to compute the checkpoint commitment
            checkpoint_commitment_inputs.extend(t_new.leaf_t.get_all_targets());

            // vi) Update the current root
            out_root_t = t_new.root_t;
        }
    });

    // Register the final root as a public input
    builder.register_public_inputs(&out_root_t.elements);

    let cur_checkpoint_head = builder.add_virtual_hash_public_input();
    let checkpoint_commitment: HashOutTarget;
    with_context!(builder, "hash checkpoint commitment", {
        checkpoint_commitment = builder.hash_or_noop::<H>(checkpoint_commitment_inputs);
    });

    let counter = builder.add_virtual_public_input();
    builder.register_public_input(out_num_leaves_t);

    let expected_degree_bits =
        degree_bits.unwrap_or_else(|| estimate_degree_bits(num_levels, num_checkpoint_updates));
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
    builder.connect_hashes(in_root_t, actual_hash_in);

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
    // cur_head = H(inner_head || cur_commitment)
    let hash_chain_inputs = [actual_head.elements, checkpoint_commitment.elements].concat();
    let expected_checkpoint_head = builder.hash_or_noop::<H>(hash_chain_inputs);
    builder.connect_hashes(cur_checkpoint_head, expected_checkpoint_head);

    // Our chain length will be inner_counter + 1 if we have an inner proof, or 1 if not.
    let one = builder.one();
    let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
    builder.connect(counter, new_counter);

    let actual_in_num_leaves = builder.select(condition, inner_num_leaves, zero);
    builder.connect(in_num_leaves_t, actual_in_num_leaves);

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
    use super::*;
    use rstest::rstest;

    fn build(state_size: usize, num_checkpoint_updates: usize, degree_bits: Option<usize>) {
        println!(
            "state_size: {}, num_checkpoint_updates: {}, degree_bits: {:?}",
            state_size, num_checkpoint_updates, degree_bits
        );
        let circuit = MinnowMTOneStepCircuit::new(state_size, num_checkpoint_updates, degree_bits);
        assert_eq!(
            circuit.circuit_data.common.degree_bits(),
            degree_bits.unwrap()
        );
    }

    // Quick tests that run by default
    #[rstest]
    #[case(10, 350, 14)]
    #[case(20, 200, 14)]
    fn test_limits_success_quick(
        #[case] state_size: usize,
        #[case] num_checkpoint_updates: usize,
        #[case] degree_bits: usize,
    ) {
        build(state_size, num_checkpoint_updates, Some(degree_bits));
    }

    // Comprehensive tests that only run when explicitly requested
    #[cfg(feature = "comprehensive_tests")]
    mod comprehensive {
        use super::*;
        use rstest::rstest;

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
}
