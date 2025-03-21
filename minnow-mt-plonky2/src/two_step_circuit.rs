use log::info;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::with_context;

use crate::merkle::add_merkle_proof_verification_to_circuit;
use crate::merkle::MerkleProofTargets;
use crate::utils::common_data_for_recursion;
use crate::utils::print_system_info;
use crate::utils::CircuitInfo;
use crate::utils::Digest;
use crate::utils::{C, D, F, H};
use crate::CheckpointUpdates;
use crate::MinnowMTServiceState;

pub struct TwoStepMinnowMTCircuits {
    pub base_circuit: BaseCircuit,
    pub cyclic_wrapper_circuit: CyclicSequentialCircuit,
}

pub struct BaseInputs {
    pub prev_targets: Vec<MerkleProofTargets>,
    pub new_targets: Vec<MerkleProofTargets>,
    pub in_num_leaves_t: Target,
    pub in_checkpoint_head_t: HashOutTarget,
}

pub struct BaseOutputs {
    pub out_mt_root_t: HashOutTarget,
    pub out_checkpoint_head_t: HashOutTarget,
}

pub struct BaseCircuit {
    pub circuit_info: CircuitInfo,
    pub circuit_data: CircuitData<F, C, D>,
    pub inputs: BaseInputs,
    pub outputs: BaseOutputs,
}

impl BaseCircuit {
    /**
     * Public inputs:
     * (i) in_num_leaves_t,
     * (ii) out_num_leaves_t,
     * (iii) in_mt_root_t,
     * (iv) out_mt_root_t,
     * (v) in_checkpoint_head_t,
     * (vi) out_checkpoint_head_t
     *
     * Private inputs:
     * (i) prev_targets,
     * (ii) new_targets
     */
    pub fn new(log_state_size: usize, num_checkpoint_updates: usize) -> Self {
        info!("Building base circuit");
        let num_levels = log_state_size + 1;
        print_system_info(num_levels, num_checkpoint_updates);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut in_mt_root_t = builder.add_virtual_hash();
        let mut out_mt_root_t = builder.add_virtual_hash();

        let mut prev_targets = vec![];
        let mut new_targets = vec![];
        let mut checkpoint_commitment_inputs = vec![];

        let in_num_leaves_t = builder.add_virtual_public_input();
        let mut out_num_leaves_t = in_num_leaves_t;

        let one = builder.one();

        with_context!(builder, "process checkpoint updates", {
            for i in 0..num_checkpoint_updates {
                let t_cur: MerkleProofTargets;
                let t_new: MerkleProofTargets;
                // i) Check inclusion proof
                t_cur = add_merkle_proof_verification_to_circuit(&mut builder, num_levels);
                if i == 0 {
                    in_mt_root_t = t_cur.root_t;
                } else {
                    builder.connect_hashes(t_cur.root_t, out_mt_root_t);
                }
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
                out_mt_root_t = t_new.root_t;
            }
        });

        // Register the final root as a public input
        builder.register_public_input(out_num_leaves_t);
        builder.register_public_inputs(&in_mt_root_t.elements);
        builder.register_public_inputs(&out_mt_root_t.elements);

        let checkpoint_commitment: HashOutTarget;
        with_context!(builder, "hash checkpoint commitment", {
            checkpoint_commitment = builder.hash_or_noop::<H>(checkpoint_commitment_inputs);
        });

        // cur_head = H(inner_head || cur_commitment)
        let cur_checkpoint_head = builder.add_virtual_hash_public_input();
        let hash_chain_inputs =
            [cur_checkpoint_head.elements, checkpoint_commitment.elements].concat();
        let new_checkpoint_head = builder.hash_or_noop::<H>(hash_chain_inputs);
        builder.register_public_inputs(&new_checkpoint_head.elements);

        let inputs = BaseInputs {
            prev_targets,
            new_targets,
            in_num_leaves_t,
            in_checkpoint_head_t: cur_checkpoint_head,
        };
        let outputs = BaseOutputs {
            out_mt_root_t,
            out_checkpoint_head_t: new_checkpoint_head,
        };
        // builder.print_gate_counts(0);
        let num_gates = builder.num_gates();
        info!("Base circuit built: {} gates", num_gates);
        let circuit_data = builder.build::<C>();
        let degree_bits = circuit_data.common.degree_bits();
        BaseCircuit {
            circuit_info: CircuitInfo {
                num_gates,
                degree_bits,
            },
            circuit_data,
            inputs,
            outputs,
        }
    }

    pub fn apply_checkpoint_updates_and_set_inputs(
        &self,
        // checkpoint_number: usize,
        checkpoint_updates: &CheckpointUpdates,
        zk_service_state: &mut MinnowMTServiceState,
        cur_checkpoint_head: &Digest,
    ) -> PartialWitness<F> {
        let mut pw = PartialWitness::new();

        pw.set_target(
            self.inputs.in_num_leaves_t,
            F::from_canonical_usize(zk_service_state.get_num_leaves()),
        )
        .unwrap();
        pw.set_hash_target(self.inputs.in_checkpoint_head_t, *cur_checkpoint_head)
            .unwrap();

        for (i, update) in checkpoint_updates.iter().enumerate() {
            zk_service_state.add_proof_targets(&mut pw, &self.inputs.prev_targets[i], &update.id);
            zk_service_state.update_leaf(&update);
            zk_service_state.add_proof_targets(&mut pw, &self.inputs.new_targets[i], &update.id);
        }
        pw
    }
}

pub struct CyclicCircuitTargets {
    pub condition: BoolTarget,
    pub base_proof: ProofWithPublicInputsTarget<D>,
    pub last_proof: ProofWithPublicInputsTarget<D>,
    pub verifier_data: VerifierCircuitTarget,
}

pub struct CyclicSequentialCircuit {
    pub circuit_info: CircuitInfo,
    pub circuit_data: CircuitData<F, C, D>,
    pub targets: CyclicCircuitTargets,
}

impl CyclicSequentialCircuit {
    pub fn new(initial_root: &Digest, base_circuit_data: &CircuitData<F, C, D>) -> Self {
        info!("Building cyclic circuit");
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Base circuit
        let base_common_data = &base_circuit_data.common;
        let base_proof_with_pis = builder.add_virtual_proof_with_pis(base_common_data);
        let base_verifier_data_target =
            builder.constant_verifier_data(&base_circuit_data.verifier_only);
        with_context!(builder, "verify base proof", {
            builder.verify_proof::<C>(
                &base_proof_with_pis,
                &base_verifier_data_target,
                &base_common_data,
            );
        });

        let base_in_num_leaves = base_proof_with_pis.public_inputs[0];
        let base_out_num_leaves = base_proof_with_pis.public_inputs[1];
        let base_in_mt_root =
            HashOutTarget::try_from(&base_proof_with_pis.public_inputs[2..6]).unwrap();
        let base_out_mt_root =
            HashOutTarget::try_from(&base_proof_with_pis.public_inputs[6..10]).unwrap();
        let base_in_checkpoint_head =
            HashOutTarget::try_from(&base_proof_with_pis.public_inputs[10..14]).unwrap();
        let base_out_checkpoint_head =
            HashOutTarget::try_from(&base_proof_with_pis.public_inputs[14..18]).unwrap();

        // Make out's public
        builder.register_public_input(base_out_num_leaves);
        builder.register_public_inputs(&base_out_mt_root.elements);
        builder.register_public_inputs(&base_out_checkpoint_head.elements);

        // Condition is false for the base case, true for the recursive case.
        let condition = builder.add_virtual_bool_target_safe();
        let counter = builder.add_virtual_public_input();

        // Cyclic circuit
        let verifier_data_target = builder.add_verifier_data_public_inputs();
        // Set to 14 after trial and error (figuring out the number of gates in CyclicSequentialCircuit)
        let common_data = common_data_for_recursion(14, builder.num_public_inputs());
        let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
        let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
        with_context!(builder, "verify inner proof", {
            builder
                .conditionally_verify_cyclic_proof_or_dummy::<C>(
                    condition,
                    &inner_cyclic_proof_with_pis,
                    &common_data,
                )
                .unwrap();
        });

        let inner_num_leaves = inner_cyclic_pis[0];
        let inner_mt_root = HashOutTarget::try_from(&inner_cyclic_pis[1..5]).unwrap();
        let inner_checkpoint_head = HashOutTarget::try_from(&inner_cyclic_pis[5..9]).unwrap();
        let inner_cyclic_counter = inner_cyclic_pis[9];

        // Our chain length will be inner_counter + 1 if we have an inner proof, or 1 if not.
        let one = builder.one();
        let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
        builder.connect(counter, new_counter);

        let zero = builder.zero();
        let actual_in_num_leaves = builder.select(condition, inner_num_leaves, zero);
        builder.connect(base_in_num_leaves, actual_in_num_leaves);

        let initial_root = builder.constant_hash(*initial_root);
        let actual_in_mt_root = HashOutTarget {
            elements: core::array::from_fn(|i| {
                builder.select(
                    condition,
                    inner_mt_root.elements[i],
                    initial_root.elements[i],
                )
            }),
        };
        builder.connect_hashes(base_in_mt_root, actual_in_mt_root);

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
        builder.connect_hashes(base_in_checkpoint_head, actual_head);

        let targets = CyclicCircuitTargets {
            condition,
            base_proof: base_proof_with_pis,
            last_proof: inner_cyclic_proof_with_pis,
            verifier_data: verifier_data_target,
        };
        // builder.print_gate_counts(0);
        let num_gates = builder.num_gates();
        info!("Cyclic circuit built: {} gates", num_gates);
        let circuit_data = builder.build::<C>();
        let degree_bits = circuit_data.common.degree_bits();
        CyclicSequentialCircuit {
            circuit_info: CircuitInfo {
                num_gates,
                degree_bits,
            },
            circuit_data,
            targets,
        }
    }

    pub fn set_inputs(
        &self,
        base_case: bool,
        base_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> PartialWitness<F> {
        let mut pw = PartialWitness::new();
        pw.set_bool_target(self.targets.condition, !base_case)
            .unwrap();
        pw.set_proof_with_pis_target(&self.targets.base_proof, base_proof)
            .unwrap();
        pw.set_proof_with_pis_target(&self.targets.last_proof, prev_proof)
            .unwrap();
        pw.set_verifier_data_target(&self.targets.verifier_data, verifier_data)
            .unwrap();
        pw
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::{
        commit_single_update,
        merkle::get_initial_root,
        utils::{generate_sample_checkpoint_updates, init_logging, Digest},
    };

    use super::*;
    use hashbrown::HashMap;
    use plonky2::recursion::{
        cyclic_recursion::{self, check_cyclic_proof_verifier_data},
        dummy_circuit::cyclic_base_proof,
    };

    #[test]
    fn base_circuit_test() {
        // init_logging(log::LevelFilter::Info);
        let log_state_size = 30;
        let num_checkpoint_updates = 225;
        let circuit = BaseCircuit::new(log_state_size, num_checkpoint_updates);
        println!("{:?}", circuit.circuit_info);
        let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
        let all_checkpoint_updates = generate_sample_checkpoint_updates(1, num_checkpoint_updates);
        let old_head = Digest::ZERO;
        let old_num_leaves = zk_service_state.get_num_leaves();
        let old_root = zk_service_state.get_root();
        let pw = circuit.apply_checkpoint_updates_and_set_inputs(
            &all_checkpoint_updates[0],
            &mut zk_service_state,
            &old_head,
        );

        let start = Instant::now();
        let proof = circuit.circuit_data.prove(pw).unwrap();
        let end = Instant::now();
        info!("Proof generation time: {:?}", end.duration_since(start));

        circuit.circuit_data.verify(proof.clone()).unwrap();
        assert_eq!(
            F::from_canonical_usize(old_num_leaves),
            proof.public_inputs[0]
        );
        assert_eq!(
            F::from_canonical_usize(zk_service_state.get_num_leaves()),
            proof.public_inputs[1]
        );
        assert_eq!(old_root.elements, proof.public_inputs[2..6]);
        assert_eq!(
            zk_service_state.get_root().elements,
            proof.public_inputs[6..10]
        );
        assert_eq!(old_head.elements, proof.public_inputs[10..14]);
        let new_head = commit_single_update(&all_checkpoint_updates[0], &old_head);
        assert_eq!(new_head.elements, proof.public_inputs[14..18]);
    }

    #[test]
    fn base_circuit_benchmark() {
        let log_state_size = 30;
        let start_num_checkpoint_updates = 50;
        let step = 50;
        let end_num_checkpoint_updates = 2000;
        let mut prev_info = CircuitInfo {
            num_gates: 0,
            degree_bits: 0,
        };
        for num_checkpoint_updates in (start_num_checkpoint_updates..=end_num_checkpoint_updates).step_by(step) {
            let circuit = BaseCircuit::new(log_state_size, num_checkpoint_updates);
            // let log_num_gates = (circuit.circuit_info.num_gates as f64).log2().ceil();
            let cur_info = circuit.circuit_info;
            if cur_info.degree_bits != prev_info.degree_bits {
                println!(
                    "{} {} {}",
                    num_checkpoint_updates - step, prev_info.num_gates, prev_info.degree_bits
                );
            }
            prev_info = cur_info;
        }
    }

    #[test]
    fn test_cyclic_circuit() {
        init_logging(log::LevelFilter::Info);
        let log_state_size = 20;
        let num_checkpoint_updates = 100;
        let num_checkpoints = 10;
        let initial_root = get_initial_root(log_state_size + 1);
        let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
        let all_checkpoint_updates = generate_sample_checkpoint_updates(10, num_checkpoint_updates);

        let base_circuit = BaseCircuit::new(log_state_size, num_checkpoint_updates);
        let cyclic_circuit =
            CyclicSequentialCircuit::new(&initial_root, &base_circuit.circuit_data);
        
        info!("Base circuit: {:?}", base_circuit.circuit_info);
        info!("Cyclic circuit: {:?}", cyclic_circuit.circuit_info);

        let mut cur_head = Digest::ZERO;
        let mut base_proofs = vec![];

        // Generate all base proofs
        for i in 0..num_checkpoints {
            // Apply the first checkpoint update
            let pw = base_circuit.apply_checkpoint_updates_and_set_inputs(
                &all_checkpoint_updates[i],
                &mut zk_service_state,
                &cur_head,
            );
            let proof = base_circuit.circuit_data.prove(pw).unwrap();
            base_circuit.circuit_data.verify(proof.clone()).unwrap();
            info!("Base proof {} verified", i);
            // Update the head
            cur_head = commit_single_update(&all_checkpoint_updates[i], &cur_head);
            base_proofs.push(proof);
        }

        // Generate all cyclic proofs
        let verifier_data = &cyclic_circuit.circuit_data.verifier_only;
        let common_data = &cyclic_circuit.circuit_data.common;
        let starter_proof =
            cyclic_base_proof(&common_data, &verifier_data, HashMap::<usize, F>::new());
        let mut prev_proof = starter_proof;
        for i in 0..num_checkpoints {
            let pw = cyclic_circuit.set_inputs(
                i == 0,
                &base_proofs[i],
                &prev_proof,
                &cyclic_circuit.circuit_data.verifier_only,
            );
            let proof = cyclic_circuit.circuit_data.prove(pw).unwrap();
            cyclic_circuit.circuit_data.verify(proof.clone()).unwrap();
            check_cyclic_proof_verifier_data(&proof, verifier_data, common_data).unwrap();
            info!("Cyclic proof {} verified", i);
            prev_proof = proof;
        }
    }
}
