use log::info;
use minnow_lib::{
    hash_commitment,
    utils::{common_data_for_recursion, print_system_info, CircuitInfo, Digest, C, D, F},
    Batch,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    with_context,
};

use crate::{merkle::MerkleProofTargets, process_many_batches, CircuitState, MinnowMTServiceState};

pub type Bundle = Vec<Batch>;

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

pub struct BaseCircuitConfig {
    pub log_state_size: usize,
    pub num_batches: usize,
    pub batch_size: usize,
}

pub struct BaseCircuit {
    pub circuit_info: CircuitInfo,
    pub circuit_data: CircuitData<F, C, D>,
    pub inputs: BaseInputs,
    pub outputs: BaseOutputs,
    pub config: BaseCircuitConfig,
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
    pub fn new(log_state_size: usize, num_batches: usize, batch_size: usize) -> Self {
        info!("Building base circuit");
        let num_levels = log_state_size + 1;
        print_system_info(num_levels, num_batches, batch_size);

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

        builder.register_public_input(in_state_t.num_leaves_t);
        builder.register_public_input(out_state_t.num_leaves_t);

        builder.register_public_inputs(&in_state_t.root_t.elements);
        builder.register_public_inputs(&out_state_t.root_t.elements);

        builder.register_public_inputs(&in_state_t.checkpoint_head_t.elements);
        builder.register_public_inputs(&out_state_t.checkpoint_head_t.elements);

        let inputs = BaseInputs {
            prev_targets,
            new_targets,
            in_num_leaves_t: in_state_t.num_leaves_t,
            in_checkpoint_head_t: in_state_t.checkpoint_head_t,
        };
        let outputs = BaseOutputs {
            out_mt_root_t: out_state_t.root_t,
            out_checkpoint_head_t: out_state_t.checkpoint_head_t,
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
            config: BaseCircuitConfig {
                log_state_size,
                num_batches,
                batch_size,
            },
        }
    }

    pub fn apply_bundle_and_compute_witness(
        &self,
        bundle: &Bundle,
        zk_service_state: &mut MinnowMTServiceState,
    ) -> PartialWitness<F> {
        assert_eq!(
            bundle.len(),
            self.config.num_batches,
            "Bundle size mismatch"
        );
        for batch in bundle {
            assert_eq!(batch.len(), self.config.batch_size, "Batch size mismatch");
        }

        let mut pw = PartialWitness::new();

        pw.set_target(
            self.inputs.in_num_leaves_t,
            F::from_canonical_usize(zk_service_state.get_num_leaves()),
        )
        .unwrap();
        pw.set_hash_target(
            self.inputs.in_checkpoint_head_t,
            zk_service_state.get_head(),
        )
        .unwrap();

        for (i, update) in bundle.iter().flatten().enumerate() {
            zk_service_state.add_proof_targets(&mut pw, &self.inputs.prev_targets[i], &update.id);
            zk_service_state.update_leaf(&update);
            zk_service_state.add_proof_targets(&mut pw, &self.inputs.new_targets[i], &update.id);
        }

        let new_head = hash_commitment(
            &bundle,
            self.config.batch_size,
            &zk_service_state.get_head(),
        )
        .unwrap();
        zk_service_state.update_head(&new_head);

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

    use hashbrown::HashMap;
    use minnow_lib::utils::generate_sample_updates;
    use plonky2::recursion::{
        cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::cyclic_base_proof,
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        merkle::get_initial_root,
        test_utils::{BaseProofMessage, PartialWitnessMessage},
    };

    #[test]
    fn base_circuit_test() {
        let log_state_size = 10;
        let num_batches = 5; // also equal to num_batches_per_checkpoint
        let batch_size = 10;
        let circuit = BaseCircuit::new(log_state_size, num_batches, batch_size);
        println!("{:?}", circuit.circuit_info);
        let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
        let checkpoint_updates = generate_sample_updates(num_batches, batch_size);

        let old_head = zk_service_state.get_head();
        let old_num_leaves = zk_service_state.get_num_leaves();
        let old_root = zk_service_state.get_root();

        let pw =
            circuit.apply_bundle_and_compute_witness(&checkpoint_updates, &mut zk_service_state);
        let new_head = zk_service_state.get_head();

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
        assert_eq!(new_head.elements, proof.public_inputs[14..18]);
    }

    #[test]
    fn test_e2e() {
        let log_state_size = 10;
        let num_batches_per_checkpoint = 5; // also equal to num_batches_per_checkpoint
        let batch_size = 10;
        let num_checkpoints = 5;
        let all_checkpoint_updates =
            generate_sample_updates(num_checkpoints * num_batches_per_checkpoint, batch_size);
        let all_checkpoint_updates: Vec<Bundle> = all_checkpoint_updates
            .chunks(num_batches_per_checkpoint)
            .map(|chunk| chunk.to_vec())
            .collect();

        let initial_root = get_initial_root(log_state_size + 1);
        let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);

        let base_circuit = BaseCircuit::new(log_state_size, num_batches_per_checkpoint, batch_size);
        let cyclic_circuit =
            CyclicSequentialCircuit::new(&initial_root, &base_circuit.circuit_data);

        println!("Base circuit: {:?}", base_circuit.circuit_info);
        println!("Cyclic circuit: {:?}", cyclic_circuit.circuit_info);

        let mut base_proofs = vec![];

        // Generate all base proofs
        for i in 0..num_checkpoints {
            let sample_updates = all_checkpoint_updates[i].clone();
            let pw = base_circuit
                .apply_bundle_and_compute_witness(&sample_updates, &mut zk_service_state);
            let proof = base_circuit.circuit_data.prove(pw).unwrap();
            base_proofs.push(proof.clone());

            base_circuit.circuit_data.verify(proof).unwrap();
            println!("Base proof {} verified", i);
            println!("Cur head: {:?}", zk_service_state.get_head());
        }

        // Generate all cyclic proofs sequentially
        let verifier_data = &cyclic_circuit.circuit_data.verifier_only;
        let common_data = &cyclic_circuit.circuit_data.common;
        let starter_proof =
            cyclic_base_proof(&common_data, &verifier_data, HashMap::<usize, F>::new());
        let mut prev_proof = starter_proof;
        for i in 0..num_checkpoints {
            let pw =
                cyclic_circuit.set_inputs(i == 0, &base_proofs[i], &prev_proof, &verifier_data);
            let proof = cyclic_circuit.circuit_data.prove(pw).unwrap();
            cyclic_circuit.circuit_data.verify(proof.clone()).unwrap();
            check_cyclic_proof_verifier_data(&proof, verifier_data, common_data).unwrap();
            info!("Cyclic proof {} verified", i);
            prev_proof = proof;
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn multi_machine_simulation() {
        let log_state_size = 2;
        let num_batches_per_checkpoint = 3;
        let batch_size = 2;
        let num_checkpoints = 3;
        let all_checkpoint_updates =
            generate_sample_updates(num_checkpoints * num_batches_per_checkpoint, batch_size);
        let all_checkpoint_updates: Vec<Bundle> = all_checkpoint_updates
            .chunks(num_batches_per_checkpoint)
            .map(|chunk| chunk.to_vec())
            .collect();

        // Initialize the initial root and state for the primary
        let initial_root = get_initial_root(log_state_size + 1);
        let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
        let base_circuit = BaseCircuit::new(log_state_size, num_batches_per_checkpoint, batch_size);
        let circuit_data = &base_circuit.circuit_data;
        let cyclic_circuit = CyclicSequentialCircuit::new(&initial_root, &circuit_data);
        tracing::info!("Base circuit: {:?}", base_circuit.circuit_info);

        // Channels for communication between tasks
        let (tx_proxy_1_pw, rx_proxy_1_pw) = mpsc::channel(10);
        let (tx_proxy_2_pw, rx_proxy_2_pw) = mpsc::channel(10);
        let (tx_cyclic_prover_pw, mut rx_cyclic_prover_pw) = mpsc::channel(10);

        // Running on the Primary: Generate all base proofs
        let hasher_handle = tokio::spawn(async move {
            for i in 0..num_checkpoints {
                tracing::info!("[primary] Processing checkpoint {i}");
                let sample_updates = all_checkpoint_updates[i].clone();
                let pw = base_circuit
                    .apply_bundle_and_compute_witness(&sample_updates, &mut zk_service_state);

                let message = PartialWitnessMessage {
                    index: i as u64,
                    witness: pw,
                };
                let serialized = bincode::serialize(&message).unwrap();
                if i % 2 == 0 {
                    tx_proxy_1_pw.send(serialized).await.unwrap();
                } else {
                    tx_proxy_2_pw.send(serialized).await.unwrap();
                }
            }

            // Close the channels to signal completion
            drop(tx_proxy_1_pw);
            drop(tx_proxy_2_pw);
            tracing::info!("[primary] Primary has sent all partial witnesses");
        });

        // Proxy: Compute the base proofs
        let tx_cyclic_prover_1 = tx_cyclic_prover_pw.clone();
        let proxy_1_handle = tokio::spawn(async move {
            let base_circuit =
                BaseCircuit::new(log_state_size, num_batches_per_checkpoint, batch_size);
            crate::test_utils::spawn_proxy_prover(rx_proxy_1_pw, tx_cyclic_prover_1, &base_circuit)
                .await;
            tracing::info!("[proxy 1] Proxy 1 has completed its work");
        });
        let proxy_2_handle = tokio::spawn(async move {
            let base_circuit =
                BaseCircuit::new(log_state_size, num_batches_per_checkpoint, batch_size);
            crate::test_utils::spawn_proxy_prover(
                rx_proxy_2_pw,
                tx_cyclic_prover_pw,
                &base_circuit,
            )
            .await;
            tracing::info!("[proxy 2] Proxy 2 has completed its work");
        });

        // Primary: Compute the cyclic proofs
        let cyclic_prover_handle = tokio::spawn(async move {
            let mut next_index = 0;
            let mut base_proofs = HashMap::new();

            let verifier_data = &cyclic_circuit.circuit_data.verifier_only;
            let common_data = &cyclic_circuit.circuit_data.common;
            let starter_proof =
                cyclic_base_proof(&common_data, &verifier_data, HashMap::<usize, F>::new());
            let mut prev_proof = starter_proof;

            'main: while let Some(serialized) = rx_cyclic_prover_pw.recv().await {
                let message = bincode::deserialize(&serialized).unwrap();
                let BaseProofMessage { index, proof } = message;
                tracing::info!("[primary] Received base proof message #{index:?}");
                base_proofs.insert(index, proof);

                loop {
                    let base_proof = match base_proofs.get(&next_index) {
                        Some(proof) => proof,
                        None => {
                            tracing::info!("Waiting for base proof {next_index}");
                            continue 'main;
                        }
                    };

                    let pw = cyclic_circuit.set_inputs(
                        next_index == 0,
                        &base_proof,
                        &prev_proof,
                        &verifier_data,
                    );
                    let proof = cyclic_circuit.circuit_data.prove(pw).unwrap();
                    cyclic_circuit.circuit_data.verify(proof.clone()).unwrap();
                    check_cyclic_proof_verifier_data(&proof, verifier_data, common_data).unwrap();

                    tracing::info!("[primary] Cyclic proof #{next_index} verified");
                    prev_proof = proof;
                    next_index += 1;
                    tracing::info!("[primary] Moving to next cyclic proof {next_index}");
                }
            }
            tracing::info!("[primary] Cyclic prover has completed its work");
        });

        // Wait for all tasks to complete
        futures::future::join_all(vec![
            hasher_handle,
            proxy_1_handle,
            proxy_2_handle,
            cyclic_prover_handle,
        ])
        .await;
    }
}
