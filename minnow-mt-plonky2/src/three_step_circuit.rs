use log::debug;
use log::info;
use minnow_lib::hash_commitment;
use minnow_lib::utils::Digest;
use minnow_lib::Bundle;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::with_context;

use crate::merkle::get_initial_root;
use crate::two_step_circuit::{BaseCircuit, CyclicSequentialCircuit};
use crate::MinnowMTServiceState;

use hashbrown::HashMap;
use std::time::Instant;

use minnow_lib::utils::CircuitInfo;
use minnow_lib::utils::{C, D, F};

pub struct ThreeStepMinnowMTCircuitConfig {
    pub log_state_size: usize,
    pub bundle_size: usize,
    pub sub_bundle_size: usize,
    pub batch_size: usize,
    pub branching_factor: usize,
    pub num_base_circuits_to_compress: usize,
    pub num_compression_levels: u32,
}

pub struct ThreeStepMinnowMTCircuits {
    pub base_circuit: BaseCircuit,
    pub compressed_circuits: Vec<CompressedCircuit>,
    pub sequential_circuit: CyclicSequentialCircuit,
    pub config: ThreeStepMinnowMTCircuitConfig,
}

impl ThreeStepMinnowMTCircuits {
    pub fn new(
        log_state_size: usize,
        bundle_size: usize,
        sub_bundle_size: usize,
        batch_size: usize,
        branching_factor: usize,
    ) -> Self {
        let num_batches_per_bundle = bundle_size / batch_size;
        assert!(bundle_size % batch_size == 0);
        let num_batches_per_base_circuit = sub_bundle_size / batch_size;
        assert!(sub_bundle_size % batch_size == 0);

        info!("num_batches_per_bundle: {}", num_batches_per_bundle);
        info!(
            "num_batches_per_base_circuit: {}",
            num_batches_per_base_circuit
        );

        let base_circuit =
            BaseCircuit::new(log_state_size, num_batches_per_base_circuit, batch_size);

        // ceil(bundle_size / sub_bundle_size)
        let num_base_circuits_to_compress = bundle_size.div_ceil(sub_bundle_size);
        println!(
            "num_base_circuits_to_compress: {}",
            num_base_circuits_to_compress
        );

        // Compute ceil(log_branching_factor(num_base_circuits_to_compress))
        let mut num_compression_levels = num_base_circuits_to_compress.ilog(branching_factor);
        if branching_factor.pow(num_compression_levels) < num_base_circuits_to_compress {
            num_compression_levels += 1;
        }
        assert!(branching_factor.pow(num_compression_levels) >= num_base_circuits_to_compress);

        let mut compressed_circuits: Vec<CompressedCircuit> = vec![];
        for _ in 0..num_compression_levels {
            if let Some(last_circuit_data) = compressed_circuits.last() {
                let compressed_circuit =
                    CompressedCircuit::new(&last_circuit_data.circuit_data, branching_factor);
                compressed_circuits.push(compressed_circuit);
            } else {
                let compressed_circuit =
                    CompressedCircuit::new(&base_circuit.circuit_data, branching_factor);
                compressed_circuits.push(compressed_circuit);
            }
        }

        let root_circuit = compressed_circuits.last().unwrap();

        let initial_root = get_initial_root(log_state_size + 1);
        let sequential_circuit =
            CyclicSequentialCircuit::new(&initial_root, &root_circuit.circuit_data);
        Self {
            base_circuit,
            compressed_circuits,
            sequential_circuit,
            config: ThreeStepMinnowMTCircuitConfig {
                log_state_size,
                bundle_size,
                sub_bundle_size,
                batch_size,
                branching_factor,
                num_base_circuits_to_compress,
                num_compression_levels,
            },
        }
    }

    pub fn apply_bundle_and_prove(
        &self,
        bundle: &Bundle,
        zk_service_state: &mut MinnowMTServiceState,
        cur_head: &Digest,
        mut prev_sequential_proof: Option<ProofWithPublicInputs<F, C, D>>,
        verify_proofs: bool,
    ) -> (Digest, ProofWithPublicInputs<F, C, D>) {
        assert_eq!(
            bundle.len(),
            self.config.bundle_size / self.config.batch_size,
            "Bundle size mismatch"
        );
        for batch in bundle {
            assert_eq!(batch.len(), self.config.batch_size, "Batch size mismatch");
        }
        info!("================Prove bundle================================");

        // Generate all base proofs
        let num_sub_bundles = self
            .config
            .bundle_size
            .div_ceil(self.config.sub_bundle_size);
        debug!("Number of sub-bundles: {}", num_sub_bundles);
        let mut base_proofs = vec![];
        let num_batches_per_sub_bundle = self.config.sub_bundle_size / self.config.batch_size;
        let mut cur_head = cur_head.clone();
        for i in 0..num_sub_bundles {
            let sample_updates = bundle
                [i * num_batches_per_sub_bundle..(i + 1) * num_batches_per_sub_bundle]
                .to_vec();
            let new_head = hash_commitment(&sample_updates, self.config.batch_size, &cur_head);
            let pw = self.base_circuit.apply_bundle_and_compute_witness(
                &sample_updates,
                zk_service_state,
                &cur_head,
            );
            let start = Instant::now();
            let proof = self.base_circuit.circuit_data.prove(pw).unwrap();
            base_proofs.push(proof.clone());
            let end = Instant::now();
            info!(
                "Base proof {} generation time: {:?}",
                i,
                end.duration_since(start)
            );

            // To be run by the verifier
            if verify_proofs {
                self.base_circuit.circuit_data.verify(proof).unwrap();
                info!("Base proof {} verified", i);
            }

            cur_head = new_head;
        }

        // Generate the compressed proofs sequentially. At each level, use the previous level's proofs as inputs.

        let mut cur_level_proofs = base_proofs;
        for i in 0..self.config.num_compression_levels {
            let compressed_circuit = &self.compressed_circuits[i as usize];
            // let cur_level_proofs_refs: Vec<&ProofWithPublicInputs<F, C, D>> = cur_level_proofs.iter().collect();
            let num_proofs_to_generate = cur_level_proofs.len() / self.config.branching_factor;
            let mut new_level_proofs = vec![];
            for j in 0..num_proofs_to_generate {
                let cur_level_proof_refs: Vec<&ProofWithPublicInputs<F, C, D>> = cur_level_proofs
                    [j * self.config.branching_factor..(j + 1) * self.config.branching_factor]
                    .iter()
                    .collect();
                let pw = compressed_circuit.set_inputs(&cur_level_proof_refs);
                let start = Instant::now();
                let proof = compressed_circuit.circuit_data.prove(pw).unwrap();
                new_level_proofs.push(proof.clone());
                let end = Instant::now();
                info!(
                    "Level {} compressed proof {} generation time: {:?}",
                    i,
                    j,
                    end.duration_since(start)
                );

                if verify_proofs {
                    compressed_circuit
                        .circuit_data
                        .verify(proof.clone())
                        .unwrap();
                    info!("Level {} compressed proof {} verified", i, j);
                }
            }
            cur_level_proofs = new_level_proofs;
        }

        let sequential_circuit = &self.sequential_circuit;
        assert_eq!(
            cur_level_proofs.len(),
            1,
            "Expected 1 proof at the end of compression"
        );
        let mut base_case = false;
        if prev_sequential_proof.is_none() {
            base_case = true;
            let verifier_data = &sequential_circuit.circuit_data.verifier_only;
            let common_data = &sequential_circuit.circuit_data.common;
            let starter_proof =
                cyclic_base_proof(&common_data, &verifier_data, HashMap::<usize, F>::new());
            prev_sequential_proof = Some(starter_proof);
        }
        let prev_sequential_proof = prev_sequential_proof.unwrap();

        let pw = sequential_circuit.set_inputs(
            base_case,
            &cur_level_proofs[0],
            &prev_sequential_proof,
            &sequential_circuit.circuit_data.verifier_only,
        );
        let proof = sequential_circuit.circuit_data.prove(pw).unwrap();
        if verify_proofs {
            sequential_circuit
                .circuit_data
                .verify(proof.clone())
                .unwrap();
            info!("Sequential proof verified");
        }

        (cur_head, proof)
    }
}

pub struct CompressedCircuit {
    pub circuit_info: CircuitInfo,
    pub circuit_data: CircuitData<F, C, D>,
    pub targets: Targets,
}

pub struct Targets {
    pub in_proofs: Vec<ProofWithPublicInputsTarget<D>>,
}

impl CompressedCircuit {
    pub fn new(in_circuit_data: &CircuitData<F, C, D>, num_proofs_to_compress: usize) -> Self {
        info!(
            "Building compressed circuit for {:?}",
            in_circuit_data.verifier_only.circuit_digest
        );
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut in_proofs = vec![];
        let mut cur_num_leaves = builder.add_virtual_target();
        let mut cur_checkpoint_head = builder.add_virtual_hash();
        let mut cur_mt_root = builder.add_virtual_hash();
        for i in 0..num_proofs_to_compress {
            let in_common_data = &in_circuit_data.common;
            let in_proof_with_pis = builder.add_virtual_proof_with_pis(in_common_data);
            let in_verifier_data_target =
                builder.constant_verifier_data(&in_circuit_data.verifier_only);
            with_context!(builder, "verify in proof", {
                builder.verify_proof::<C>(
                    &in_proof_with_pis,
                    &in_verifier_data_target,
                    &in_common_data,
                );
            });
            let in_num_leaves = in_proof_with_pis.public_inputs[0];
            let out_num_leaves = in_proof_with_pis.public_inputs[1];
            let in_mt_root =
                HashOutTarget::try_from(&in_proof_with_pis.public_inputs[2..6]).unwrap();
            let out_mt_root =
                HashOutTarget::try_from(&in_proof_with_pis.public_inputs[6..10]).unwrap();
            let in_checkpoint_head =
                HashOutTarget::try_from(&in_proof_with_pis.public_inputs[10..14]).unwrap();
            let out_checkpoint_head =
                HashOutTarget::try_from(&in_proof_with_pis.public_inputs[14..18]).unwrap();
            if i != 0 {
                builder.connect(cur_num_leaves, in_num_leaves);
                builder.connect_hashes(cur_checkpoint_head, in_checkpoint_head);
                builder.connect_hashes(cur_mt_root, in_mt_root);
            }
            cur_num_leaves = out_num_leaves;
            cur_checkpoint_head = out_checkpoint_head;
            cur_mt_root = out_mt_root;
            in_proofs.push(in_proof_with_pis);
        }

        // Make the first proof's inputs and last proof's outputs public.
        // We retain the same shape for the pub inputs as the BaseCircuit.
        let first_proof = in_proofs.first().unwrap();
        let last_proof = in_proofs.last().unwrap();

        builder.register_public_input(first_proof.public_inputs[0]);
        builder.register_public_input(last_proof.public_inputs[1]);

        builder.register_public_inputs(&first_proof.public_inputs[2..6]);
        builder.register_public_inputs(&last_proof.public_inputs[6..10]);

        builder.register_public_inputs(&first_proof.public_inputs[10..14]);
        builder.register_public_inputs(&last_proof.public_inputs[14..18]);

        let num_gates = builder.num_gates();
        info!("Compressed circuit built: {} gates", num_gates);
        let circuit_data = builder.build::<C>();

        CompressedCircuit {
            circuit_info: CircuitInfo {
                num_gates,
                degree_bits: circuit_data.common.degree_bits(),
            },
            circuit_data,
            targets: Targets { in_proofs },
        }
    }

    pub fn set_inputs(&self, in_proofs: &[&ProofWithPublicInputs<F, C, D>]) -> PartialWitness<F> {
        assert_eq!(in_proofs.len(), self.targets.in_proofs.len());
        let mut pw = PartialWitness::new();
        for i in 0..self.targets.in_proofs.len() {
            pw.set_proof_with_pis_target(&self.targets.in_proofs[i], &in_proofs[i])
                .unwrap();
        }
        pw
    }
}

#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::MinnowMTServiceState;
    use minnow_lib::hash_commitment;
    use minnow_lib::utils::{
        generate_sample_checkpoint_updates, generate_sample_updates, set_log_level, Digest,
    };
    use std::time::Instant;

    #[test]
    fn test_compressed_circuit() {
        let log_state_size = 10;
        let num_batches = 6;
        let batch_size = 50;
        let num_checkpoints = 2;
        // let num_batches_per_base_circuit = 2;
        // let total_num_batches = num_batches_per_base_circuit * num_batches;
        let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
        let circuit = BaseCircuit::new(log_state_size, num_batches, batch_size);

        // Generate two base proofs
        let all_checkpoint_updates =
            generate_sample_checkpoint_updates(num_checkpoints, num_batches, batch_size);
        let mut head = Digest::ZERO;
        let pw = circuit.apply_bundle_and_compute_witness(
            &all_checkpoint_updates[0],
            &mut zk_service_state,
            &head,
        );
        let base_proof_0 = circuit.circuit_data.prove(pw).unwrap();
        head = hash_commitment(&all_checkpoint_updates[0], batch_size, &head);
        let pw = circuit.apply_bundle_and_compute_witness(
            &all_checkpoint_updates[1],
            &mut zk_service_state,
            &head,
        );
        let base_proof_1 = circuit.circuit_data.prove(pw).unwrap();

        let compressed_circuit = CompressedCircuit::new(&circuit.circuit_data, 2);
        let pw = compressed_circuit.set_inputs(&[&base_proof_0, &base_proof_1]);
        let start = Instant::now();
        let combined_proof = compressed_circuit.circuit_data.prove(pw).unwrap();
        let end = Instant::now();
        info!("Proof generation time: {:?}", end.duration_since(start));
        compressed_circuit
            .circuit_data
            .verify(combined_proof.clone())
            .unwrap();
        assert_eq!(
            combined_proof.public_inputs[0],
            base_proof_0.public_inputs[0]
        );
        assert_eq!(
            combined_proof.public_inputs[1],
            base_proof_1.public_inputs[1]
        );
        assert_eq!(
            combined_proof.public_inputs[2..6],
            base_proof_0.public_inputs[2..6]
        );
        assert_eq!(
            combined_proof.public_inputs[6..10],
            base_proof_1.public_inputs[6..10]
        );
        assert_eq!(
            combined_proof.public_inputs[10..14],
            base_proof_0.public_inputs[10..14]
        );
        assert_eq!(
            combined_proof.public_inputs[14..18],
            base_proof_1.public_inputs[14..18]
        );
    }

    #[test]
    fn test_a_possibly_optimal_config() {
        let log_state_size = 30;
        let bundle_size = 500;
        let batch_size = 25;
        let sub_bundle_size = 225;
        let branching_factor = 3;

        assert!(sub_bundle_size % batch_size == 0);
        let three_step_circuit = ThreeStepMinnowMTCircuits::new(
            log_state_size,
            bundle_size,
            sub_bundle_size,
            batch_size,
            branching_factor,
        );
        println!(
            "Base circuit info: {:?}",
            three_step_circuit.base_circuit.circuit_info
        );
        println!(
            "Compressed circuit info: {:?}",
            three_step_circuit.compressed_circuits[0].circuit_info
        );
        println!(
            "Sequential circuit info: {:?}",
            three_step_circuit.sequential_circuit.circuit_info
        );

        assert_eq!(three_step_circuit.base_circuit.circuit_info.degree_bits, 14);
        assert_eq!(three_step_circuit.compressed_circuits.len(), 1);
        assert_eq!(
            three_step_circuit.compressed_circuits[0]
                .circuit_info
                .degree_bits,
            14
        );
        assert_eq!(
            three_step_circuit
                .sequential_circuit
                .circuit_info
                .degree_bits,
            14
        );
    }

    #[test]
    fn test_e2e() {
        let log_state_size = 20;
        let batch_size = 25;
        let sub_bundle_size = 225;
        let branching_factor = 3;
        let bundle_size = sub_bundle_size * branching_factor * branching_factor; // 675

        let three_step_circuit = ThreeStepMinnowMTCircuits::new(
            log_state_size,
            bundle_size,
            sub_bundle_size,
            batch_size,
            branching_factor,
        );
        assert_eq!(three_step_circuit.base_circuit.circuit_info.degree_bits, 14);
        assert_eq!(three_step_circuit.compressed_circuits.len(), 2);
        assert_eq!(
            three_step_circuit.compressed_circuits[0]
                .circuit_info
                .degree_bits,
            14
        );
        assert_eq!(
            three_step_circuit.compressed_circuits[1]
                .circuit_info
                .degree_bits,
            14
        );
        assert_eq!(
            three_step_circuit
                .sequential_circuit
                .circuit_info
                .degree_bits,
            14
        );

        let num_bundles = 3;
        let num_batches_per_bundle = bundle_size / batch_size;
        let sample_updates =
            generate_sample_updates(num_batches_per_bundle * num_bundles, batch_size);
        let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
        let mut cur_head = Digest::ZERO;

        let mut prev_sequential_proof = None;
        for i in 0..num_bundles {
            let bundle = &sample_updates
                [i * num_batches_per_bundle..(i + 1) * num_batches_per_bundle]
                .to_vec();
            let (new_head, proof) = three_step_circuit.apply_bundle_and_prove(
                bundle,
                &mut zk_service_state,
                &cur_head,
                prev_sequential_proof,
                true,
            );
            cur_head = new_head;
            prev_sequential_proof = Some(proof);
        }
    }
}
