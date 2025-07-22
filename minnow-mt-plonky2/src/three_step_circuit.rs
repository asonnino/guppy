use hashbrown::HashMap;
use log::info;
use minnow_lib::{
    utils::{generate_sample_updates, CircuitInfo, MyPartialWitness, Proof, C, D, F},
    Batch,
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        proof::ProofWithPublicInputsTarget,
    },
    recursion::dummy_circuit::cyclic_base_proof,
    with_context,
};
use serde::{Deserialize, Serialize};

use crate::{
    merkle::get_initial_root,
    two_step_circuit::{BaseCircuit, CyclicSequentialCircuit},
    MinnowMTServiceState,
};

pub type SubBundle = Vec<Batch>;
pub type Bundle = Vec<SubBundle>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinnowBConfig {
    pub log_state_size: usize,
    pub batch_size: usize,
    pub num_batches_per_sub_bundle: usize,
    pub branching_factor: usize,
    pub num_compression_levels: u32,
    pub bundle_size: usize,
    pub sub_bundle_size: usize,
    pub num_sub_bundles: usize,
}

impl Default for MinnowBConfig {
    fn default() -> Self {
        let log_state_size = 10;
        let branching_factor = 2;
        let num_compression_levels = 2;
        let batch_size = 10;
        let num_batches_per_sub_bundle = 2;
        Self::new(
            log_state_size,
            batch_size,
            num_batches_per_sub_bundle,
            branching_factor,
            num_compression_levels,
        )
    }
}

impl MinnowBConfig {
    pub fn new(
        log_state_size: usize,
        batch_size: usize,
        num_batches_per_sub_bundle: usize,
        branching_factor: usize,
        num_compression_levels: u32,
    ) -> Self {
        let sub_bundle_size = num_batches_per_sub_bundle * batch_size;
        let bundle_size = sub_bundle_size * (branching_factor.pow(num_compression_levels));
        let num_sub_bundles = bundle_size / sub_bundle_size;

        // println!(
        //     "num_base_circuits_to_compress / num_sub_bundles: {}",
        //     num_sub_bundles
        // );
        assert!(branching_factor.pow(num_compression_levels) == num_sub_bundles);

        Self {
            log_state_size,
            batch_size,
            num_batches_per_sub_bundle,
            branching_factor,
            num_compression_levels,
            bundle_size,
            sub_bundle_size,
            num_sub_bundles,
        }
    }

    pub fn get_bundle_size(&self) -> usize {
        let sub_bundle_size = self.batch_size * self.num_batches_per_sub_bundle;
        sub_bundle_size * self.branching_factor.pow(self.num_compression_levels)
    }

    pub fn get_sub_bundle_size(&self) -> usize {
        self.batch_size * self.num_batches_per_sub_bundle
    }

    pub fn generate_single_sample_bundle(&self) -> Bundle {
        let num_batches_per_bundle = self.get_bundle_size() / self.batch_size;
        let all_batches = generate_sample_updates(num_batches_per_bundle, self.batch_size);
        all_batches
            .chunks(self.num_batches_per_sub_bundle)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    pub fn generate_multiple_sample_bundles(&self, num_bundles: usize) -> Vec<Bundle> {
        let num_batches_per_bundle = self.get_bundle_size() / self.batch_size;
        let all_batches =
            generate_sample_updates(num_batches_per_bundle * num_bundles, self.batch_size);
        let all_sub_bundles: Vec<SubBundle> = all_batches
            .chunks(self.num_batches_per_sub_bundle)
            .map(|chunk| chunk.to_vec())
            .collect();
        all_sub_bundles
            .chunks(self.num_sub_bundles)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    pub fn sanity_check_bundle(&self, bundle: &Bundle) {
        assert_eq!(bundle.len(), self.num_sub_bundles, "Bundle size mismatch");
        for sub_bundle in bundle {
            assert_eq!(
                sub_bundle.len(),
                self.num_batches_per_sub_bundle,
                "Batch size mismatch"
            );
            for batch in sub_bundle {
                assert_eq!(batch.len(), self.batch_size, "Batch size mismatch");
            }
        }
    }
}

pub struct MinnowBCircuits {
    pub base_circuit: BaseCircuit,
    pub compressed_circuits: Vec<CompressedCircuit>,
    pub sequential_circuit: CyclicSequentialCircuit,
    pub config: MinnowBConfig,
}

impl MinnowBCircuits {
    pub fn new_with_config(config: &MinnowBConfig) -> Self {
        println!("Building circuits with config: {:?}", config);
        let log_state_size = config.log_state_size;
        let batch_size = config.batch_size;
        let num_batches_per_sub_bundle = config.num_batches_per_sub_bundle;
        let branching_factor = config.branching_factor;
        let num_compression_levels = config.num_compression_levels;

        Self::new(
            log_state_size,
            batch_size,
            num_batches_per_sub_bundle,
            branching_factor,
            num_compression_levels,
        )
    }

    pub fn new(
        log_state_size: usize,
        batch_size: usize,
        num_batches_per_sub_bundle: usize,
        branching_factor: usize,
        num_compression_levels: u32,
    ) -> Self {
        let config = MinnowBConfig::new(
            log_state_size,
            batch_size,
            num_batches_per_sub_bundle,
            branching_factor,
            num_compression_levels,
        );

        let base_circuit = BaseCircuit::new(log_state_size, num_batches_per_sub_bundle, batch_size);

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

        let root_circuit_data = if num_compression_levels != 0 {
            &compressed_circuits.last().unwrap().circuit_data
        } else {
            &base_circuit.circuit_data
        };

        let initial_root = get_initial_root(log_state_size + 1);
        let sequential_circuit = CyclicSequentialCircuit::new(&initial_root, &root_circuit_data);
        Self {
            base_circuit,
            compressed_circuits,
            sequential_circuit,
            config,
        }
    }

    // Consumes the circuit and returns the provers.
    pub fn build_provers(self) -> MinnowBProvers {
        let base_prover = BaseProver::new(self.base_circuit);
        let compression_provers = self
            .compressed_circuits
            .into_iter()
            .map(|c| CompressionProver::new(c))
            .collect();
        let cyclic_prover = CyclicProver::new(self.sequential_circuit);
        MinnowBProvers {
            base_prover,
            compression_provers,
            cyclic_prover,
            config: self.config,
        }
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

    pub fn set_inputs(&self, in_proofs: &[&Proof]) -> PartialWitness<F> {
        assert_eq!(in_proofs.len(), self.targets.in_proofs.len());
        let mut pw = PartialWitness::new();
        for i in 0..self.targets.in_proofs.len() {
            pw.set_proof_with_pis_target(&self.targets.in_proofs[i], &in_proofs[i])
                .unwrap();
        }
        pw
    }
}

pub struct MinnowBProvers {
    pub base_prover: BaseProver,
    pub compression_provers: Vec<CompressionProver>,
    pub cyclic_prover: CyclicProver,
    pub config: MinnowBConfig,
}

pub struct Orchestrator {
    pub state: MinnowMTServiceState,
    pub provers: MinnowBProvers,
    pub debug: bool,
}

impl Orchestrator {
    pub fn new(provers: MinnowBProvers, debug: bool) -> Self {
        let state = MinnowMTServiceState::new(&[], provers.config.log_state_size);
        Self {
            state,
            provers,
            debug,
        }
    }

    // Step 1: Process a bundle and return the base witnesses.
    pub fn process_bundle_and_return_base_witnesses(
        &mut self,
        bundle: &Bundle,
    ) -> Vec<MyPartialWitness> {
        // Sanity check the bundle to catch any errors early.
        self.provers.config.sanity_check_bundle(bundle);

        let mut base_witnesses = vec![];
        for i in 0..self.provers.config.num_sub_bundles {
            let sub_bundle = &bundle[i];
            let pw = self
                .provers
                .base_prover
                .circuit
                .apply_bundle_and_compute_witness(&sub_bundle, &mut self.state);
            base_witnesses.push(pw);
        }
        base_witnesses
    }

    // Step 2: Compute base proofs
    pub fn compute_base_proof(&mut self, base_witness: MyPartialWitness) -> Proof {
        let proof = self.provers.base_prover.prove(base_witness);
        if self.debug {
            self.provers.base_prover.verify(proof.clone());
        }
        proof
    }

    // (Single machine) Compute all the base proofs in one go.
    pub fn compute_all_base_proofs(&mut self, base_witnesses: Vec<MyPartialWitness>) -> Vec<Proof> {
        let mut base_proofs = vec![];
        for witness in base_witnesses {
            let proof = self.compute_base_proof(witness);
            base_proofs.push(proof);
        }
        base_proofs
    }

    // Step 3: One round of compression of base proofs
    pub fn compress_base_proofs(&mut self, base_proofs: &[&Proof], level: usize) -> Proof {
        assert!(base_proofs.len() == self.provers.config.branching_factor);
        let compression_prover = &mut self.provers.compression_provers[level];
        let proof = compression_prover.prove(&base_proofs);
        if self.debug {
            compression_prover.verify(proof.clone());
        }
        proof
    }

    // (Single machine) Compute all the compression proofs in one go.
    pub fn compress_all_base_proofs(&mut self, base_proofs: Vec<Proof>) -> Proof {
        let b = self.provers.config.branching_factor;
        let mut cur_level_proofs: Vec<Vec<Proof>> =
            base_proofs.chunks(b).map(|chunk| chunk.to_vec()).collect();

        for i in 0..self.provers.config.num_compression_levels as usize {
            let mut new_level_proofs = vec![];
            let cur_level_proof_refs: Vec<Vec<&Proof>> = cur_level_proofs
                .iter()
                .map(|chunk| chunk.iter().collect())
                .collect();
            for j in 0..cur_level_proofs.len() {
                let proof = self.compress_base_proofs(&cur_level_proof_refs[j], i);
                new_level_proofs.push(proof);
            }
            cur_level_proofs = new_level_proofs
                .chunks(b)
                .map(|chunk| chunk.to_vec())
                .collect();
        }

        if cur_level_proofs.len() != 1 || cur_level_proofs[0].len() != 1 {
            panic!("Expected 1 proof at the end of compression");
        }
        cur_level_proofs[0][0].clone()
    }

    // Step 4: Prove the sequential circuit
    pub fn compute_cyclic_proof(&mut self, compressed_proof: Proof) -> Proof {
        let cyclic_prover = &mut self.provers.cyclic_prover;
        let proof = cyclic_prover.prove(compressed_proof);
        if self.debug {
            cyclic_prover.verify(proof.clone());
        }
        proof
    }

    // Step 5: Verify the final proof of the cyclic circuit
    pub fn verify_cyclic_proof(&mut self, proof: Proof) {
        self.provers.cyclic_prover.verify(proof);
    }

    // (Single machine) Compute all the proofs in one go.
    pub fn compute_proof(&mut self, bundle: &Bundle) -> Proof {
        let base_witnesses = self.process_bundle_and_return_base_witnesses(bundle);
        let base_proofs = self.compute_all_base_proofs(base_witnesses);
        let compressed_proof = self.compress_all_base_proofs(base_proofs);
        let cyclic_proof = self.compute_cyclic_proof(compressed_proof);
        cyclic_proof
    }
}

pub struct BaseProver {
    circuit: BaseCircuit,
}

impl BaseProver {
    pub fn new(base_circuit: BaseCircuit) -> Self {
        Self {
            circuit: base_circuit,
        }
    }

    pub fn prove(&mut self, witness: MyPartialWitness) -> Proof {
        let proof = self.circuit.circuit_data.prove(witness).unwrap();
        assert!(self.circuit.circuit_data.verify(proof.clone()).is_ok());
        proof
    }

    pub fn verify(&mut self, proof: Proof) {
        self.circuit.circuit_data.verify(proof).unwrap();
    }
}

pub struct CompressionProver {
    circuit: CompressedCircuit,
}

impl CompressionProver {
    pub fn new(circuit: CompressedCircuit) -> Self {
        Self { circuit }
    }

    pub fn prove(&mut self, materials: &[&Proof]) -> Proof {
        let pw = self.circuit.set_inputs(&materials);
        let proof = self.circuit.circuit_data.prove(pw).unwrap();
        assert!(self.circuit.circuit_data.verify(proof.clone()).is_ok());
        proof
    }

    pub fn verify(&mut self, proof: Proof) {
        self.circuit.circuit_data.verify(proof).unwrap();
    }
}

pub struct CyclicProver {
    cyclic_circuit: CyclicSequentialCircuit,
    prev_proof: Proof,
    first_proof: bool,
}

impl CyclicProver {
    pub fn new(cyclic_circuit: CyclicSequentialCircuit) -> Self {
        let verifier_data = &cyclic_circuit.circuit_data.verifier_only;
        let common_data = &cyclic_circuit.circuit_data.common;
        let public_inputs = HashMap::<usize, F>::new();
        let prev_proof = cyclic_base_proof(&common_data, &verifier_data, public_inputs);

        Self {
            cyclic_circuit,
            prev_proof,
            first_proof: true,
        }
    }

    pub fn prove(&mut self, compressed_proof: Proof) -> Proof {
        let verifier_data = &self.cyclic_circuit.circuit_data.verifier_only;
        let pw = self.cyclic_circuit.set_inputs(
            self.first_proof,
            &compressed_proof,
            &self.prev_proof,
            &verifier_data,
        );
        self.first_proof = false;
        let proof = self.cyclic_circuit.circuit_data.prove(pw).unwrap();
        self.prev_proof = proof.clone();
        assert!(&self
            .cyclic_circuit
            .circuit_data
            .verify(proof.clone())
            .is_ok());
        proof
    }

    pub fn verify(&mut self, proof: Proof) {
        self.cyclic_circuit.circuit_data.verify(proof).unwrap();
    }
}

#[allow(unused_imports)]
mod tests {
    use std::time::Instant;

    use minnow_lib::{
        hash_commitment,
        utils::{generate_sample_updates, set_log_level, Digest},
    };
    use tracing::Level;

    use super::*;
    use crate::{MinnowMTServiceState, DEFAULT_BATCH_SIZE, DEFAULT_LOG_STATE_SIZE};

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
        let all_checkpoint_updates: Bundle =
            generate_sample_updates(num_checkpoints * num_batches, batch_size)
                .chunks(num_batches)
                .map(|chunk| chunk.to_vec())
                .collect();

        let pw = circuit
            .apply_bundle_and_compute_witness(&all_checkpoint_updates[0], &mut zk_service_state);
        let base_proof_0 = circuit.circuit_data.prove(pw).unwrap();
        let pw = circuit
            .apply_bundle_and_compute_witness(&all_checkpoint_updates[1], &mut zk_service_state);
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
    fn test_configs() {
        let log_state_size = DEFAULT_LOG_STATE_SIZE;
        let batch_size = DEFAULT_BATCH_SIZE;
        let num_batches_per_sub_bundle = 4;
        let branching_factor = 3;

        for num_compression_levels in 0..=3 {
            println!(
                "Testing config with num_compression_levels = {}",
                num_compression_levels
            );
            let sub_bundle_size = batch_size * num_batches_per_sub_bundle;
            let bundle_size = sub_bundle_size
                * (branching_factor as u32).pow(num_compression_levels as u32) as usize;
            println!("Sub bundle size: {}", sub_bundle_size);
            println!("Bundle size: {}", bundle_size);
            let minnow_b_circuits = MinnowBCircuits::new(
                log_state_size,
                batch_size,
                num_batches_per_sub_bundle,
                branching_factor,
                num_compression_levels,
            );
            println!(
                "Base circuit info: {:?}",
                minnow_b_circuits.base_circuit.circuit_info
            );
            for i in 0..minnow_b_circuits.compressed_circuits.len() {
                println!(
                    "Compressed circuit info: {:?}",
                    minnow_b_circuits.compressed_circuits[i].circuit_info
                );
            }
            println!(
                "Sequential circuit info: {:?}",
                minnow_b_circuits.sequential_circuit.circuit_info
            );
            assert_eq!(minnow_b_circuits.base_circuit.circuit_info.degree_bits, 14);
            assert_eq!(
                minnow_b_circuits.compressed_circuits.len(),
                num_compression_levels as usize
            );
            for i in 0..minnow_b_circuits.compressed_circuits.len() {
                assert_eq!(
                    minnow_b_circuits.compressed_circuits[i]
                        .circuit_info
                        .degree_bits,
                    14
                );
            }
            assert_eq!(
                minnow_b_circuits
                    .sequential_circuit
                    .circuit_info
                    .degree_bits,
                14
            );
        }
    }

    #[test]
    fn test_e2e_big_config() {
        let log_state_size = 20;
        let batch_size = 25;
        let num_batches_per_sub_bundle = 9;
        let branching_factor = 3;
        let num_compression_levels = 2;

        let minnow_b_circuits = MinnowBCircuits::new(
            log_state_size,
            batch_size,
            num_batches_per_sub_bundle,
            branching_factor,
            num_compression_levels,
        );
        assert_eq!(minnow_b_circuits.base_circuit.circuit_info.degree_bits, 14);
        assert_eq!(minnow_b_circuits.compressed_circuits.len(), 2);
        assert_eq!(
            minnow_b_circuits.compressed_circuits[0]
                .circuit_info
                .degree_bits,
            14
        );
        assert_eq!(
            minnow_b_circuits.compressed_circuits[1]
                .circuit_info
                .degree_bits,
            14
        );
        assert_eq!(
            minnow_b_circuits
                .sequential_circuit
                .circuit_info
                .degree_bits,
            14
        );

        let num_bundles = 3;
        let bundles = minnow_b_circuits
            .config
            .generate_multiple_sample_bundles(num_bundles);
        let mut orchestrator = Orchestrator::new(minnow_b_circuits.build_provers(), true);
        for i in 0..num_bundles {
            let bundle = &bundles[i];
            let proof = orchestrator.compute_proof(bundle);
            orchestrator.verify_cyclic_proof(proof);
        }
    }

    #[test]
    fn test_e2e_small_config() {
        let config = MinnowBConfig::default();
        let circuits = MinnowBCircuits::new_with_config(&config);
        let provers = circuits.build_provers();

        let bundle = config.generate_single_sample_bundle();
        let mut orchestrator = Orchestrator::new(provers, true);
        let proof = orchestrator.compute_proof(&bundle);
        orchestrator.verify_cyclic_proof(proof);
    }

    #[test]
    fn test_e2e_no_compression() {
        let log_state_size = DEFAULT_LOG_STATE_SIZE;
        let batch_size = DEFAULT_BATCH_SIZE;
        let num_batches_per_sub_bundle = 4;
        let branching_factor = 3;
        let num_compression_levels = 0;

        let minnow_b_circuits = MinnowBCircuits::new(
            log_state_size,
            batch_size,
            num_batches_per_sub_bundle,
            branching_factor,
            num_compression_levels,
        );
        let bundle = minnow_b_circuits.config.generate_single_sample_bundle();
        let provers = minnow_b_circuits.build_provers();
        let mut orchestrator = Orchestrator::new(provers, true);
        let proof = orchestrator.compute_proof(&bundle);
        orchestrator.verify_cyclic_proof(proof);
    }
}
