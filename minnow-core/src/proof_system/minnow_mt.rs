// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use hashbrown::HashMap;
use minnow_lib::{
    hash_commitment,
    utils::{Digest, F},
    StreamPoint,
};
use minnow_mt_plonky2::{
    merkle::get_initial_root,
    three_step_circuit::CompressedCircuit,
    two_step_circuit::{BaseCircuit, CyclicSequentialCircuit},
    MinnowMTServiceState,
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::HashOut,
    iop::{self},
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
    recursion::dummy_circuit::cyclic_base_proof,
};

type Proof = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;

pub type StateUpdate = Vec<StreamPoint>;
pub type PartialWitness = iop::witness::PartialWitness<GoldilocksField>;
pub type BasicProof = Proof;
pub type CyclicProof = Proof;

pub struct ProofParameters {
    pub log_state_size: usize,
    pub num_batches_per_base_circuit: usize,
    pub batch_size: usize,
    pub num_compression_levels: usize,
    pub branching_factor: usize,
}

impl ProofParameters {
    pub fn build_base_circuit(&self) -> BaseCircuit {
        BaseCircuit::new(
            self.log_state_size,
            self.num_batches_per_base_circuit,
            self.batch_size,
        )
    }

    pub fn build_circuits(&self) -> (BaseCircuit, Vec<CompressedCircuit>, CyclicSequentialCircuit) {
        // Create the base circuit
        let base_circuit = self.build_base_circuit();

        // Create the compressed circuits
        let mut compressed_circuits: Vec<CompressedCircuit> = vec![];
        for _ in 0..self.num_compression_levels {
            if let Some(last_circuit_data) = compressed_circuits.last() {
                let compressed_circuit =
                    CompressedCircuit::new(&last_circuit_data.circuit_data, self.branching_factor);
                compressed_circuits.push(compressed_circuit);
            } else {
                let compressed_circuit =
                    CompressedCircuit::new(&base_circuit.circuit_data, self.branching_factor);
                compressed_circuits.push(compressed_circuit);
            }
        }

        // Create the cyclic sequential circuit
        let root_circuit = compressed_circuits.last().unwrap();
        let initial_root = get_initial_root(self.log_state_size + 1);
        let sequential_circuit =
            CyclicSequentialCircuit::new(&initial_root, &root_circuit.circuit_data);

        (base_circuit, compressed_circuits, sequential_circuit)
    }
}

pub struct PartialWitnessBuilder {
    batch_size: usize,
    cur_head: HashOut<GoldilocksField>,
    zk_service_state: MinnowMTServiceState,
    base_circuit: BaseCircuit,
}

impl PartialWitnessBuilder {
    pub fn new(parameters: &ProofParameters, base_circuit: BaseCircuit) -> Self {
        let log_state_size = parameters.log_state_size;
        let batch_size = parameters.batch_size;
        let zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
        let cur_head = Digest::ZERO;

        Self {
            batch_size,
            cur_head,
            zk_service_state,
            base_circuit,
        }
    }

    pub fn build(&mut self, state_update: Vec<StateUpdate>) -> PartialWitness {
        let new_head = hash_commitment(&state_update, self.batch_size, &self.cur_head);
        let pw = self.base_circuit.apply_bundle_and_compute_witness(
            &state_update,
            &mut self.zk_service_state,
            &self.cur_head,
        );
        self.cur_head = new_head;
        pw
    }
}

pub struct BasicProver {
    base_circuit: BaseCircuit,
}
impl BasicProver {
    pub fn new(base_circuit: BaseCircuit) -> Self {
        Self { base_circuit }
    }

    pub fn prove(&mut self, witness: PartialWitness) -> Proof {
        let proof = self.base_circuit.circuit_data.prove(witness).unwrap();
        debug_assert!(self.base_circuit.circuit_data.verify(proof.clone()).is_ok());
        proof
    }
}

pub struct CompressProver {
    circuits: Vec<CompressedCircuit>,
}

impl CompressProver {
    pub fn new(circuits: Vec<CompressedCircuit>) -> Self {
        Self { circuits }
    }

    pub fn prove(&mut self, material: Proof, compression_level: u16) -> Proof {
        let circuit = &self.circuits[compression_level as usize];
        let pw = circuit.set_inputs(&vec![&material]);
        let proof = circuit.circuit_data.prove(pw).unwrap();
        debug_assert!(circuit.circuit_data.verify(proof.clone()).is_ok());
        proof
    }
}

pub struct CyclicProver {
    cyclic_circuit: CyclicSequentialCircuit,
    prev_proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
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

    pub fn prove(&mut self, base_proof: Proof) -> Proof {
        let verifier_data = &self.cyclic_circuit.circuit_data.verifier_only;
        let pw = self.cyclic_circuit.set_inputs(
            self.first_proof,
            &base_proof,
            &self.prev_proof,
            &verifier_data,
        );
        self.first_proof = false;
        let proof = self.cyclic_circuit.circuit_data.prove(pw).unwrap();
        self.prev_proof = proof.clone();
        let circuit_data = &self.cyclic_circuit.circuit_data;
        debug_assert!(circuit_data.verify(proof.clone()).is_ok());
        proof
    }
}
