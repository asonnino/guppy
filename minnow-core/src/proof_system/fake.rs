// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use minnow_mt_plonky2::three_step_circuit;

type Placeholder = u64;

pub type ProverParameters = three_step_circuit::MinnowBConfig;
pub type StateUpdate = three_step_circuit::Bundle;
pub type PartialWitness = Placeholder;
pub type Proof = Placeholder;

pub struct Prover;

impl Prover {
    pub fn new(_parameters: &ProverParameters, _debug: bool) -> Self {
        Self
    }

    pub fn process_bundle_and_return_base_witnesses(
        &mut self,
        bundle: &StateUpdate,
    ) -> Vec<PartialWitness> {
        vec![2; bundle.len()]
    }

    pub fn compute_base_proof(&mut self, _base_witness: PartialWitness) -> Proof {
        3
    }

    pub fn compress_base_proofs(&mut self, _base_proofs: &[&Proof], _level: usize) -> Proof {
        4
    }

    pub fn compute_cyclic_proof(&mut self, _compressed_proof: Proof) -> Proof {
        5
    }

    pub fn verify_cyclic_proof(&mut self, _proof: Proof) {}
}

#[cfg(test)]
pub fn partial_witnesses_for_tests(_parameters: &ProverParameters) -> Vec<PartialWitness> {
    vec![2; 2]
}

#[cfg(test)]
pub fn compressed_proofs_for_tests(_parameters: &ProverParameters) -> Vec<Proof> {
    vec![3; 2]
}

#[cfg(test)]
mod tests {

    use crate::proof_system::{Prover, ProverParameters};

    #[test]
    fn compute_base_proof() {
        let parameters = ProverParameters::default();
        let debug = true;
        let mut prover = Prover::new(&parameters, debug);
        let bundle = parameters.generate_single_sample_bundle();
        let mut witnesses = prover.process_bundle_and_return_base_witnesses(&bundle);

        let _ = prover.compute_base_proof(witnesses.pop().unwrap());
    }

    #[test]
    fn compress_proof() {
        let parameters = ProverParameters {
            branching_factor: 2,
            ..ProverParameters::default()
        };
        let debug = true;
        let mut prover = Prover::new(&parameters, debug);
        let bundle = parameters.generate_single_sample_bundle();
        let witnesses = prover.process_bundle_and_return_base_witnesses(&bundle);

        let base_proof = witnesses
            .into_iter()
            .map(|w| prover.compute_base_proof(w))
            .collect::<Vec<_>>();

        let p = base_proof.iter().take(2).collect::<Vec<_>>();
        let _ = prover.compress_base_proofs(&p, 0);
    }

    #[test]
    fn multi_level_compression() {
        let parameters = ProverParameters {
            branching_factor: 2,
            ..ProverParameters::default()
        };
        let debug = true;
        let mut prover = Prover::new(&parameters, debug);
        let bundle = parameters.generate_single_sample_bundle();
        let witnesses = prover.process_bundle_and_return_base_witnesses(&bundle);

        // Compute base proofs
        let base_proof = witnesses
            .into_iter()
            .map(|w| prover.compute_base_proof(w))
            .collect::<Vec<_>>();

        // Compression level 0
        let first = base_proof.iter().take(2).collect::<Vec<_>>();
        let last = base_proof.iter().skip(2).collect::<Vec<_>>();
        let first = prover.compress_base_proofs(&first, 0);
        let last = prover.compress_base_proofs(&last, 0);

        // Compression level 1
        let _ = prover.compress_base_proofs(&[&first, &last], 1);
    }

    #[test]
    fn cyclic_proof() {
        let parameters = ProverParameters {
            branching_factor: 2,
            ..ProverParameters::default()
        };
        let debug = true;
        let mut prover = Prover::new(&parameters, debug);
        let bundle = parameters.generate_single_sample_bundle();
        let witnesses = prover.process_bundle_and_return_base_witnesses(&bundle);

        // Compute base proofs
        let base_proof = witnesses
            .into_iter()
            .map(|w| prover.compute_base_proof(w))
            .collect::<Vec<_>>();

        // Compression level 0
        let first = base_proof.iter().take(2).collect::<Vec<_>>();
        let last = base_proof.iter().skip(2).collect::<Vec<_>>();
        let first = prover.compress_base_proofs(&first, 0);
        let last = prover.compress_base_proofs(&last, 0);

        // Compression level 1
        let proof = prover.compress_base_proofs(&[&first, &last], 1);

        // Compute cyclic proof
        let _ = prover.compute_cyclic_proof(proof);
    }
}
