// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use hashbrown::HashMap;
use minnow_mt_plonky2::three_step_circuit::{self, Bundle, MinnowBCircuits, Orchestrator};
use plonky2::{field::goldilocks_field::GoldilocksField, iop::target::Target};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

impl From<PartialWitness> for minnow_lib::utils::MyPartialWitness {
    fn from(pw: PartialWitness) -> Self {
        pw.0
    }
}

impl From<minnow_lib::utils::MyPartialWitness> for PartialWitness {
    fn from(pw: minnow_lib::utils::MyPartialWitness) -> Self {
        Self(pw)
    }
}

impl Serialize for PartialWitness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.target_values.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PartialWitness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = <HashMap<Target, GoldilocksField>>::deserialize(deserializer)?;
        Ok(Self(minnow_lib::utils::MyPartialWitness {
            target_values: map,
        }))
    }
}

pub type ProverParameters = three_step_circuit::MinnowBConfig;

pub type StateUpdate = three_step_circuit::Bundle;
#[derive(Clone, Debug)]
pub struct PartialWitness(minnow_lib::utils::MyPartialWitness);
pub type Proof = minnow_lib::utils::Proof;

pub struct Prover(three_step_circuit::Orchestrator);

impl Prover {
    pub fn new(parameters: &ProverParameters, debug: bool) -> Self {
        let circuits = MinnowBCircuits::new_with_config(parameters);
        let provers = circuits.build_provers();
        let orchestrator = Orchestrator::new(provers, debug);
        Self(orchestrator)
    }

    pub fn process_bundle_and_return_base_witnesses(
        &mut self,
        bundle: &Bundle,
    ) -> Vec<PartialWitness> {
        self.0
            .process_bundle_and_return_base_witnesses(bundle)
            .into_iter()
            .map(PartialWitness)
            .collect()
    }

    pub fn compute_base_proof(&mut self, base_witness: PartialWitness) -> Proof {
        self.0.compute_base_proof(base_witness.into())
    }

    pub fn compress_base_proofs(&mut self, base_proofs: &[&Proof], level: usize) -> Proof {
        self.0.compress_base_proofs(base_proofs, level)
    }

    pub fn compute_cyclic_proof(&mut self, compressed_proof: Proof) -> Proof {
        self.0.compute_cyclic_proof(compressed_proof)
    }

    pub fn verify_cyclic_proof(&mut self, proof: Proof) {
        self.0.verify_cyclic_proof(proof)
    }
}

#[cfg(test)]
pub fn partial_witnesses_for_tests(parameters: &ProverParameters) -> Vec<PartialWitness> {
    let mut prover = Prover::new(&parameters, false);
    let bundle = parameters.generate_single_sample_bundle();
    prover.process_bundle_and_return_base_witnesses(&bundle)
}

#[cfg(test)]
pub fn compressed_proofs_for_tests(parameters: &ProverParameters) -> Vec<Proof> {
    use std::vec;

    let mut prover = Prover::new(&parameters, false);
    let witnesses = partial_witnesses_for_tests(parameters);

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

    vec![first, last]
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
