// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

type Placeholder = Vec<u8>;

pub type StateUpdate = Placeholder;
pub type PartialWitness = Placeholder;
pub type Proof = Placeholder;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProverParameters {
    pub total_compression_levels: u16,
}

impl ProverParameters {
    #[cfg(test)]
    pub fn new_for_tests() -> Self {
        Self {
            total_compression_levels: 3,
        }
    }

    pub fn build_provers(
        &self,
    ) -> (
        PartialWitnessBuilder,
        BasicProver,
        CompressProver,
        CyclicProver,
    ) {
        (
            PartialWitnessBuilder,
            BasicProver,
            CompressProver,
            CyclicProver,
        )
    }
}

pub struct PartialWitnessBuilder;
impl PartialWitnessBuilder {
    pub fn build(&mut self, _state_updates: Vec<Placeholder>) -> Placeholder {
        vec![1; 32]
    }
}

pub struct BasicProver;
impl BasicProver {
    pub fn prove(&mut self, _material: Placeholder) -> Placeholder {
        vec![2; 32]
    }
}

pub struct CompressProver;
impl CompressProver {
    pub fn prove(&mut self, _material: Placeholder, _compression_level: u16) -> Placeholder {
        vec![3; 32]
    }
}

pub struct CyclicProver;
impl CyclicProver {
    pub fn prove(&mut self, _material: Placeholder) -> Placeholder {
        vec![4; 32]
    }
}

#[cfg(test)]
pub fn sample_state_updates() -> Vec<Vec<StateUpdate>> {
    vec![
        vec![vec![1; 32], vec![2; 32]],
        vec![vec![3; 32], vec![4; 32]],
        vec![vec![5; 32], vec![6; 32]],
    ]
}

#[cfg(test)]
pub fn sample_partial_witness() -> PartialWitness {
    vec![1; 32]
}

#[cfg(test)]
pub fn sample_proof() -> Proof {
    vec![5; 32]
}
