// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

type Placeholder = Vec<u8>;

pub type StateUpdate = Placeholder;
pub type PartialWitness = Placeholder;
pub type BasicProof = Placeholder;
pub type CyclicProof = Placeholder;

pub struct PartialWitnessBuilder;
impl PartialWitnessBuilder {
    pub fn build(&mut self, _state_update: Placeholder) -> Placeholder {
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
