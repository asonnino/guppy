// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::proof_system::{PartialWitness, Proof};

pub mod config;
pub mod metrics;
pub mod networking;
pub mod primary;
pub mod proof_system;
pub mod proxy;

pub type ProofIndex = u64;

#[derive(Serialize, Deserialize, Debug)]
pub enum ProtocolMessage {
    BasicProofMaterial {
        index: ProofIndex,
        material: PartialWitness,
    },
    PartialCompressionProof {
        index: ProofIndex,
        compression_level: u16,
        proof: Proof,
    },
    FinalCompressionProof {
        index: ProofIndex,
        proof: Proof,
    },
}

impl ProtocolMessage {
    pub fn index(&self) -> ProofIndex {
        match self {
            ProtocolMessage::BasicProofMaterial { index, .. } => *index,
            ProtocolMessage::PartialCompressionProof { index, .. } => *index,
            ProtocolMessage::FinalCompressionProof { index, .. } => *index,
        }
    }
}
