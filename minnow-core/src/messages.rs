// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::proof_system::{PartialWitness, Proof, StateUpdate};

pub type SubmissionTimestamp = f64;
pub type ProofIndex = u64;

#[derive(Serialize, Deserialize, Debug)]
pub struct StateUpdateMessage {
    pub submission_timestamp: SubmissionTimestamp,
    pub updates: Vec<StateUpdate>,
}

impl StateUpdateMessage {
    pub fn new(updates: Vec<StateUpdate>) -> Self {
        Self {
            submission_timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs_f64(),
            updates,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ProtocolMessage {
    BasicProofMaterial {
        submission_timestamp: SubmissionTimestamp,
        index: ProofIndex,
        material: PartialWitness,
    },
    PartialCompressionProof {
        submission_timestamp: SubmissionTimestamp,
        index: ProofIndex,
        compression_level: u16,
        proof: Proof,
    },
    FinalCompressionProof {
        submission_timestamp: SubmissionTimestamp,
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
