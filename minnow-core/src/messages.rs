// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fmt::Debug, time::SystemTime};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::proof_system::{PartialWitness, Proof, ProverParameters, StateUpdate};

pub type SubmissionTimestamp = f64;
pub type ProofIndex = u64;

#[derive(Serialize, Deserialize, Debug)]
pub struct StateUpdateMessage {
    pub submission_timestamp: SubmissionTimestamp,
    pub updates: StateUpdate,
}

impl StateUpdateMessage {
    pub fn new(updates: StateUpdate) -> Self {
        Self {
            submission_timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs_f64(),
            updates,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PartialCompressionProof {
    pub submission_timestamp: SubmissionTimestamp,
    pub index: ProofIndex,
    pub compression_level: u16,
    pub proofs: Vec<Proof>,
}

impl Debug for PartialCompressionProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PartialCompressionProof {{ submission_timestamp: {}, index: {}, compression_level: {}, proofs: {} }}",
            self.submission_timestamp,
            self.index,
            self.compression_level,
            self.proofs.len()
        )
    }
}

impl PartialCompressionProof {
    pub fn batch(mut proofs: Vec<Self>, branching_factor: u64) -> Self {
        if proofs.is_empty() {
            panic!("Cannot create a batch from an empty vector");
        }

        let mut batched = proofs.remove(0);
        for proof in proofs {
            if batched.submission_timestamp > proof.submission_timestamp {
                batched.submission_timestamp = proof.submission_timestamp;
            }
            if batched.index > proof.index {
                batched.index = proof.index;
            }
            assert!(proof.compression_level == batched.compression_level);
            batched.proofs.extend(proof.proofs);
        }
        batched.index /= branching_factor;
        batched
    }
}

pub struct PartialCompressionProofAggregator {
    compression_level: u16,
    parameters: ProverParameters,
    pending: DashMap<ProofIndex, PartialCompressionProof>,
    next_index: ProofIndex,
}

impl PartialCompressionProofAggregator {
    pub fn new(compression_level: u16, parameters: ProverParameters) -> Self {
        assert!(compression_level < parameters.num_compression_levels as u16);
        Self {
            compression_level,
            parameters,
            pending: DashMap::new(),
            next_index: 0,
        }
    }

    pub fn update(&mut self, proof: PartialCompressionProof) -> Option<PartialCompressionProof> {
        assert!(proof.compression_level == self.compression_level);
        self.pending.insert(proof.index, proof);

        let branching_factor = self.parameters.branching_factor as u64;
        let range = self.next_index..self.next_index + branching_factor;

        if range.clone().any(|i| !self.pending.contains_key(&i)) {
            return None;
        }

        let proofs = range.map(|i| self.pending.remove(&i).unwrap().1).collect();
        self.next_index += branching_factor;
        Some(PartialCompressionProof::batch(proofs, branching_factor))
    }
}

#[derive(Serialize, Deserialize)]
pub enum ProtocolMessage {
    BasicProofMaterial {
        submission_timestamp: SubmissionTimestamp,
        index: ProofIndex,
        material: PartialWitness,
    },
    PartialCompressionProof(PartialCompressionProof),
    FinalCompressionProof {
        submission_timestamp: SubmissionTimestamp,
        index: ProofIndex,
        proof: Proof,
    },
}

impl Debug for ProtocolMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolMessage::BasicProofMaterial { index, .. } => {
                write!(f, "BasicProofMaterial {{ index: {} }}", index)
            }
            ProtocolMessage::PartialCompressionProof(proof) => proof.fmt(f),
            ProtocolMessage::FinalCompressionProof { index, .. } => {
                write!(f, "FinalCompressionProof {{ index: {} }}", index)
            }
        }
    }
}

impl ProtocolMessage {
    pub fn index(&self) -> ProofIndex {
        match self {
            ProtocolMessage::BasicProofMaterial { index, .. } => *index,

            ProtocolMessage::PartialCompressionProof(proof) => proof.index,
            ProtocolMessage::FinalCompressionProof { index, .. } => *index,
        }
    }
}
