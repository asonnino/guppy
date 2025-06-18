// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};

use crate::{
    proof_system::{BasicProver, CompressProver},
    proxy::id_manager::IdManager,
    ProtocolMessage,
};

pub struct ProverDriver {
    rx_primary_to_proxy: Receiver<ProtocolMessage>,
    tx_primary: Sender<ProtocolMessage>,
    basic_prover: BasicProver,
    compress_prover: CompressProver,
    pending: IdManager,
    max_compression_level: u16,
}

impl ProverDriver {
    pub fn new(
        rx_primary_to_proxy: Receiver<ProtocolMessage>,
        tx_primary: Sender<ProtocolMessage>,
        basic_prover: BasicProver,
        compress_prover: CompressProver,
        max_compression_level: u16,
    ) -> Self {
        Self {
            rx_primary_to_proxy,
            tx_primary,
            basic_prover,
            compress_prover,
            pending: IdManager::new(),
            max_compression_level,
        }
    }

    pub async fn run(&mut self) {
        while let Some(message) = self.rx_primary_to_proxy.recv().await {
            self.pending.insert(message);

            loop {
                let Some(lowest) = self.pending.pop_lowest() else {
                    break;
                };
                let reply = self.build_proof(lowest).await;
                if self.tx_primary.send(reply).await.is_err() {
                    return;
                }
            }
        }
    }

    async fn build_proof(&mut self, message: ProtocolMessage) -> ProtocolMessage {
        match message {
            ProtocolMessage::BasicProofMaterial { index, material } => {
                let proof = self.basic_prover.prove(material);
                ProtocolMessage::PartialCompressionProof {
                    index,
                    compression_level: 0,
                    proof,
                }
            }
            ProtocolMessage::PartialCompressionProof {
                index,
                compression_level,
                proof,
            } => {
                let proof = self.compress_prover.prove(proof, compression_level);
                if compression_level < self.max_compression_level {
                    ProtocolMessage::PartialCompressionProof {
                        index,
                        compression_level: compression_level + 1,
                        proof,
                    }
                } else {
                    ProtocolMessage::FinalCompressionProof { index, proof }
                }
            }
            _ => panic!("Received unexpected message"),
        }
    }

    pub fn spawn(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }
}
