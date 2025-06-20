// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
    time::Instant,
};

use crate::{
    messages::ProtocolMessage,
    metrics::Metrics,
    proof_system::{BaseProver, CompressionProver},
    proxy::id_manager::IdManager,
};

pub struct ProverDriver {
    metrics: Arc<Metrics>,
    rx_primary_to_proxy: Receiver<ProtocolMessage>,
    tx_primary: Sender<ProtocolMessage>,
    basic_prover: BaseProver,
    compress_prover: CompressionProver,
    pending: IdManager,
    max_compression_level: u16,
}

impl ProverDriver {
    pub fn new(
        metrics: Arc<Metrics>,
        rx_primary_to_proxy: Receiver<ProtocolMessage>,
        tx_primary: Sender<ProtocolMessage>,
        basic_prover: BaseProver,
        compress_prover: CompressionProver,
        max_compression_level: u16,
    ) -> Self {
        Self {
            metrics,
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
            tracing::debug!("Received message for prover: {message:?}");
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
                let start = Instant::now();
                let proof = self.basic_prover.prove(material);
                let elapsed = start.elapsed();
                self.metrics.observe_basic_prover_latency(elapsed);

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
                let start = Instant::now();
                let proof = self.compress_prover.prove(proof, compression_level);
                let elapsed = start.elapsed();
                self.metrics.observe_compress_prover_latency(elapsed);

                if compression_level < self.max_compression_level {
                    ProtocolMessage::PartialCompressionProof {
                        index,
                        compression_level: compression_level + 1,
                        proof,
                    }
                } else {
                    tracing::debug!("Final compression proof for index {index} with compression level {compression_level}");
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
