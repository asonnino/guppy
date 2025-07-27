// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
    time::Instant,
};

use crate::{
    messages::{PartialCompressionProof, ProtocolMessage},
    metrics::Metrics,
    proof_system::{Prover, ProverParameters},
    proxy::id_manager::IdManager,
};

pub struct ProverDriver {
    metrics: Arc<Metrics>,
    prover: Prover,
    rx_primary_to_proxy: Receiver<ProtocolMessage>,
    tx_primary: Sender<ProtocolMessage>,
    pending: IdManager,
    max_compression_level: u16,
}

impl ProverDriver {
    pub fn new(
        parameters: &ProverParameters,
        metrics: Arc<Metrics>,
        rx_primary_to_proxy: Receiver<ProtocolMessage>,
        tx_primary: Sender<ProtocolMessage>,
    ) -> Self {
        Self {
            metrics,
            prover: Prover::new(parameters, false),
            rx_primary_to_proxy,
            tx_primary,
            pending: IdManager::new(),
            max_compression_level: parameters.num_compression_levels as u16,
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
            ProtocolMessage::BasicProofMaterial {
                submission_timestamp,
                index,
                material,
            } => {
                let start = Instant::now();
                let proof = self.prover.compute_base_proof(material);
                let elapsed = start.elapsed();
                self.metrics.observe_basic_prover_latency(elapsed);

                if self.max_compression_level == 0 {
                    ProtocolMessage::FinalCompressionProof {
                        submission_timestamp,
                        index,
                        proof,
                    }
                } else {
                    ProtocolMessage::PartialCompressionProof(PartialCompressionProof {
                        submission_timestamp,
                        index,
                        compression_level: 0,
                        proofs: vec![proof],
                    })
                }
            }
            ProtocolMessage::PartialCompressionProof(PartialCompressionProof {
                submission_timestamp,
                index,
                compression_level,
                proofs,
            }) => {
                tracing::debug!(
                    "Received partial compression proof for index {index} at level {compression_level}"
                );
                let material: Vec<_> = proofs.iter().collect();
                let start = Instant::now();
                let proof = self
                    .prover
                    .compress_base_proofs(&material, compression_level as usize);
                let elapsed = start.elapsed();
                self.metrics.observe_compress_prover_latency(elapsed);

                if compression_level + 1 < self.max_compression_level {
                    tracing::debug!(
                        "Generated partial compression proof for index {index} at level {compression_level}, forwarding for next level"
                    );
                    ProtocolMessage::PartialCompressionProof(PartialCompressionProof {
                        submission_timestamp,
                        index,
                        compression_level: compression_level + 1,
                        proofs: vec![proof],
                    })
                } else {
                    tracing::info!("Final compression proof for index {index} with compression level {compression_level}");
                    ProtocolMessage::FinalCompressionProof {
                        submission_timestamp,
                        index,
                        proof,
                    }
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
