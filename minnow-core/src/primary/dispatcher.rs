// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use dashmap::DashMap;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};

use crate::{
    messages::{
        PartialCompressionProof,
        PartialCompressionProofAggregator,
        ProofIndex,
        ProtocolMessage,
        StateUpdateMessage,
        SubmissionTimestamp,
    },
    metrics::Metrics,
    primary::load_balancer::LoadBalancer,
    proof_system::{Proof, Prover, ProverParameters},
};

pub struct Dispatcher {
    metrics: Arc<Metrics>,
    prover: Prover,
    rx_proxy_connections: Receiver<Sender<ProtocolMessage>>,
    rx_state_updates: Receiver<StateUpdateMessage>,
    rx_proxy_to_primary: Receiver<ProtocolMessage>,
    tx_cyclic_prover: Sender<(SubmissionTimestamp, ProofIndex, Proof)>,
    load_balancer: LoadBalancer<ProtocolMessage>,
    aggregators: DashMap<u16, PartialCompressionProofAggregator>,
    index: ProofIndex,
}

impl Dispatcher {
    pub fn new(
        prover_parameters: ProverParameters,
        metrics: Arc<Metrics>,
        rx_proxy_connections: Receiver<Sender<ProtocolMessage>>,
        rx_state_updates: Receiver<StateUpdateMessage>,
        rx_proxy_to_primary: Receiver<ProtocolMessage>,
        tx_cyclic_prover: Sender<(SubmissionTimestamp, ProofIndex, Proof)>,
        load_balancer: LoadBalancer<ProtocolMessage>,
    ) -> Self {
        let prover = Prover::new(&prover_parameters, false);
        let aggregators = (0..prover_parameters.num_compression_levels as u16)
            .map(|compression_level| {
                (
                    compression_level,
                    PartialCompressionProofAggregator::new(
                        compression_level,
                        prover_parameters.clone(),
                    ),
                )
            })
            .collect();

        Self {
            metrics,
            prover,
            rx_proxy_connections,
            rx_state_updates,
            rx_proxy_to_primary,
            tx_cyclic_prover,
            load_balancer,
            aggregators,
            index: 0,
        }
    }

    async fn handle_partial_compression_proof(
        &mut self,
        proof: PartialCompressionProof,
    ) -> Option<()> {
        assert!(proof.proofs.len() == 1);

        let index = proof.index;
        let compression_level = proof.compression_level;
        tracing::debug!(
            "Received partial compression proof at with index {index} at level {compression_level}"
        );
        let Some(mut aggregator) = self.aggregators.get_mut(&compression_level) else {
            panic!("Received compression proof for unknown compression level {compression_level}");
        };

        match aggregator.update(proof) {
            Some(compressed_proof) => {
                let index = compressed_proof.index;
                tracing::debug!("Received enough partial compression proofs for batched index {index}, forwarding compressed proof");
                let message = ProtocolMessage::PartialCompressionProof(compressed_proof);
                if self.load_balancer.send(message).await.is_err() {
                    return None;
                }
            }
            None => {
                tracing::debug!("Not enough partial compression proofs received yet for index {index}, waiting for more");
            }
        }
        Some(())
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(connection) = self.rx_proxy_connections.recv() => {
                    tracing::info!("Received new proxy connection, adding to load balancer");
                    self.load_balancer.add_proxy(connection);
                },
                Some(message) = self.rx_state_updates.recv() => {
                    tracing::debug!("Received state update, building proof material");
                    let StateUpdateMessage { submission_timestamp, updates } = message;
                    let start = Instant::now();
                    let witnesses = self.prover.process_bundle_and_return_base_witnesses(&updates);
                    let elapsed = start.elapsed();
                    self.metrics.observe_partial_witness_builder_latency(elapsed);

                    for material in witnesses {
                        let message = ProtocolMessage::BasicProofMaterial { submission_timestamp, index: self.index, material };
                        self.index += 1;
                        if self.load_balancer.send(message).await.is_err() {
                            break
                        }
                    }
                },
                Some(message) = self.rx_proxy_to_primary.recv() => {
                    match message {
                        ProtocolMessage::PartialCompressionProof (proof) => {
                            if self.handle_partial_compression_proof(proof).await.is_none() {
                                break;
                            }
                        }
                        ProtocolMessage::FinalCompressionProof{submission_timestamp, index, proof} => {
                            tracing::debug!("Received final compression proof for index {index}, forwarding to cyclic prover");
                            if self.tx_cyclic_prover.send((submission_timestamp,index,proof)).await.is_err() {
                                break;
                            }
                        },
                        _ => {
                            panic!("Received unexpected message");
                        }
                    }
                },
                else => {
                    tracing::info!("No more messages to process, stopping load balancer");
                    break
                }
            }
        }
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }
}
