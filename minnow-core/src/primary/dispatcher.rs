// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};

use crate::{
    metrics::Metrics,
    primary::load_balancer::LoadBalancer,
    proof_system::{PartialWitnessBuilder, Proof, StateUpdate},
    ProofIndex,
    ProtocolMessage,
};

pub struct Dispatcher {
    metrics: Arc<Metrics>,
    rx_proxy_connections: Receiver<Sender<ProtocolMessage>>,
    rx_state_updates: Receiver<Vec<StateUpdate>>,
    rx_proxy_to_primary: Receiver<ProtocolMessage>,
    tx_cyclic_prover: Sender<(ProofIndex, Proof)>,
    load_balancer: LoadBalancer<ProtocolMessage>,
    partial_witness_builder: PartialWitnessBuilder,
    index: ProofIndex,
}

impl Dispatcher {
    pub fn new(
        metrics: Arc<Metrics>,
        rx_proxy_connections: Receiver<Sender<ProtocolMessage>>,
        rx_state_updates: Receiver<Vec<StateUpdate>>,
        rx_proxy_to_primary: Receiver<ProtocolMessage>,
        tx_cyclic_prover: Sender<(ProofIndex, Proof)>,
        load_balancer: LoadBalancer<ProtocolMessage>,
        partial_witness_builder: PartialWitnessBuilder,
    ) -> Self {
        Self {
            metrics,
            rx_proxy_connections,
            rx_state_updates,
            rx_proxy_to_primary,
            tx_cyclic_prover,
            load_balancer,
            partial_witness_builder,
            index: 0,
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(connection) = self.rx_proxy_connections.recv() => {
                    tracing::info!("Received new proxy connection, adding to load balancer");
                    self.load_balancer.add_proxy(connection);
                },
                Some(updates) = self.rx_state_updates.recv() => {
                    tracing::debug!("Received state update, building proof material");
                    let start = Instant::now();
                    let material = self.partial_witness_builder.build(updates);
                    let elapsed = start.elapsed();
                    self.metrics.observe_partial_witness_builder_latency(elapsed);

                    let message = ProtocolMessage::BasicProofMaterial { index: self.index, material };
                    self.index += 1;

                    if self.load_balancer.send(message).await.is_err() {
                        break
                    }
                },
                Some(message) = self.rx_proxy_to_primary.recv() => {
                    // TODO: Avoid deserializing and re-serializing PartialCompressionProof only to re-forward them.
                    match message {
                        ProtocolMessage::PartialCompressionProof { .. } => {
                            tracing::debug!("Received partial compression proof, forwarding to load balancer");
                            if self.load_balancer.send(message).await.is_err() {
                                break
                            }

                        }
                        ProtocolMessage::FinalCompressionProof{index, proof} => {
                            tracing::debug!("Received final compression proof for index {index}, forwarding to cyclic prover");
                            if self.tx_cyclic_prover.send((index,proof)).await.is_err() {
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
