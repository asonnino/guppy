// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use dashmap::DashMap;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};

use crate::{
    messages::{ProofIndex, SubmissionTimestamp},
    metrics::Metrics,
    proof_system::{Proof, Prover, ProverParameters},
};

pub struct CyclicProverDriver {
    metrics: Arc<Metrics>,
    prover: Prover,
    rx_cyclic_prover: Receiver<(SubmissionTimestamp, ProofIndex, Proof)>,
    tx_output: Sender<Proof>,
    pending: DashMap<ProofIndex, Proof>,
    next_index: ProofIndex,
}

impl CyclicProverDriver {
    pub fn new(
        parameters: &ProverParameters,
        metrics: Arc<Metrics>,
        rx_cyclic_prover: Receiver<(SubmissionTimestamp, ProofIndex, Proof)>,
        tx_output: Sender<Proof>,
    ) -> Self {
        Self {
            metrics,
            prover: Prover::new(parameters, false),
            rx_cyclic_prover,
            tx_output,
            pending: DashMap::new(),
            next_index: 0,
        }
    }

    pub async fn run(&mut self) {
        while let Some((submission_timestamp, index, material)) = self.rx_cyclic_prover.recv().await
        {
            tracing::debug!("Received cyclic proof material for index {index}");
            self.pending.insert(index, material);

            loop {
                let Some((_, material)) = self.pending.remove(&self.next_index) else {
                    break;
                };
                tracing::debug!("Processing cyclic proof for index {}", self.next_index);

                let start = Instant::now();
                let proof = self.prover.compute_cyclic_proof(material);
                let elapsed = start.elapsed();
                self.metrics.observe_cyclic_prover_latency(elapsed);
                self.metrics.observe_total_latency(submission_timestamp);

                tracing::info!("Cyclic proof generated for index {}", self.next_index);
                self.next_index += 1;
                let _ = self.tx_output.send(proof).await;
            }
        }
    }

    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }
}
