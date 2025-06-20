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
    proof_system::{CyclicProver, Proof},
};

pub struct CyclicProverDriver {
    metrics: Arc<Metrics>,
    rx_cyclic_prover: Receiver<(SubmissionTimestamp, ProofIndex, Proof)>,
    tx_output: Sender<Proof>,
    state: CyclicProver,
    pending: DashMap<ProofIndex, Proof>,
    next_index: ProofIndex,
}

impl CyclicProverDriver {
    pub fn new(
        metrics: Arc<Metrics>,
        rx_cyclic_prover: Receiver<(SubmissionTimestamp, ProofIndex, Proof)>,
        tx_output: Sender<Proof>,
        state: CyclicProver,
    ) -> Self {
        Self {
            metrics,
            rx_cyclic_prover,
            tx_output,
            state,
            pending: DashMap::new(),
            next_index: 0,
        }
    }

    pub async fn run(&mut self) {
        while let Some((submission_timestamp, index, material)) = self.rx_cyclic_prover.recv().await
        {
            self.pending.insert(index, material);

            loop {
                let Some((_, material)) = self.pending.remove(&self.next_index) else {
                    break;
                };

                let start = Instant::now();
                let proof = self.state.prove(material);
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
