// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use dashmap::DashMap;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{
    proof_system::{CyclicProver, Proof},
    ProofIndex,
};

pub struct CyclicProverDriver {
    rx_cyclic_prover: Receiver<(ProofIndex, Proof)>,
    tx_output: Sender<Proof>,
    state: CyclicProver,
    pending: DashMap<ProofIndex, Proof>,
    next_index: ProofIndex,
}

impl CyclicProverDriver {
    pub fn new(
        rx_cyclic_prover: Receiver<(ProofIndex, Proof)>,
        tx_output: Sender<Proof>,
        state: CyclicProver,
    ) -> Self {
        Self {
            rx_cyclic_prover,
            tx_output,
            state,
            pending: DashMap::new(),
            next_index: 0,
        }
    }

    pub async fn run(&mut self) {
        while let Some((index, material)) = self.rx_cyclic_prover.recv().await {
            self.pending.insert(index, material);

            loop {
                let Some((_, material)) = self.pending.remove(&self.next_index) else {
                    break;
                };
                let proof = self.state.prove(material);
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
