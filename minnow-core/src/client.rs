// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use tokio::{
    sync::mpsc,
    time::{self},
};

use crate::{
    config::NodeConfig,
    networking::{client::NetworkClient, DEFAULT_CHANNEL_SIZE},
    proof_system::{self, StateUpdate},
};

pub struct Client {
    config: NodeConfig,
    load: usize,
    tx_outgoing: mpsc::Sender<Vec<StateUpdate>>,
    network_client: NetworkClient<(), Vec<StateUpdate>>,
}

impl Client {
    const TARGET_INTERVAL: Duration = Duration::from_millis(100);

    pub fn new(config: NodeConfig, load: usize) -> Self {
        let (tx_incoming, _rx_incoming) = mpsc::channel(1); // Unused
        let (tx_outgoing, rx_outgoing) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let address = config.client_server_address;
        let network_client = NetworkClient::<(), _>::new(address, tx_incoming, rx_outgoing);

        Self {
            config,
            load,
            tx_outgoing,
            network_client,
        }
    }

    pub async fn run(self) {
        // Spawn the network client to send messages
        tracing::info!("Booting network client...");
        let _handle = self.network_client.spawn();
        tokio::task::yield_now().await;

        // Prepare the state updates
        tracing::info!("Generating state updates");
        let prover_parameters = &self.config.prover_parameters;
        let mut state_updates = proof_system::generate_state_updates(prover_parameters);

        // Send updates at a fixed interval
        let updates_per_interval = (self.load + 9) / 10;
        let mut interval = time::interval(Self::TARGET_INTERVAL);

        tracing::info!("Client starting to send state updates");
        loop {
            interval.tick().await;

            let count = updates_per_interval.min(state_updates.len());
            if count == 0 {
                tracing::warn!("No state updates available to send");
                break;
            }

            let to_send = state_updates.drain(..count).collect::<Vec<_>>();
            for updates in to_send {
                self.tx_outgoing.send(updates).await.unwrap();
            }
        }
        tracing::info!("Client finished sending state updates");
    }
}
