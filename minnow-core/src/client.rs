// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use tokio::{
    sync::mpsc,
    time::{self},
};

use crate::{
    config::NodeConfig,
    messages::StateUpdateMessage,
    metrics::Metrics,
    networking::{client::NetworkClient, DEFAULT_CHANNEL_SIZE},
};

pub struct Client {
    config: NodeConfig,
    metrics: Option<Arc<Metrics>>,
    load: usize,
    duration: Duration,
    tx_outgoing: mpsc::Sender<StateUpdateMessage>,
    network_client: NetworkClient<(), StateUpdateMessage>,
}

impl Client {
    pub fn new(
        config: NodeConfig,
        load: usize,
        duration: Duration,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let (tx_incoming, _rx_incoming) = mpsc::channel(1); // Unused
        let (tx_outgoing, rx_outgoing) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let address = config.client_server_address;
        let network_client = NetworkClient::<(), _>::new(address, tx_incoming, rx_outgoing);

        Self {
            config,
            load,
            duration,
            tx_outgoing,
            network_client,
            metrics,
        }
    }

    pub async fn run(self) {
        // Spawn the network client to send messages
        tracing::info!("Booting network client...");
        let _handle = self.network_client.spawn();
        tokio::task::yield_now().await;

        // Prepare the state updates
        let prover_parameters = &self.config.prover_parameters;
        let total_updates = self.load * self.duration.as_secs() as usize;
        tracing::info!("Generating {total_updates} batches of state updates");
        let mut state_updates = prover_parameters.generate_multiple_sample_bundles(total_updates);

        // Send updates at a fixed interval
        let updates_per_interval = self.load;
        let mut interval = time::interval(Duration::from_secs(1));

        tracing::info!("Client starting to send state updates");
        loop {
            interval.tick().await;

            let count = updates_per_interval.min(state_updates.len());
            if count == 0 {
                tracing::info!("No state updates available to send");
                break;
            }
            tracing::info!(
                "Sending {} state updates ({} remaining)",
                count,
                state_updates.len() - count
            );

            let to_send = state_updates.drain(..count).collect::<Vec<_>>();
            for updates in to_send {
                let message = StateUpdateMessage::new(updates);
                self.tx_outgoing.send(message).await.unwrap();
            }

            if let Some(metrics) = &self.metrics {
                metrics.new_updates_submitted(count);
            }
        }
        tracing::info!("Client finished sending state updates");
    }
}
