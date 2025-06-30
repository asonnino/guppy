// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};

use crate::{
    config::NodeConfig,
    metrics::Metrics,
    networking::server::NetworkServer,
    primary::{
        cyclic_driver::CyclicProverDriver,
        dispatcher::Dispatcher,
        load_balancer::LoadBalancer,
    },
    proof_system::Proof,
    proxy::prover_driver::ProverDriver,
};

pub const DEFAULT_CHANNEL_SIZE: usize = 100_000;

pub struct PrimaryNode {
    dispatcher_handle: JoinHandle<()>,
    prover_driver_handle: JoinHandle<()>,
    cyclic_prover_handle: JoinHandle<()>,
    proxy_server_handle: JoinHandle<std::io::Result<()>>,
    client_server_handle: JoinHandle<std::io::Result<()>>,
    metrics_server_handle: JoinHandle<Result<(), std::io::Error>>,
    rx_client_connections: Receiver<Sender<()>>,
}

impl PrimaryNode {
    pub fn start(config: NodeConfig, tx_output: Sender<Proof>) -> Self {
        let registry = prometheus::Registry::new();
        let metrics = Arc::new(Metrics::new(&registry));

        let (tx_proxy_connections, rx_proxy_connections) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_client_connections, rx_client_connections) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_state_updates, rx_state_updates) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_local_proxy, rx_local_proxy) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_proxy_to_primary, rx_proxy_to_primary) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_cyclic_prover, rx_cyclic_prover) = mpsc::channel(DEFAULT_CHANNEL_SIZE);

        let load_balancer = LoadBalancer::new(tx_local_proxy);
        let dispatcher_handle = Dispatcher::new(
            config.prover_parameters.clone(),
            metrics.clone(),
            rx_proxy_connections,
            rx_state_updates,
            rx_proxy_to_primary,
            tx_cyclic_prover,
            load_balancer,
        )
        .spawn();

        let prover_driver_handle = ProverDriver::new(
            &config.prover_parameters,
            metrics.clone(),
            rx_local_proxy,
            tx_proxy_to_primary.clone(),
        )
        .spawn();

        let cyclic_prover_handle = CyclicProverDriver::new(
            &config.prover_parameters,
            metrics,
            rx_cyclic_prover,
            tx_output,
        )
        .spawn();

        let proxy_server_handle = NetworkServer::new(
            config.proxy_server_address,
            tx_proxy_connections,
            tx_proxy_to_primary,
        )
        .spawn();

        let client_server_handle = NetworkServer::new(
            config.client_server_address,
            tx_client_connections,
            tx_state_updates,
        )
        .spawn();

        let metrics_server_handle =
            crate::metrics::start_prometheus_server(config.metrics_server_address, &registry);

        tracing::info!("Primary node started with config: {config:?}");
        Self {
            dispatcher_handle,
            prover_driver_handle,
            cyclic_prover_handle,
            proxy_server_handle,
            client_server_handle,
            metrics_server_handle,
            rx_client_connections,
        }
    }

    pub async fn join(mut self) {
        let (
            dispatcher_result,
            prover_driver_handle,
            cyclic_prover_result,
            proxy_server_result,
            client_server_result,
            metrics_server_result,
            _,
        ) = tokio::join!(
            self.dispatcher_handle,
            self.prover_driver_handle,
            self.cyclic_prover_handle,
            self.proxy_server_handle,
            self.client_server_handle,
            self.metrics_server_handle,
            async move { while self.rx_client_connections.recv().await.is_some() {} }
        );

        if let Err(e) = dispatcher_result {
            tracing::error!("Dispatcher task failed: {e:?}");
        }
        if let Err(e) = prover_driver_handle {
            tracing::error!("Prover Driver task failed: {e:?}");
        }
        if let Err(e) = cyclic_prover_result {
            tracing::error!("Cyclic prover task failed: {e:?}");
        }

        match proxy_server_result {
            Ok(Err(e)) => tracing::error!("Proxy network error: {e:?}"),
            Err(e) => tracing::error!("Proxy server task failed: {e:?}"),
            _ => (),
        }
        match client_server_result {
            Ok(Err(e)) => tracing::error!("Client network error: {e:?}"),
            Err(e) => tracing::error!("Client server task failed: {e:?}"),
            _ => (),
        }
        match metrics_server_result {
            Ok(Err(e)) => tracing::error!("Metrics server error: {e:?}"),
            Err(e) => tracing::error!("Metrics server task failed: {e:?}"),
            _ => (),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::{net::SocketAddr, time::Duration};

    use tokio::{sync::mpsc, task::JoinHandle};

    use crate::{
        config::NodeConfig,
        messages::StateUpdateMessage,
        networking::{self, client::NetworkClient},
        primary::node::{PrimaryNode, DEFAULT_CHANNEL_SIZE},
        proof_system::{ProverParameters, StateUpdate},
        proxy::node::ProxyNode,
    };

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn local_proxy() {
        let parameters = ProverParameters::default();
        let config = NodeConfig {
            client_server_address: networking::get_test_address(),
            proxy_server_address: networking::get_test_address(),
            metrics_server_address: networking::get_test_address(),
            prover_parameters: parameters.clone(),
        };

        // Start the primary node with the given configuration
        let (tx_output, mut rx_output) = mpsc::channel(1);
        let _primary_node = PrimaryNode::start(config.clone(), tx_output);
        tokio::task::yield_now().await;

        // Create a network client to submit requests to the primary node
        let (tx_incoming, _rx_incoming) = mpsc::channel(1);
        let (tx_outgoing, rx_outgoing) = mpsc::channel(1);
        let _client_handle =
            NetworkClient::<(), _>::new(config.client_server_address, tx_incoming, rx_outgoing)
                .spawn();

        let total_requests = 3;
        let bundles = parameters.generate_multiple_sample_bundles(total_requests);
        for bundle in bundles {
            let message = StateUpdateMessage::new(bundle);
            tx_outgoing.send(message).await.unwrap();
        }

        // Wait for all requests to be processed
        tokio::time::timeout(Duration::from_secs(10), async move {
            for i in 0..total_requests {
                let _ = rx_output.recv().await.unwrap();
                tracing::debug!("Received request {i}");
            }
        })
        .await
        .expect("Timed out waiting for output");
    }

    async fn client(
        server_address: SocketAddr,
        state_updates: Vec<StateUpdate>,
    ) -> JoinHandle<Result<(), std::io::Error>> {
        // Create a network client to submit requests to the primary node
        let (tx_incoming, _rx_incoming) = mpsc::channel(1);
        let (tx_outgoing, rx_outgoing) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let client_handle =
            NetworkClient::<(), _>::new(server_address, tx_incoming, rx_outgoing).spawn();

        for update in state_updates {
            let message = StateUpdateMessage::new(update);
            tx_outgoing.send(message).await.unwrap();
        }

        client_handle
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn end_to_end() {
        // Setup the configuration for the proxy node
        let parameters = ProverParameters::default();
        let config = NodeConfig {
            client_server_address: networking::get_test_address(),
            proxy_server_address: networking::get_test_address(),
            metrics_server_address: networking::get_test_address(),
            prover_parameters: parameters.clone(),
        };

        // Start the proxy nodes
        let _proxy_node_1 = ProxyNode::start(config.clone());
        let _proxy_node_2 = ProxyNode::start(config.clone());
        tokio::task::yield_now().await;

        // Start the primary node
        let (tx_output, mut rx_output) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let _primary_node = PrimaryNode::start(config.clone(), tx_output);
        tokio::task::yield_now().await;

        // Start the client
        let total_state_updates = 3;
        let state_updates = parameters.generate_multiple_sample_bundles(total_state_updates);
        let _client_handle = client(config.client_server_address, state_updates).await;

        // Wait for all requests to be processed
        tokio::time::timeout(Duration::from_secs(10), async move {
            for _ in 0..total_state_updates {
                let _ = rx_output.recv().await.unwrap();
            }
        })
        .await
        .expect("Timed out waiting for output");
    }
}
