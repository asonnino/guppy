// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};

use crate::{
    config::NodeConfig,
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
    rx_client_connections: Receiver<Sender<()>>,
}

impl PrimaryNode {
    pub fn start(config: NodeConfig, tx_output: Sender<Proof>) -> Self {
        let (tx_proxy_connections, rx_proxy_connections) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_client_connections, rx_client_connections) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_state_updates, rx_state_updates) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_local_proxy, rx_local_proxy) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_proxy_to_primary, rx_proxy_to_primary) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_cyclic_prover, rx_cyclic_prover) = mpsc::channel(DEFAULT_CHANNEL_SIZE);

        let (partial_witness_builder, basic_prover, compress_prover, cyclic_prover) =
            config.prover_parameters.build_provers();

        let load_balancer = LoadBalancer::new(tx_local_proxy);
        let dispatcher_handle = Dispatcher::new(
            rx_proxy_connections,
            rx_state_updates,
            rx_proxy_to_primary,
            tx_cyclic_prover,
            load_balancer,
            partial_witness_builder,
        )
        .spawn();

        let prover_driver_handle = ProverDriver::new(
            rx_local_proxy,
            tx_proxy_to_primary.clone(),
            basic_prover,
            compress_prover,
            config.prover_parameters.total_compression_levels,
        )
        .spawn();

        let cyclic_prover_handle =
            CyclicProverDriver::new(rx_cyclic_prover, tx_output, cyclic_prover).spawn();

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

        tracing::info!("Primary node started with config: {config:?}");
        Self {
            dispatcher_handle,
            prover_driver_handle,
            cyclic_prover_handle,
            proxy_server_handle,
            client_server_handle,
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
            _,
        ) = tokio::join!(
            self.dispatcher_handle,
            self.prover_driver_handle,
            self.cyclic_prover_handle,
            self.proxy_server_handle,
            self.client_server_handle,
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
    }
}

#[cfg(test)]
mod tests {

    use std::{net::SocketAddr, time::Duration};

    use tokio::{sync::mpsc, task::JoinHandle};

    use crate::{
        config::NodeConfig,
        networking::{self, client::NetworkClient},
        primary::node::{PrimaryNode, DEFAULT_CHANNEL_SIZE},
        proof_system::{ProverParameters, StateUpdate},
        proxy::node::ProxyNode,
    };

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn local_proxy() {
        let config = NodeConfig {
            client_server_address: crate::networking::get_test_address(),
            proxy_server_address: crate::networking::get_test_address(),
            prover_parameters: ProverParameters::new_for_tests(),
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

        let total_requests = 100;
        for i in 0..total_requests {
            let state_update = vec![i; 32];
            tx_outgoing.send(vec![state_update]).await.unwrap();
        }

        // Wait for all requests to be processed
        tokio::time::timeout(Duration::from_millis(100), async move {
            for _ in 0..total_requests {
                let _ = rx_output.recv().await.unwrap();
            }
        })
        .await
        .expect("Timed out waiting for output");
    }

    async fn client(
        server_address: SocketAddr,
        state_updates: Vec<Vec<StateUpdate>>,
    ) -> JoinHandle<Result<(), std::io::Error>> {
        // Create a network client to submit requests to the primary node
        let (tx_incoming, _rx_incoming) = mpsc::channel(1);
        let (tx_outgoing, rx_outgoing) = mpsc::channel(1);
        let client_handle =
            NetworkClient::<(), _>::new(server_address, tx_incoming, rx_outgoing).spawn();

        for update in state_updates {
            tx_outgoing.send(update).await.unwrap();
        }

        client_handle
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn end_to_end() {
        // Setup the configuration for the proxy node
        let config = NodeConfig {
            client_server_address: networking::get_test_address(),
            proxy_server_address: networking::get_test_address(),
            prover_parameters: ProverParameters {
                total_compression_levels: 3,
                ..ProverParameters::new_for_tests()
            },
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
        let state_updates = crate::proof_system::sample_state_updates();
        let total_state_updates = state_updates.len();
        let _client_handle = client(config.client_server_address, state_updates).await;

        // Wait for all requests to be processed
        tokio::time::timeout(Duration::from_millis(100), async move {
            for _ in 0..total_state_updates {
                let _ = rx_output.recv().await.unwrap();
            }
        })
        .await
        .expect("Timed out waiting for output");
    }
}
