// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::{
    sync::mpsc::{self},
    task::JoinHandle,
};

use crate::{
    config::NodeConfig,
    metrics::Metrics,
    networking::client::NetworkClient,
    proxy::prover_driver::ProverDriver,
};

pub const DEFAULT_CHANNEL_SIZE: usize = 100_000;

pub struct ProxyNode {
    prover_driver_handle: JoinHandle<()>,
    network_client_handle: JoinHandle<std::io::Result<()>>,
    metrics_server_handle: JoinHandle<Result<(), std::io::Error>>,
}

impl ProxyNode {
    pub fn start(config: NodeConfig) -> Self {
        let registry = prometheus::Registry::new();
        let metrics = Arc::new(Metrics::new(&registry));

        let (tx_primary_to_proxy, rx_primary_to_proxy) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (tx_proxy_to_primary, rx_proxy_to_primary) = mpsc::channel(DEFAULT_CHANNEL_SIZE);

        let (_, basic_prover, compress_prover, _) = config.prover_parameters.build_provers();

        let prover_driver_handle = ProverDriver::new(
            metrics,
            rx_primary_to_proxy,
            tx_proxy_to_primary,
            basic_prover,
            compress_prover,
            config.prover_parameters.total_compression_levels,
        )
        .spawn();

        let network_client_handle = NetworkClient::new(
            config.proxy_server_address,
            tx_primary_to_proxy,
            rx_proxy_to_primary,
        )
        .spawn();

        let metrics_server_handle =
            crate::metrics::start_prometheus_server(config.metrics_server_address, &registry);

        tracing::info!("Proxy node started with config: {config:?}");
        Self {
            prover_driver_handle,
            network_client_handle,
            metrics_server_handle,
        }
    }

    pub async fn join(self) {
        let (prover_driver_result, network_client_result, metrics_server_result) = tokio::join!(
            self.prover_driver_handle,
            self.network_client_handle,
            self.metrics_server_handle
        );

        if let Err(e) = prover_driver_result {
            tracing::error!("Prover Driver task failed: {e:?}");
        }
        match network_client_result {
            Ok(Err(e)) => tracing::error!("Proxy network error: {e:?}"),
            Err(e) => tracing::error!("Proxy server task failed: {e:?}"),
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
    use std::time::Duration;

    use futures::future;
    use tokio::sync::mpsc;

    use crate::{
        config::NodeConfig,
        messages::ProtocolMessage,
        networking::server::NetworkServer,
        proof_system::ProverParameters,
        proxy::node::ProxyNode,
    };

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn partial_compression_proof() {
        let config = NodeConfig {
            client_server_address: crate::networking::get_test_address(),
            proxy_server_address: crate::networking::get_test_address(),
            metrics_server_address: crate::networking::get_test_address(),
            prover_parameters: ProverParameters {
                total_compression_levels: 3,
                ..ProverParameters::new_for_tests()
            },
        };
        println!("Starting proxy node with config: {config:?}");

        // Spawn the client and send transactions to the primary.
        let (tx_connections, mut rx_connections) = mpsc::channel(1);
        let (tx_incoming, mut rx_incoming) = mpsc::channel(1);

        let _fake_primary_handle =
            NetworkServer::new(config.proxy_server_address, tx_connections, tx_incoming).spawn();

        // Send a transaction to the proxy.
        let total_base_proofs = 100;

        let sender_handle = tokio::spawn(async move {
            let tx = rx_connections.recv().await.unwrap();
            for i in 0..total_base_proofs {
                let message = ProtocolMessage::BasicProofMaterial {
                    index: i,
                    material: crate::proof_system::sample_partial_witness(),
                };
                tx.send(message).await.unwrap();
            }
        });

        let receiver_handle = tokio::spawn(async move {
            let mut next_expected_index = 0;
            while let Some(reply) = rx_incoming.recv().await {
                match reply {
                    ProtocolMessage::PartialCompressionProof {
                        index,
                        compression_level,
                        ..
                    } => {
                        tracing::info!("Received partial proof for index {index}");
                        assert!(
                            compression_level <= config.prover_parameters.total_compression_levels
                        );
                        assert_eq!(index, next_expected_index);
                        next_expected_index += 1;
                        if next_expected_index == total_base_proofs {
                            tracing::info!("All expected partial proofs received");
                            break;
                        }
                    }
                    _ => panic!("Received unexpected message: {reply:?}"),
                }
            }
        });

        tokio::task::yield_now().await; // Ensure tasks are scheduled

        // Start the proxy node with the given configuration.
        let _proxy_node = ProxyNode::start(config.clone());

        tokio::time::timeout(
            Duration::from_millis(100),
            future::join_all(vec![sender_handle, receiver_handle]),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn final_compression_proof() {
        let config = NodeConfig {
            client_server_address: crate::networking::get_test_address(),
            proxy_server_address: crate::networking::get_test_address(),
            metrics_server_address: crate::networking::get_test_address(),
            prover_parameters: ProverParameters {
                total_compression_levels: 3,
                ..ProverParameters::new_for_tests()
            },
        };
        println!("Starting proxy node with config: {config:?}");

        // Spawn the client and send transactions to the primary.
        let (tx_connections, mut rx_connections) = mpsc::channel(1);
        let (tx_incoming, mut rx_incoming) = mpsc::channel(1);

        let _fake_primary_handle =
            NetworkServer::new(config.proxy_server_address, tx_connections, tx_incoming).spawn();

        // Send a transaction to the proxy.
        let total_base_proofs = 100;

        let sender_handle = tokio::spawn(async move {
            let tx = rx_connections.recv().await.unwrap();
            for i in 0..total_base_proofs {
                let message = ProtocolMessage::PartialCompressionProof {
                    index: i,
                    compression_level: config.prover_parameters.total_compression_levels - 1,
                    proof: crate::proof_system::sample_proof(),
                };
                tx.send(message).await.unwrap();
            }
        });

        let receiver_handle = tokio::spawn(async move {
            let mut next_expected_index = 0;
            while let Some(reply) = rx_incoming.recv().await {
                match reply {
                    ProtocolMessage::FinalCompressionProof { index, .. } => {
                        tracing::info!("Received final proof for index {index}");
                        assert_eq!(index, next_expected_index);
                        next_expected_index += 1;
                        if next_expected_index == total_base_proofs {
                            tracing::info!("All expected proofs received");
                            break; // All expected messages received
                        }
                    }
                    _ => panic!("Received unexpected message: {reply:?}"),
                }
            }
        });

        tokio::task::yield_now().await; // Ensure tasks are scheduled

        // Start the proxy node with the given configuration.
        let _proxy_node = ProxyNode::start(config.clone());

        tokio::time::timeout(
            Duration::from_millis(1000),
            future::join_all(vec![sender_handle, receiver_handle]),
        )
        .await
        .unwrap();
    }
}
