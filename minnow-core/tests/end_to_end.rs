// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{io, net::SocketAddr, time::Duration};

use minnow_core::{
    config::NodeConfig,
    networking::{self, client::NetworkClient, DEFAULT_CHANNEL_SIZE},
    primary::node::PrimaryNode,
    proxy::node::ProxyNode,
};
use tokio::{sync::mpsc, task::JoinHandle};

async fn client(
    server_address: SocketAddr,
    total_requests: usize,
) -> JoinHandle<Result<(), io::Error>> {
    // Create a network client to submit requests to the primary node
    let (tx_incoming, _rx_incoming) = mpsc::channel(1);
    let (tx_outgoing, rx_outgoing) = mpsc::channel(1);
    let client_handle =
        NetworkClient::<(), _>::new(server_address, tx_incoming, rx_outgoing).spawn();

    for i in 0..total_requests {
        let state_update = vec![i; 32];
        tx_outgoing.send(state_update).await.unwrap();
    }

    client_handle
}

#[tokio::test]
async fn end_to_end_test() {
    // Setup the configuration for the proxy node
    let config = NodeConfig {
        client_server_address: networking::get_test_address(),
        proxy_server_address: networking::get_test_address(),
        max_compression_level: 3,
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
    let total_requests = 100;
    let _client_handle = client(config.client_server_address, total_requests).await;

    // Wait for all requests to be processed
    tokio::time::timeout(Duration::from_millis(100), async move {
        for _ in 0..total_requests {
            let _ = rx_output.recv().await.unwrap();
        }
    })
    .await
    .expect("Timed out waiting for output");
}
