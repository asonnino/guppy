// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use clap::Parser;
use minnow_core::{
    client::Client,
    config::{ImportExport, NodeConfig},
    networking,
    primary::node::PrimaryNode,
    proof_system::{Proof, ProverParameters},
    proxy::node::ProxyNode,
};
use tokio::sync::mpsc;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    operation: Operation,
}

#[derive(Parser)]
enum Operation {
    Primary {
        #[clap(long, value_name = "FILE")]
        config_path: String,

        #[clap(long, default_value_t = 10, value_name = "LOAD")]
        load: usize,
    },
    Proxy {
        #[clap(long, value_name = "FILE")]
        config_path: String,
    },
    DryRun {
        #[clap(long, default_value_t = 10, value_name = "LOAD")]
        load: usize,
    },
}

#[tokio::main]
async fn main() {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();
    match args.operation {
        Operation::Primary { config_path, load } => run_primary_node(config_path, load).await,
        Operation::Proxy { config_path } => run_proxy_node(config_path).await,
        Operation::DryRun { load } => dry_run(load).await,
    }
}

fn sink_output(mut rx_output: mpsc::Receiver<Proof>) {
    tokio::spawn(async move {
        while let Some(output) = rx_output.recv().await {
            tracing::info!("Received output from primary node: {output:?}");
        }
    });
}

async fn run_primary_node(config_path: impl AsRef<Path>, load: usize) {
    let config = NodeConfig::load(&config_path).expect("Failed to load primary node configuration");
    let (tx_output, rx_output) = tokio::sync::mpsc::channel(1024);
    sink_output(rx_output);
    let primary_handle = PrimaryNode::start(config.clone(), tx_output).join();
    let client_handle = Client::new(config, load).run();
    tokio::join!(primary_handle, client_handle);
}

async fn run_proxy_node(config_path: impl AsRef<Path>) {
    let config = NodeConfig::load(&config_path).expect("Failed to load proxy node configuration");
    ProxyNode::start(config).join().await;
}

async fn dry_run(load: usize) {
    tracing::info!("Deploying local testbed with 1 primary and 1 proxy node");
    let config = NodeConfig {
        client_server_address: networking::get_test_address(),
        proxy_server_address: networking::get_test_address(),
        metrics_server_address: networking::get_test_address(),
        prover_parameters: ProverParameters::default(),
    };

    let (tx_output, rx_output) = tokio::sync::mpsc::channel(1024);
    sink_output(rx_output);
    let primary_handle = PrimaryNode::start(config.clone(), tx_output).join();
    let proxy_handle = ProxyNode::start(config.clone()).join();

    tokio::task::yield_now().await; // Ensure tasks are scheduled

    let client_handle = Client::new(config, load).run();

    tokio::join!(primary_handle, proxy_handle, client_handle);
}
