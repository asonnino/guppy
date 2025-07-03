// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{Debug, Display},
    net::IpAddr,
    ops::Deref,
    path::PathBuf,
};

use minnow_core::config::{
    DEFAULT_CLIENT_SERVER_PORT, DEFAULT_METRICS_SERVER_PORT, DEFAULT_PROXY_SERVER_PORT,
};
use serde::{Deserialize, Serialize};

use super::{ProtocolCommands, ProtocolMetrics, ProtocolParameters, BINARY_PATH};
use crate::{
    benchmark::BenchmarkParameters, client::Instance, collector::MetricLabel, settings::Settings,
};

const TARGET_CONFIG_FILE: &str = "target_configs.yaml";

#[derive(Clone, Serialize, Deserialize)]
pub struct TargetConfigs {
    #[serde(default)]
    pub prover_parameters: minnow_core::proof_system::ProverParameters,
    pub proxies: u16,
    pub load: u16,
    pub duration: u16,
}

impl Deref for TargetConfigs {
    type Target = minnow_core::proof_system::ProverParameters;

    fn deref(&self) -> &Self::Target {
        &self.prover_parameters
    }
}

impl Debug for TargetConfigs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.proxies)
    }
}

impl Display for TargetConfigs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} proxies", self.proxies)
    }
}

impl Default for TargetConfigs {
    fn default() -> Self {
        Self {
            prover_parameters: minnow_core::proof_system::ProverParameters::default(),
            proxies: 0,
            load: 10,
            duration: 60,
        }
    }
}

impl ProtocolParameters for TargetConfigs {}
impl ProtocolParameters for Vec<TargetConfigs> {}

pub struct TargetProtocol {
    working_dir: PathBuf,
}

impl ProtocolCommands for TargetProtocol {
    fn protocol_dependencies(&self) -> Vec<&'static str> {
        vec![
            "sudo apt -y install libfontconfig1-dev",
            "sudo apt-get install -y clang",
        ]
    }

    fn db_directories(&self) -> Vec<std::path::PathBuf> {
        vec![]
    }

    async fn genesis_command<'a, I>(
        &self,
        mut instances: I,
        parameters: &BenchmarkParameters,
    ) -> String
    where
        I: Iterator<Item = &'a Instance>,
    {
        // Get the primary instance IP address.
        let primary_ip = instances
            .next()
            .expect("At least one instance is required for the genesis command")
            .main_ip;

        // Create the config file (same for all nodes).
        let config = &minnow_core::config::NodeConfig {
            client_server_address: format!("{primary_ip}:{DEFAULT_CLIENT_SERVER_PORT}")
                .parse()
                .unwrap(),
            proxy_server_address: format!("{primary_ip}:{DEFAULT_PROXY_SERVER_PORT}")
                .parse()
                .unwrap(),
            metrics_server_address: format!("{primary_ip}:{DEFAULT_METRICS_SERVER_PORT}")
                .parse()
                .unwrap(),
            prover_parameters: parameters.target_configs.prover_parameters.clone(),
        };

        // Command to upload the config of the db and the stress client.
        let target_configs_string = serde_yaml::to_string(config).unwrap();
        let target_configs_path = self.working_dir.join(TARGET_CONFIG_FILE);
        let upload_target_configs = format!(
            "echo -e '{target_configs_string}' > {}",
            target_configs_path.display()
        );
        ["source $HOME/.cargo/env", &upload_target_configs].join(" && ")
    }

    fn node_command<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        let target_configs_path = self.working_dir.join(TARGET_CONFIG_FILE);
        instances
            .into_iter()
            .enumerate()
            .map(|(i, instance)| {
                // Command to run the benchmark
                let mut run = vec![
                    "RUST_LOG=minnow_core=info".to_string(),
                    format!("./{BINARY_PATH}/minnow-core"),
                ];
                run.extend(if i == 0 {
                    // The first instance is the primary node.
                    let configs = &parameters.target_configs;
                    vec![
                        "primary".to_string(),
                        format!("--load {}", configs.load),
                        format!("--duration {}", configs.duration),
                    ]
                } else {
                    vec!["proxy".to_string()]
                });
                run.push(format!("--config-path {}", target_configs_path.display()));

                // Join the commands to run on the instance.
                let command = ["source $HOME/.cargo/env", &run.join(" ")].join(" && ");
                (instance, command)
            })
            .collect()
    }
}

impl ProtocolMetrics for TargetProtocol {
    fn bucket_metrics(&self) -> Vec<MetricLabel> {
        vec![
            MetricLabel("total_latency_s".to_string()),
            MetricLabel("provers_latency_s".to_string()),
        ]
    }

    fn nodes_metrics_path<I>(
        &self,
        instances: I,
        _parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        instances
            .into_iter()
            .map(|x| {
                let ip = IpAddr::V4(x.main_ip);
                let path = format!("{ip}:{DEFAULT_METRICS_SERVER_PORT}/metrics",);
                (x, path)
            })
            .collect()
    }
}

impl TargetProtocol {
    /// Make a new instance of the target protocol commands generator.
    pub fn new(settings: &Settings) -> Self {
        Self {
            working_dir: settings.working_dir.clone(),
        }
    }
}
