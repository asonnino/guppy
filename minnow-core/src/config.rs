// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{io, net::SocketAddr, path::Path};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::proof_system::ProverParameters;

pub const DEFAULT_PROXY_SERVER_PORT: u16 = 8080;
pub const DEFAULT_CLIENT_SERVER_PORT: u16 = 8081;
pub const DEFAULT_METRICS_SERVER_PORT: u16 = 8082;

pub trait ImportExport: Serialize + DeserializeOwned {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let content = std::fs::read_to_string(&path)?;
        let object =
            serde_yaml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(object)
    }

    fn print<P: AsRef<Path>>(&self, path: P) -> Result<(), io::Error> {
        let content =
            serde_yaml::to_string(self).expect("Failed to serialize object to YAML string");
        std::fs::write(&path, content)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeConfig {
    pub proxy_server_address: SocketAddr,
    pub client_server_address: SocketAddr,
    pub metrics_server_address: SocketAddr,
    pub prover_parameters: ProverParameters,
}

impl ImportExport for NodeConfig {}
