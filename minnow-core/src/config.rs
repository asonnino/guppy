// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::proof_system::ProverParameters;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeConfig {
    pub proxy_server_address: SocketAddr,
    pub client_server_address: SocketAddr,
    pub prover_parameters: ProverParameters,
}
