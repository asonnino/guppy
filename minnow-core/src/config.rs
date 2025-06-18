// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeConfig {
    pub proxy_server_address: SocketAddr,
    pub client_server_address: SocketAddr,
    pub max_compression_level: u16,
}
