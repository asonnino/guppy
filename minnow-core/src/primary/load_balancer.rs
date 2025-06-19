// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use tokio::sync::mpsc::{self, Sender};

pub struct LoadBalancer<M> {
    tx_local_proxy: Sender<M>,
    proxy_connections: BTreeMap<u16, Sender<M>>,
}

impl<M> LoadBalancer<M> {
    pub fn new(tx_local_proxy: Sender<M>) -> Self {
        Self {
            tx_local_proxy,
            proxy_connections: BTreeMap::new(),
        }
    }

    pub fn add_proxy(&mut self, tx: Sender<M>) {
        self.proxy_connections.insert(0, tx);
    }

    // TODO: Add a method to lower the weight of a proxy connection after processing.
    pub async fn send(&mut self, message: M) -> Result<(), mpsc::error::SendError<M>> {
        let mut m = Some(message);

        while let Some((weight, tx)) = self.proxy_connections.pop_first() {
            if let Err(e) = tx.send(m.take().unwrap()).await {
                tracing::warn!("Failed to send message to proxy with weight {weight}: {e}");
                m.replace(e.0);
            } else {
                self.proxy_connections.insert(weight + 1, tx);
                tracing::debug!("Message sent to proxy with weight {weight}");
                return Ok(());
            }
        }

        self.tx_local_proxy.send(m.take().unwrap()).await
    }
}
