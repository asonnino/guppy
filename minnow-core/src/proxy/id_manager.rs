// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::{ProofIndex, ProtocolMessage};

pub struct IdManager {
    map: BTreeMap<ProofIndex, Vec<ProtocolMessage>>,
}

impl IdManager {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, material: ProtocolMessage) {
        self.map.entry(material.index()).or_default().push(material);
    }

    pub fn pop_lowest(&mut self) -> Option<ProtocolMessage> {
        if let Some((&id, vec)) = self.map.iter_mut().next() {
            let object = vec.pop();
            if vec.is_empty() {
                self.map.remove(&id);
            }
            object
        } else {
            None
        }
    }
}
