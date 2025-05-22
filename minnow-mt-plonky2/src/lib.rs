pub mod merkle;
use log::trace;
use merkle::{MerkleProof, MerkleProofTargets, MerkleTree};

pub mod one_step_circuit;
pub mod three_step_circuit;
pub mod two_step_circuit;

use minnow_lib::utils::{Digest, MyPartialWitness as PartialWitness};

use std::collections::HashMap;

use minnow_lib::{StreamID, StreamPoint};

#[derive(Debug)]
pub struct MinnowMTServiceState {
    pub merkle_tree: MerkleTree,
    // used to quickly find the index of a stream point
    stream_id_to_idx: HashMap<StreamID, usize>,
}

impl MinnowMTServiceState {
    pub fn new(stream_points: &[StreamPoint], max_log_state_size: usize) -> Self {
        let mut stream_id_to_idx = HashMap::new();
        for (i, stream_point) in stream_points.iter().enumerate() {
            stream_id_to_idx.insert(stream_point.id, i);
        }
        let num_levels = max_log_state_size + 1;
        let merkle_tree = MerkleTree::build_from_stream_points(stream_points, num_levels);
        Self {
            merkle_tree,
            stream_id_to_idx,
        }
    }

    pub fn get_num_leaves(&self) -> usize {
        self.merkle_tree.get_num_leaves()
    }

    pub fn get_root(&self) -> Digest {
        self.merkle_tree.root()
    }

    pub fn get_proof(&self, index: usize) -> MerkleProof {
        self.merkle_tree.get_proof(index).unwrap()
    }

    pub fn get_idx(&self, stream_id: &StreamID) -> Option<usize> {
        self.stream_id_to_idx.get(stream_id).cloned()
    }

    pub fn update_leaf(&mut self, point: &StreamPoint) {
        let idx = self.get_idx(&point.id);
        if idx.is_none() {
            // If the stream point is not in the tree, add it
            let idx = self.merkle_tree.add_leaf(point);
            self.stream_id_to_idx.insert(point.id, idx);
        } else {
            // If the stream point is already in the tree, update it
            let idx = idx.unwrap();
            self.merkle_tree.update_leaf(idx, &point).unwrap();
        }
    }

    // Add Merkle proof verification to the circuit for a given stream ID.
    // If the stream ID is absent, we use the next available index under the expectation that update_leaf() will be called after this.
    pub fn add_proof_targets(
        &self,
        pw: &mut PartialWitness,
        targets: &MerkleProofTargets,
        stream_id: &StreamID,
    ) {
        let mut index = self.get_idx(stream_id);
        if index.is_none() {
            trace!("add_proof_targets: adding to end");
            index = Some(self.merkle_tree.get_num_leaves());
        }
        let index = index.unwrap();
        trace!("add_proof_targets: adding verification for stream");

        let proof = self.get_proof(index);
        let root = self.merkle_tree.root();
        let leaf = self.merkle_tree.get_leaf(index);
        proof.set_proof_targets(pw, targets, &root, &leaf, index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minnow_lib::commit_single_update;
    use minnow_lib::STREAM_VAL_LEN;

    #[test]
    fn test_commit_single_update() {
        let d_prev = Digest::ZERO;
        let l = vec![StreamPoint::new(1, [0; STREAM_VAL_LEN])];
        let d = commit_single_update(&l, &d_prev);
        println!("{:?}", d);
    }
}
