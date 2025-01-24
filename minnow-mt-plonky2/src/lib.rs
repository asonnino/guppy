pub mod merkle;
use log::trace;
use merkle::{MerkleProof, MerkleProofTargets, MerkleTree};

pub mod circuit;
use circuit::{Digest, MyPartialWitness as PartialWitness, F, H};

pub mod utils;

use plonky2::field::types::Field;
use plonky2::plonk::config::Hasher;

use std::collections::HashMap;

pub const STREAM_VAL_LEN: usize = 32;
pub const STREAM_ID_LEN: usize = 4;
pub const NEW_FLAG_LEN: usize = 4;
pub const STREAM_POINT_LEN: usize = STREAM_VAL_LEN + STREAM_ID_LEN + NEW_FLAG_LEN; // 32 bytes for digest + 4 bytes for stream id + 4 bytes for new flag

pub type StreamVal = [u8; STREAM_VAL_LEN];
pub type StreamID = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPoint {
    pub id: StreamID,
    pub digest: StreamVal,
    pub new: bool,
}

impl StreamPoint {
    pub fn new(id: StreamID, digest: StreamVal) -> Self {
        Self {
            id,
            digest,
            new: false,
        }
    }

    pub fn new_with_flag(id: StreamID, digest: StreamVal, new: bool) -> Self {
        Self { id, digest, new }
    }

    pub fn encode(&self) -> EncodedStreamPoint {
        let stream_id_f = F::from_canonical_u32(self.id);
        let new_flag_f = F::from_bool(self.new);
        let mut digest_f = [F::ZERO; STREAM_VAL_LEN_F];
        for (i, chunk) in self.digest.chunks(CHUNK_SIZE).enumerate() {
            let u32_val = u32::from_le_bytes(chunk.try_into().unwrap());
            digest_f[i] = F::from_canonical_u32(u32_val);
        }
        EncodedStreamPoint {
            stream_id_f,
            stream_val_f: digest_f,
            new_flag_f,
        }
    }
}

// How many bytes to pack into a single field element? We use 4 bytes for now.
// So each leaf looks like this:
//  [stream_id, val_0, val_1, ..., val_8, new_flag]
// TODO: Technically, we have a bit more space since Goldilocks field size is ~2^64, so this can be further optimized (if needed).
const CHUNK_SIZE: usize = 4;
pub const STREAM_VAL_LEN_F: usize = STREAM_VAL_LEN / CHUNK_SIZE;
pub const STREAM_POINT_LEN_F: usize = 2 + STREAM_VAL_LEN_F; // 10

// EncodedStreamPoint is an encoded StreamPoint struct
#[derive(Clone, Debug)]
pub struct EncodedStreamPoint {
    pub stream_id_f: F,
    pub stream_val_f: [F; STREAM_VAL_LEN_F],
    pub new_flag_f: F,
}

impl EncodedStreamPoint {
    pub fn default() -> Self {
        Self {
            stream_id_f: F::ZERO,
            stream_val_f: [F::ZERO; STREAM_VAL_LEN_F],
            new_flag_f: F::ZERO,
        }
    }

    pub fn to_arr(&self) -> [F; STREAM_POINT_LEN_F] {
        let mut arr = [F::ZERO; STREAM_POINT_LEN_F];
        arr[0] = self.stream_id_f;
        arr[1..STREAM_POINT_LEN_F - 1].copy_from_slice(&self.stream_val_f);
        arr[STREAM_POINT_LEN_F - 1] = self.new_flag_f;
        arr
    }
}

// The updates from a single checkpoint. The size is m
pub type CheckpointUpdates = Vec<StreamPoint>;

pub fn commit_single_update(updates: &CheckpointUpdates, prev_head: &Digest) -> Digest {
    let mut checkpoint_commitment_inputs = Vec::new();
    for stream_point in updates {
        checkpoint_commitment_inputs.extend(stream_point.encode().to_arr());
    }
    let checkpoint_commitment = H::hash_or_noop(checkpoint_commitment_inputs.as_slice());
    let f = [prev_head.elements, checkpoint_commitment.elements].concat();
    H::hash_or_noop(&f)
}

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

    #[test]
    fn test_commit_single_update() {
        let d_prev = Digest::ZERO;
        let l = vec![StreamPoint::new(1, [0; STREAM_VAL_LEN])];
        let d = commit_single_update(&l, &d_prev);
        println!("{:?}", d);
    }
}
