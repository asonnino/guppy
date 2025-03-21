use std::collections::HashMap;

use merkle::{MerkleProof, MerkleTree};
use rkyv::{Archive, Deserialize, Serialize};

use crate::{BatchCheckpointUpdates, CheckpointUpdates, Digest, StreamID, StreamPoint};

#[macro_use]
pub mod merkle;

#[derive(Debug, Clone)]
pub struct MinnowMTServiceState {
    merkle_tree: MerkleTree,
    stream_points: Vec<StreamPoint>,
    // used to quickly find the index of a stream point
    stream_id_to_idx: HashMap<StreamID, usize>,
}

impl MinnowMTServiceState {
    /// Create a new MinnowMTServiceState for the given set of streams.
    /// Currently, MinnowMT only supports an a-priori fixed set of streams.
    /// TODO: in the future, allow streams to be added.
    pub fn new(stream_points: Vec<StreamPoint>) -> Self {
        let mut stream_id_to_idx = HashMap::new();
        for (i, stream_point) in stream_points.iter().enumerate() {
            stream_id_to_idx.insert(stream_point.id, i);
        }
        Self {
            merkle_tree: MerkleTree::build_from_leaf_hashes(stream_points.iter().map(
                |stream_point| leaf_hash!(stream_point.id.to_le_bytes(), stream_point.digest),
            )),
            stream_points,
            stream_id_to_idx,
        }
    }

    /// Return the global commitment of the state.
    pub fn global_commitment(&self) -> &Digest {
        self.merkle_tree.root()
    }

    /// Update the state and return the proof for the update.
    pub fn update_and_return_proof(
        &mut self,
        stream_update: StreamPoint,
    ) -> Option<MinnowMTUpdateProof> {
        let stream_id = stream_update.id;
        let idx = self.stream_id_to_idx.get(&stream_id)?;
        let prev_stream_digest = self.stream_points[*idx].digest;
        self.merkle_tree
            .update_leaf_hash(
                *idx,
                leaf_hash!(stream_update.id.to_le_bytes(), stream_update.digest),
            )
            .expect("we check above that the leaf index exists");
        self.stream_points[*idx] = stream_update;
        let merkle_proof = self
            .merkle_tree
            .get_proof(*idx)
            .expect("index should exist");
        Some(MinnowMTUpdateProof {
            stream_id,
            prev_stream_digest,
            tracked_stream_index: *idx as u32,
            inclusion_proof: merkle_proof,
        })
    }

    pub fn process_batch_checkpoint_updates(
        &mut self,
        batch: &BatchCheckpointUpdates,
    ) -> BatchMinnowMTStateUpdates {
        BatchMinnowMTStateUpdates {
            checkpoint_updates: batch
                .0
                .iter()
                .map(|checkpoint_updates| self.process_single_checkpoint_update(checkpoint_updates))
                .collect(),
        }
    }

    pub fn process_single_checkpoint_update(
        &mut self,
        checkpoint_updates: &CheckpointUpdates,
    ) -> MinnowMTStateUpdates {
        MinnowMTStateUpdates {
            stream_update_proofs: checkpoint_updates
                .iter()
                .filter_map(|stream_point| self.update_and_return_proof(stream_point.clone()))
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Archive, Debug, Clone)]
pub struct MinnowMTUpdateProof {
    stream_id: StreamID,
    prev_stream_digest: Digest,
    // Keep this as u32 to not waste space
    tracked_stream_index: u32,
    inclusion_proof: MerkleProof,
}

impl MinnowMTUpdateProof {
    pub fn verify(&self, prev_global_commitment: &Digest) -> bool {
        self.inclusion_proof.verify_proof_from_leaf_hash(
            prev_global_commitment,
            leaf_hash!(self.stream_id.to_le_bytes(), self.prev_stream_digest),
            self.tracked_stream_index as usize,
        )
    }

    pub fn new_global_commitment(&self, new_stream_digest: &Digest) -> Digest {
        self.inclusion_proof
            .compute_root_from_leaf_hash(
                leaf_hash!(self.stream_id.to_le_bytes(), new_stream_digest),
                self.tracked_stream_index as usize,
            )
            .expect("index should exist")
    }
}

#[derive(Serialize, Deserialize, Archive, Debug, Clone)]
pub struct MinnowMTStateUpdates {
    pub stream_update_proofs: Vec<MinnowMTUpdateProof>,
}

impl MinnowMTStateUpdates {
    // In the worst case, it iterates over all the tracked streams and all the checkpoint updates.
    // This is O(n + m) where n is the number of tracked streams and m is the number of checkpoint updates.
    pub fn process_single_checkpoint_update(
        &self,
        tracked_streams: &[StreamID],
        prev_global_commitment: &Digest,
        checkpoint_updates: &CheckpointUpdates,
    ) -> Digest {
        let mut global_commitment = *prev_global_commitment;
        let mut current_stream_idx = 0;
        let mut update_proof_iter = self.stream_update_proofs.iter();
        let n_tracked_streams = tracked_streams.len();
        'stream_updates: for stream_update in checkpoint_updates {
            // No update for the current stream index, continue to the next one.
            while stream_update.id > tracked_streams[current_stream_idx] {
                current_stream_idx += 1;
                if current_stream_idx >= n_tracked_streams {
                    break 'stream_updates;
                }
            }
            // We are not tracking the stream from this update.
            if stream_update.id < tracked_streams[current_stream_idx] {
                continue 'stream_updates;
            }
            // We are tracking the stream from this update.
            let proof = update_proof_iter
                .next()
                .expect("we should have a proof for each tracked stream that is updated");
            assert_eq!(proof.stream_id, stream_update.id);
            assert!(proof.verify(&global_commitment));
            global_commitment = proof.new_global_commitment(&stream_update.digest);
        }
        global_commitment
    }
}

#[derive(Serialize, Deserialize, Archive, Debug, Clone)]
pub struct BatchMinnowMTStateUpdates {
    pub checkpoint_updates: Vec<MinnowMTStateUpdates>,
}

impl BatchMinnowMTStateUpdates {
    pub fn process_batch_checkpoint_updates(
        &self,
        tracked_streams: &[StreamID],
        prev_global_commitment: &Digest,
        batch_checkpoint_updates: &BatchCheckpointUpdates,
    ) -> Digest {
        let mut global_commitment = *prev_global_commitment;
        for (state_updates, checkpoint_updates) in self
            .checkpoint_updates
            .iter()
            .zip(batch_checkpoint_updates.0.iter())
        {
            global_commitment = state_updates.process_single_checkpoint_update(
                tracked_streams,
                &global_commitment,
                checkpoint_updates,
            );
        }
        global_commitment
    }
}
