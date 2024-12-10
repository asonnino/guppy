use rkyv::{Archive, Deserialize, Serialize};
use sha3::{Digest as OtherDigest, Sha3_256};

pub mod minnow_h;
pub mod minnow_mt;

pub const DIGEST_LEN: usize = 32;
pub type Digest = [u8; DIGEST_LEN];
pub type StreamID = u32;
// A total of 36 bytes per stream point
#[derive(Serialize, Deserialize, Archive, Debug, Clone, PartialEq, Eq)]
pub struct StreamPoint {
    pub id: StreamID,
    pub digest: Digest,
}

impl StreamPoint {
    pub fn new(id: StreamID, digest: Digest) -> Self {
        Self { id, digest }
    }
}

// The updates from a single checkpoint. The size is m
pub type CheckpointUpdates = Vec<StreamPoint>;
// The updates from multiple checkpoints. The size of a batch is c
#[derive(Serialize, Deserialize, Archive)]
pub struct BatchCheckpointUpdates(pub Vec<CheckpointUpdates>);

pub fn check_sorted(u: &CheckpointUpdates) -> bool {
    u.windows(2).all(|w| w[0].id <= w[1].id)
}

// O(m) hashes
#[sp1_derive::cycle_tracker]
pub fn commit_batch_updates(batch: &BatchCheckpointUpdates, d_prev: &Digest) -> Digest {
    let mut d = *d_prev;
    for checkpoint_updates in &batch.0 {
        d = commit_single_update(checkpoint_updates, &d);
    }
    d
}

pub fn commit_single_update(l: &CheckpointUpdates, d_prev: &Digest) -> Digest {
    let mut hasher = Sha3_256::new();
    hasher.update(d_prev);
    for stream_point in l {
        hasher.update(&stream_point.id.to_le_bytes());
        hasher.update(&stream_point.digest);
    }
    hasher.finalize().into()
}

#[sp1_derive::cycle_tracker]
pub fn commit_stream_ids(stream_ids: &[u32]) -> Digest {
    let mut hasher = Sha3_256::new();
    for stream_id in stream_ids {
        hasher.update(&stream_id.to_le_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn test_commit_single_checkpoint_updates() {
        let checkpoint_updates = vec![StreamPoint::new(1, [1; 32]), StreamPoint::new(2, [2; 32])];
        let d_prev = [0; 32];
        let commitment = commit_single_update(&checkpoint_updates, &d_prev);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_commit_batch_checkpoint_updates() {
        let batch = BatchCheckpointUpdates(vec![
            vec![StreamPoint::new(1, [1; 32]), StreamPoint::new(2, [2; 32])],
            vec![StreamPoint::new(1, [3; 32]), StreamPoint::new(3, [4; 32])],
        ]);
        let d_prev = [0; 32];
        let commitment = commit_batch_updates(&batch, &d_prev);
        assert_eq!(commitment.len(), 32);
    }
}
