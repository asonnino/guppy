use sha3::{Digest as OtherDigest, Sha3_256};

pub type Digest = [u8; 32];
pub type StreamID = u32;

// The updates from a single checkpoint. The size is m
pub type CheckpointUpdates = Vec<(StreamID, Digest)>;
// The updates from multiple checkpoints. The size of the outermost vector is c
pub type BatchCheckpointUpdates = Vec<CheckpointUpdates>;
// The global state of the ZK service. The size is n
pub type GlobalState = Vec<(StreamID, Digest)>;

// O(m * n * c) operations
#[sp1_derive::cycle_tracker]
pub fn process_batch_updates(batch: &BatchCheckpointUpdates, v_prev: &GlobalState) -> GlobalState {
    let mut v = v_prev.clone();
    for checkpoint_updates in batch {
        v = process_single_update(checkpoint_updates, &v);
    }
    v
}

pub fn process_single_update(
    checkpoint_updates: &CheckpointUpdates,
    v_prev: &GlobalState,
) -> GlobalState {
    let mut v_next = GlobalState::new();
    for (stream, existing_value) in v_prev {
        if let Some((_, new_value)) = checkpoint_updates.iter().find(|(s, _)| s == stream) {
            v_next.push((*stream, *new_value));
        } else {
            v_next.push((*stream, *existing_value));
        }
    }
    v_next
}

// pub fn compute_new_state(l: &CheckpointUpdates, v_prev: &GlobalState) -> GlobalState {
//     let mut v_next = GlobalState::new();
//     for (stream, existing_value) in v_prev {
//         if let Some(new_value) = l.get(stream) {
//             v_next.push((*stream, *new_value));
//         } else {
//             v_next.push((*stream, *existing_value));
//         }
//     }
//     v_next
// }

// O(n) hashes
#[sp1_derive::cycle_tracker]
pub fn compute_global_commitment(v: &GlobalState) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for (stream, value) in v {
        hasher.update(stream.to_le_bytes());
        hasher.update(value);
    }
    hasher.finalize().into()
}

// O(m) hashes
#[sp1_derive::cycle_tracker]
pub fn commit_batch_updates(batch: &BatchCheckpointUpdates, d_prev: &Digest) -> Digest {
    let mut d = *d_prev;
    for checkpoint_updates in batch {
        d = commit_single_update(checkpoint_updates, &d);
    }
    d
}

pub fn commit_single_update(l: &CheckpointUpdates, d_prev: &Digest) -> Digest {
    let mut hasher = Sha3_256::new();
    hasher.update(d_prev);
    for (stream, value) in l {
        hasher.update(stream.to_le_bytes());
        hasher.update(value);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_single_checkpoint_updates() {
        let checkpoint_updates = vec![(1, [1; 32]), (2, [2; 32])];
        let v_prev = vec![(1, [0; 32]), (2, [0; 32]), (3, [3; 32])];
        let expected = vec![(1, [1; 32]), (2, [2; 32]), (3, [3; 32])];
        let result = process_single_update(&checkpoint_updates, &v_prev);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_process_batch_checkpoint_updates() {
        let batch = vec![
            vec![(1, [1; 32]), (2, [2; 32])],
            vec![(1, [3; 32]), (3, [4; 32])],
        ];
        let v_prev = vec![(1, [0; 32]), (2, [0; 32]), (3, [0; 32])];
        let expected = vec![(1, [3; 32]), (2, [2; 32]), (3, [4; 32])];
        let result = process_batch_updates(&batch, &v_prev);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_commit_single_checkpoint_updates() {
        let checkpoint_updates = vec![(1, [1; 32]), (2, [2; 32])];
        let d_prev = [0; 32];
        let commitment = commit_single_update(&checkpoint_updates, &d_prev);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_commit_batch_checkpoint_updates() {
        let batch = vec![
            vec![(1, [1; 32]), (2, [2; 32])],
            vec![(1, [3; 32]), (3, [4; 32])],
        ];
        let d_prev = [0; 32];
        let commitment = commit_batch_updates(&batch, &d_prev);
        assert_eq!(commitment.len(), 32);
    }
}
