use rkyv::{Archive, Deserialize, Serialize};
use sha3::{Digest as OtherDigest, Sha3_256};

pub mod merkle;

pub const DIGEST_LEN: usize = 32;
pub type Digest = [u8; DIGEST_LEN];
pub type StreamID = u32;
pub type StreamPoint = (StreamID, Digest); // A total of 36 bytes per stream point

// The updates from a single checkpoint. The size is m
pub type CheckpointUpdates = Vec<StreamPoint>;
// The updates from multiple checkpoints. The size of a batch is c
#[derive(Serialize, Deserialize, Archive)]
pub struct BatchCheckpointUpdates(pub Vec<CheckpointUpdates>);

// The state of the ZK service. The size is n
pub type ZKServiceState = Vec<StreamPoint>;

// For each index j in ZKServiceState, generate a hint (b, i)
//  if b is true, then u[i].0 == z[j].0
//  if b is false, then u[i-1].0 < z[j].0 < u[i].0
pub type Hint = (bool, usize);
pub type Hints = Vec<Hint>;
#[derive(Serialize, Deserialize, Archive)]
pub struct HintsBatch(pub Vec<Hints>);

pub fn check_sorted(u: &CheckpointUpdates) -> bool {
    u.windows(2).all(|w| w[0].0 <= w[1].0)
}

// Note: Run by the prover. Not expected to be called from the zkVM.
pub fn generate_hints_batch_and_process_batch_updates(
    batch: &BatchCheckpointUpdates,
    z_prev: &ZKServiceState,
) -> (HintsBatch, ZKServiceState) {
    let mut hints = Vec::new();
    let mut z_next = z_prev.clone();
    for checkpoint_updates in &batch.0 {
        let h = generate_hints(checkpoint_updates, &z_next);
        hints.push(h);
        z_next = process_single_update(checkpoint_updates, &z_next);
    }
    (HintsBatch(hints), z_next)
}

// Note: Run by the prover. Not expected to be called from the zkVM.
pub fn generate_hints(u: &CheckpointUpdates, z_prev: &ZKServiceState) -> Vec<Hint> {
    assert!(check_sorted(u));
    let mut hints = Vec::new();
    for j in 0..z_prev.len() {
        let (stream_id, _) = z_prev[j];

        // Find the insertion point where stream_id would fit. Can return [0, u.len()]
        let i = u.partition_point(|(s, _)| *s <= stream_id);

        // Check if we found an exact match (need to look at previous element)
        let b = i > 0 && u[i - 1].0 == stream_id;
        let hint_index = if b { i - 1 } else { i };

        hints.push((b, hint_index.try_into().unwrap()));
    }
    hints
}

#[sp1_derive::cycle_tracker]
pub fn process_batch_updates_with_hints(
    batch: &BatchCheckpointUpdates,
    z_prev: &ZKServiceState,
    hints: &HintsBatch,
) -> ZKServiceState {
    let mut z_next = z_prev.clone();
    for (checkpoint_updates, hints) in batch.0.iter().zip(hints.0.iter()) {
        z_next = process_single_update_with_hints(checkpoint_updates, &z_next, hints);
    }
    z_next
}

pub fn process_single_update_with_hints(
    checkpoint_updates: &CheckpointUpdates,
    z_prev: &ZKServiceState,
    hints: &Hints,
) -> ZKServiceState {
    let mut z_next = Vec::new();
    for (i, (b, hint_index)) in hints.iter().enumerate() {
        let (stream_id, value) = z_prev[i];
        if *b {
            z_next.push(checkpoint_updates[*hint_index]);
        } else {
            // Check that the element is indeed not in the checkpoint updates
            if *hint_index < checkpoint_updates.len() {
                let next_stream_id = checkpoint_updates[*hint_index].0;
                assert!(stream_id < next_stream_id);
            }
            if *hint_index > 0 {
                let prev_stream_id = checkpoint_updates[*hint_index - 1].0;
                assert!(prev_stream_id < stream_id);
            }

            z_next.push((stream_id, value));
        }
    }
    z_next
}

// O(m * n * c) operations: linear scan
#[sp1_derive::cycle_tracker]
pub fn process_batch_updates(
    batch: &BatchCheckpointUpdates,
    v_prev: &ZKServiceState,
) -> ZKServiceState {
    let mut v = v_prev.clone();
    for checkpoint_updates in &batch.0 {
        v = process_single_update(checkpoint_updates, &v);
    }
    v
}

pub fn process_single_update(
    checkpoint_updates: &CheckpointUpdates,
    v_prev: &ZKServiceState,
) -> ZKServiceState {
    let mut v_next = Vec::new();
    for (stream, existing_value) in v_prev {
        if let Some((_, new_value)) = checkpoint_updates.iter().find(|(s, _)| s == stream) {
            v_next.push((*stream, *new_value));
        } else {
            v_next.push((*stream, *existing_value));
        }
    }
    v_next
}

// // Note: Previous implementation with a HashMap used for GlobalState
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
pub fn compute_global_commitment(v: &ZKServiceState) -> [u8; 32] {
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
    for checkpoint_updates in &batch.0 {
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
    use std::vec;

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
        let batch = BatchCheckpointUpdates(vec![
            vec![(1, [1; 32]), (2, [2; 32])],
            vec![(1, [3; 32]), (3, [4; 32])],
        ]);
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
        let batch = BatchCheckpointUpdates(vec![
            vec![(1, [1; 32]), (2, [2; 32])],
            vec![(1, [3; 32]), (3, [4; 32])],
        ]);
        let d_prev = [0; 32];
        let commitment = commit_batch_updates(&batch, &d_prev);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_hints() {
        let checkpoint_updates = vec![(1, [1; 32]), (2, [2; 32])];
        let z_prev = vec![(1, [0; 32]), (2, [0; 32]), (3, [3; 32])];
        let hints = generate_hints(&checkpoint_updates, &z_prev);
        assert_eq!(hints, vec![(true, 0), (true, 1), (false, 2)]);
        let result = process_single_update_with_hints(&checkpoint_updates, &z_prev, &hints);
        assert_eq!(result, vec![(1, [1; 32]), (2, [2; 32]), (3, [3; 32])]);

        let checkpoint_updates = vec![(1, [1; 32]), (2, [2; 32])];
        let z_prev = vec![(1, [0; 32]), (3, [3; 32])];
        let hints = generate_hints(&checkpoint_updates, &z_prev);
        assert_eq!(hints, vec![(true, 0), (false, 2)]);
        let result = process_single_update_with_hints(&checkpoint_updates, &z_prev, &hints);
        assert_eq!(result, vec![(1, [1; 32]), (3, [3; 32])]);

        let checkpoint_updates = vec![(1, [1; 32]), (5, [2; 32])];
        let z_prev = vec![(1, [0; 32]), (3, [3; 32]), (4, [4; 32])];
        let hints = generate_hints(&checkpoint_updates, &z_prev);
        assert_eq!(hints, vec![(true, 0), (false, 1), (false, 1)]);
        let result = process_single_update_with_hints(&checkpoint_updates, &z_prev, &hints);
        assert_eq!(result, vec![(1, [1; 32]), (3, [3; 32]), (4, [4; 32])]);

        // generate 20 updates
        let mut checkpoint_updates = Vec::new();
        for i in 0..20 {
            checkpoint_updates.push((5 * i as u32, [i + 10 as u8; 32]));
        }
        let z_prev = vec![(0, [0; 32]), (23, [23; 32]), (50, [50; 32])];
        let hints = generate_hints(&checkpoint_updates, &z_prev);
        assert_eq!(hints, vec![(true, 0), (false, 5), (true, 10)]);
        let result = process_single_update_with_hints(&checkpoint_updates, &z_prev, &hints);
        assert_eq!(result, vec![(0, [10; 32]), (23, [23; 32]), (50, [20; 32])]);
    }
}
