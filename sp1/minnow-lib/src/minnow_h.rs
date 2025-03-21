use rkyv::{Archive, Deserialize, Serialize};
use sha3::{Digest as OtherDigest, Sha3_256};

use crate::{BatchCheckpointUpdates, CheckpointUpdates, Digest, StreamPoint};

// The state of the ZK service. The size is n
#[derive(Serialize, Deserialize, Archive, Debug, Clone, PartialEq, Eq)]
pub struct MinnowHServiceState {
    pub stream_points: Vec<StreamPoint>,
}

impl From<Vec<StreamPoint>> for MinnowHServiceState {
    fn from(stream_points: Vec<StreamPoint>) -> Self {
        Self { stream_points }
    }
}

impl MinnowHServiceState {
    pub fn new(stream_points: Vec<StreamPoint>) -> Self {
        Self { stream_points }
    }

    // Note: Run by the prover. Not expected to be called from the zkVM.
    pub fn generate_hints_batch_and_process_batch_updates(
        &mut self,
        batch: &BatchCheckpointUpdates,
    ) -> HintsBatch {
        let mut hints = Vec::new();
        for checkpoint_updates in &batch.0 {
            let h = self.generate_hints(checkpoint_updates);
            hints.push(h);
            self.process_single_update(checkpoint_updates);
        }
        HintsBatch(hints)
    }

    // Note: Run by the prover. Not expected to be called from the zkVM.
    pub fn generate_hints(&self, u: &CheckpointUpdates) -> Vec<Hint> {
        assert!(check_sorted(u));
        let mut hints = Vec::new();
        for j in 0..self.stream_points.len() {
            let stream_point = &self.stream_points[j];

            // Find the insertion point where stream_id would fit. Can return [0, u.len()]
            let i = u.partition_point(|pred_point| pred_point.id <= stream_point.id);

            // Check if we found an exact match (need to look at previous element)
            let b = i > 0 && u[i - 1].id == stream_point.id;
            let hint_index = if b { i - 1 } else { i };

            hints.push((b, hint_index.try_into().unwrap()));
        }
        hints
    }

    #[sp1_derive::cycle_tracker]
    pub fn process_batch_updates_with_hints(
        &mut self,
        batch: &BatchCheckpointUpdates,
        hints: &HintsBatch,
    ) {
        for (checkpoint_updates, hints) in batch.0.iter().zip(hints.0.iter()) {
            self.process_single_update_with_hints(checkpoint_updates, hints);
        }
    }

    pub fn process_single_update_with_hints(
        &mut self,
        checkpoint_updates: &CheckpointUpdates,
        hints: &Hints,
    ) {
        for (i, (b, hint_index)) in hints.iter().enumerate() {
            if *b {
                self.stream_points[i] = checkpoint_updates[*hint_index].clone();
            } else {
                // Check that the element is indeed not in the checkpoint updates
                let stream_point = &self.stream_points[i];
                if *hint_index < checkpoint_updates.len() {
                    let next_stream_id = checkpoint_updates[*hint_index].id;
                    assert!(stream_point.id < next_stream_id);
                }
                if *hint_index > 0 {
                    let prev_stream_id = checkpoint_updates[*hint_index - 1].id;
                    assert!(prev_stream_id < stream_point.id);
                }
            }
        }
    }

    // O(m * n * c) operations: linear scan
    #[sp1_derive::cycle_tracker]
    pub fn process_batch_updates(&mut self, batch: &BatchCheckpointUpdates) {
        for checkpoint_updates in &batch.0 {
            self.process_single_update(checkpoint_updates);
        }
    }

    pub fn process_single_update(&mut self, checkpoint_updates: &CheckpointUpdates) {
        for stream_point in self.stream_points.iter_mut() {
            if let Some(new_stream_point) =
                checkpoint_updates.iter().find(|s| s.id == stream_point.id)
            {
                *stream_point = new_stream_point.clone();
            }
        }
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
    pub fn compute_global_commitment(&self) -> Digest {
        let mut hasher = Sha3_256::new();
        for stream_point in &self.stream_points {
            hasher.update(&stream_point.id.to_le_bytes());
            hasher.update(&stream_point.digest);
        }
        hasher.finalize().into()
    }
}

// For each index j in ZKServiceState, generate a hint (b, i)
//  if b is true, then u[i].0 == z[j].0
//  if b is false, then u[i-1].0 < z[j].0 < u[i].0
pub type Hint = (bool, usize);
pub type Hints = Vec<Hint>;
#[derive(Serialize, Deserialize, Archive)]
pub struct HintsBatch(pub Vec<Hints>);

pub fn check_sorted(u: &CheckpointUpdates) -> bool {
    u.windows(2).all(|w| w[0].id <= w[1].id)
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn test_process_single_checkpoint_updates() {
        let checkpoint_updates = vec![StreamPoint::new(1, [1; 32]), StreamPoint::new(2, [2; 32])];
        let mut v_prev: MinnowHServiceState = vec![
            StreamPoint::new(1, [0; 32]),
            StreamPoint::new(2, [0; 32]),
            StreamPoint::new(3, [3; 32]),
        ]
        .into();
        let expected = vec![
            StreamPoint::new(1, [1; 32]),
            StreamPoint::new(2, [2; 32]),
            StreamPoint::new(3, [3; 32]),
        ]
        .into();
        v_prev.process_single_update(&checkpoint_updates);
        assert_eq!(v_prev, expected);
    }

    #[test]
    fn test_process_batch_checkpoint_updates() {
        let batch = BatchCheckpointUpdates(vec![
            vec![StreamPoint::new(1, [1; 32]), StreamPoint::new(2, [2; 32])],
            vec![StreamPoint::new(1, [3; 32]), StreamPoint::new(3, [4; 32])],
        ]);
        let mut v_prev: MinnowHServiceState = vec![
            StreamPoint::new(1, [0; 32]),
            StreamPoint::new(2, [0; 32]),
            StreamPoint::new(3, [0; 32]),
        ]
        .into();
        let expected = vec![
            StreamPoint::new(1, [3; 32]),
            StreamPoint::new(2, [2; 32]),
            StreamPoint::new(3, [4; 32]),
        ]
        .into();
        v_prev.process_batch_updates(&batch);
        assert_eq!(v_prev, expected);
    }

    #[test]
    fn test_hints() {
        let checkpoint_updates = vec![StreamPoint::new(1, [1; 32]), StreamPoint::new(2, [2; 32])];
        let mut z_prev: MinnowHServiceState = vec![
            StreamPoint::new(1, [0; 32]),
            StreamPoint::new(2, [0; 32]),
            StreamPoint::new(3, [3; 32]),
        ]
        .into();
        let hints = z_prev.generate_hints(&checkpoint_updates);
        assert_eq!(hints, vec![(true, 0), (true, 1), (false, 2)]);
        z_prev.process_single_update_with_hints(&checkpoint_updates, &hints);
        assert_eq!(
            z_prev,
            vec![
                StreamPoint::new(1, [1; 32]),
                StreamPoint::new(2, [2; 32]),
                StreamPoint::new(3, [3; 32]),
            ]
            .into()
        );

        let checkpoint_updates = vec![StreamPoint::new(1, [1; 32]), StreamPoint::new(2, [2; 32])];
        let z_prev = vec![StreamPoint::new(1, [0; 32]), StreamPoint::new(3, [3; 32])];
        let mut z_prev: MinnowHServiceState = z_prev.into();
        let hints = z_prev.generate_hints(&checkpoint_updates);
        assert_eq!(hints, vec![(true, 0), (false, 2)]);
        z_prev.process_single_update_with_hints(&checkpoint_updates, &hints);
        assert_eq!(
            z_prev,
            vec![StreamPoint::new(1, [1; 32]), StreamPoint::new(3, [3; 32])].into()
        );

        let checkpoint_updates = vec![StreamPoint::new(1, [1; 32]), StreamPoint::new(5, [2; 32])];
        let z_prev = vec![
            StreamPoint::new(1, [0; 32]),
            StreamPoint::new(3, [3; 32]),
            StreamPoint::new(4, [4; 32]),
        ];
        let mut z_prev: MinnowHServiceState = z_prev.into();
        let hints = z_prev.generate_hints(&checkpoint_updates);
        assert_eq!(hints, vec![(true, 0), (false, 1), (false, 1)]);
        z_prev.process_single_update_with_hints(&checkpoint_updates, &hints);
        assert_eq!(
            z_prev,
            vec![
                StreamPoint::new(1, [1; 32]),
                StreamPoint::new(3, [3; 32]),
                StreamPoint::new(4, [4; 32])
            ]
            .into()
        );

        // generate 20 updates
        let mut checkpoint_updates = Vec::new();
        for i in 0..20 {
            checkpoint_updates.push(StreamPoint::new(5 * i as u32, [i + 10 as u8; 32]));
        }
        let z_prev = vec![
            StreamPoint::new(0, [0; 32]),
            StreamPoint::new(23, [23; 32]),
            StreamPoint::new(50, [50; 32]),
        ];
        let mut z_prev: MinnowHServiceState = z_prev.into();
        let hints = z_prev.generate_hints(&checkpoint_updates);
        assert_eq!(hints, vec![(true, 0), (false, 5), (true, 10)]);
        z_prev.process_single_update_with_hints(&checkpoint_updates, &hints);
        assert_eq!(
            z_prev,
            vec![
                StreamPoint::new(0, [10; 32]),
                StreamPoint::new(23, [23; 32]),
                StreamPoint::new(50, [20; 32])
            ]
            .into()
        );
    }
}
