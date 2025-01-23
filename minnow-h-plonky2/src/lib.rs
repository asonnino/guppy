use minnow_mt_plonky2::{
    circuit::{Digest, F, H}, CheckpointUpdates, StreamID, StreamPoint, STREAM_VAL_LEN
};
use plonky2::field::types::Field;
use plonky2::plonk::config::Hasher;

pub mod circuit;

pub struct MinnowHServiceState {
    pub stream_points: Vec<StreamPoint>,
}

impl MinnowHServiceState {
    pub fn new(stream_ids: &[StreamID]) -> Self {
        Self {
            stream_points: stream_ids
                .iter()
                .map(|id| StreamPoint::new(*id, [0; STREAM_VAL_LEN]))
                .collect(),
        }
    }

    pub fn commit(&self) -> Digest {
        let encoded_stream_points = self
            .stream_points
            .iter()
            .map(|sp| sp.encode().to_arr())
            .flatten()
            .collect::<Vec<F>>();
        H::hash_or_noop(&encoded_stream_points)
    }

    pub fn len(&self) -> usize {
        self.stream_points.len()
    }

    pub fn iter(&self) -> std::slice::Iter<StreamPoint> {
        self.stream_points.iter()
    }

    pub fn apply_checkpoint_updates(&mut self, checkpoint_updates: &CheckpointUpdates) {
        for point in self.stream_points.iter_mut() {
            for update in checkpoint_updates.iter() {
                if point.id == update.id {
                    point.digest = update.digest;
                    break;
                }
            }
        }
    }
}

// impl MinnowHServiceState {
//     pub fn new(stream_ids: &[StreamID]) -> Self {
//         Self { stream_points: stream_ids.iter().map(|id| StreamPoint::new(*id, vec![0; STREAM_VAL_LEN_F])).collect() }
//     }
// }

// impl From<Vec<StreamPoint>> for MinnowHServiceState {
//     fn from(stream_points: Vec<StreamPoint>) -> Self {
//         Self { stream_points }
//     }
// }

#[cfg(test)]
mod tests {
    use minnow_mt_plonky2::STREAM_VAL_LEN;

    use super::*;

    #[test]
    fn test_commit() {
        let num_tracking_streams = 10;
        let state = MinnowHServiceState {
            stream_points: (0..num_tracking_streams)
                .map(|id| StreamPoint::new(id as StreamID, [0; STREAM_VAL_LEN]))
                .collect(),
        };
        let commitment = state.commit();
        assert_eq!(
            commitment.elements[0],
            F::from_canonical_u64(6109254219606511396)
        );
    }
}
