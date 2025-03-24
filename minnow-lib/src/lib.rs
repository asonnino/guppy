pub mod checkpoint_commitment;
pub mod merkle;
pub mod utils;

use utils::{Digest, MyCircuitBuilder as CircuitBuilder, MyPartialWitness as PartialWitness, F, H};

use rand::Rng;

use plonky2::field::types::Field;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::config::Hasher;

pub const STREAM_VAL_LEN: usize = 32;
pub const STREAM_ID_LEN: usize = 32;
pub const NEW_FLAG_LEN: usize = 4;
// 32 bytes for digest + 32 bytes for stream id + 4 bytes for new flag
pub const STREAM_POINT_LEN: usize = STREAM_VAL_LEN + STREAM_ID_LEN + NEW_FLAG_LEN;

pub type StreamVal = [u8; STREAM_VAL_LEN];
pub type StreamID = [u8; STREAM_ID_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPoint {
    pub id: StreamID,
    pub digest: StreamVal,
    pub new: bool,
}

impl StreamPoint {
    pub fn default() -> Self {
        Self {
            id: [0; STREAM_ID_LEN],
            digest: [0; STREAM_VAL_LEN],
            new: false,
        }
    }

    pub fn random() -> Self {
        let mut rng = rand::rng();
        let id: StreamID = rng.random();
        let digest: StreamVal = rng.random();
        Self::new(id, digest)
    }

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

    // TODO: Add tests for this function
    pub fn encode(&self) -> EncodedStreamPoint {
        assert!(2_u64.pow(CHUNK_SIZE as u32 * 8) < 0xFFFFFFFF00000001);

        let mut stream_id_f = [F::ZERO; STREAM_ID_LEN_F];
        for (i, chunk) in self.id.chunks(CHUNK_SIZE).enumerate() {
            let u64_val = u64::from_le_bytes({
                let mut bytes = [0u8; 8];
                bytes[..chunk.len()].copy_from_slice(chunk);
                bytes
            });
            stream_id_f[i] = F::from_canonical_u64(u64_val);
        }

        let mut stream_val_f = [F::ZERO; STREAM_VAL_LEN_F];
        for (i, chunk) in self.digest.chunks(CHUNK_SIZE).enumerate() {
            let u64_val = u64::from_le_bytes({
                let mut bytes = [0u8; 8];
                bytes[..chunk.len()].copy_from_slice(chunk);
                bytes
            });
            stream_val_f[i] = F::from_canonical_u64(u64_val);
        }

        let new_flag_f = F::from_bool(self.new);
        EncodedStreamPoint {
            stream_id_f,
            stream_val_f,
            new_flag_f,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.id.iter().cloned());
        bytes.extend(self.digest.iter().cloned());
        bytes.push(self.new as u8);
        bytes
    }
}

// How many bytes to pack into a single field element? We use 7 bytes for now.
// So each leaf looks like this:
//  [id_0, id_1, ..., id_4, val_0, val_1, ..., val_4, new_flag]
// TODO: Technically, we have a bit more space since Goldilocks field size is ~2^64, so this can be further optimized.
const CHUNK_SIZE: usize = 7;
pub const STREAM_VAL_LEN_F: usize = (STREAM_VAL_LEN + CHUNK_SIZE - 1) / CHUNK_SIZE; // ceil(STREAM_VAL_LEN / CHUNK_SIZE)
pub const STREAM_ID_LEN_F: usize = (STREAM_ID_LEN + CHUNK_SIZE - 1) / CHUNK_SIZE; // ceil(STREAM_ID_LEN / CHUNK_SIZE)
pub const STREAM_POINT_LEN_F: usize = STREAM_ID_LEN_F + STREAM_VAL_LEN_F + 1; // 11

// EncodedStreamPoint is an encoded StreamPoint struct
#[derive(Clone, Debug)]
pub struct EncodedStreamPoint {
    pub stream_id_f: [F; STREAM_ID_LEN_F],
    pub stream_val_f: [F; STREAM_VAL_LEN_F],
    pub new_flag_f: F,
}

impl EncodedStreamPoint {
    pub fn default() -> Self {
        StreamPoint::default().encode()
    }

    pub fn to_arr(&self) -> [F; STREAM_POINT_LEN_F] {
        let mut arr = [F::ZERO; STREAM_POINT_LEN_F];
        arr[0..STREAM_ID_LEN_F].copy_from_slice(&self.stream_id_f);
        arr[STREAM_ID_LEN_F..STREAM_ID_LEN_F + STREAM_VAL_LEN_F]
            .copy_from_slice(&self.stream_val_f);
        arr[STREAM_ID_LEN_F + STREAM_VAL_LEN_F] = self.new_flag_f;
        arr
    }
}

// Replace the type alias with this struct
#[derive(Debug, Clone, Default)]
pub struct CheckpointUpdates {
    elements: Vec<StreamPoint>,
}

impl CheckpointUpdates {
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    pub fn push(&mut self, update: StreamPoint) {
        self.elements.push(update);
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &StreamPoint> {
        self.elements.iter()
    }

    pub fn from_iter(iter: impl Iterator<Item = StreamPoint>) -> Self {
        Self {
            elements: iter.collect(),
        }
    }

    pub fn from(vec: Vec<StreamPoint>) -> Self {
        Self { elements: vec }
    }
}

pub fn commit_single_update(updates: &CheckpointUpdates, prev_head: &Digest) -> Digest {
    let mut checkpoint_commitment_inputs = Vec::new();
    for stream_point in updates.iter() {
        checkpoint_commitment_inputs.extend(stream_point.encode().to_arr());
    }

    let checkpoint_commitment = H::hash_or_noop(checkpoint_commitment_inputs.as_slice());
    let f = [prev_head.elements, checkpoint_commitment.elements].concat();
    H::hash_or_noop(&f)
}

#[derive(Clone, Debug)]
pub struct StreamPointTarget {
    pub stream_id_t: Vec<Target>,
    pub stream_val_t: Vec<Target>,
    pub new_flag_t: BoolTarget,
}

impl StreamPointTarget {
    pub fn new(builder: &mut CircuitBuilder) -> Self {
        Self {
            stream_id_t: builder.add_virtual_targets(STREAM_ID_LEN_F),
            stream_val_t: builder.add_virtual_targets(STREAM_VAL_LEN_F),
            new_flag_t: builder.add_virtual_bool_target_safe(),
        }
    }

    pub fn from_existing(
        stream_id_t: Vec<Target>,
        stream_val_t: Vec<Target>,
        new_flag_t: BoolTarget,
    ) -> Self {
        Self {
            stream_id_t,
            stream_val_t,
            new_flag_t,
        }
    }

    pub fn get_all_targets(&self) -> Vec<Target> {
        let mut targets = vec![];
        targets.extend(self.stream_id_t.iter().cloned());
        targets.extend(self.stream_val_t.iter().cloned());
        targets.push(self.new_flag_t.target);
        assert_eq!(targets.len(), STREAM_POINT_LEN_F);
        targets
    }

    pub fn set_proof_targets(
        &self,
        pw: &mut PartialWitness,
        encoded_leaf_data: &EncodedStreamPoint,
    ) {
        for i in 0..STREAM_ID_LEN_F {
            pw.set_target(self.stream_id_t[i], encoded_leaf_data.stream_id_f[i])
                .unwrap();
        }

        for i in 0..STREAM_VAL_LEN_F {
            pw.set_target(self.stream_val_t[i], encoded_leaf_data.stream_val_f[i])
                .unwrap();
        }
        pw.set_target(self.new_flag_t.target, encoded_leaf_data.new_flag_f)
            .unwrap();
    }
}

pub fn usize_to_stream_id(i: usize) -> StreamID {
    let mut id = [0u8; STREAM_ID_LEN];
    id[..8].copy_from_slice(&i.to_le_bytes());
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usize_to_stream_id() {
        let id = usize_to_stream_id(42);
        assert_eq!(id[0], 42);
        assert_eq!(&id[8..], &[0u8; STREAM_ID_LEN - 8]);
    }

    #[test]
    fn test_checkpoint_updates() {
        let mut updates = CheckpointUpdates::new();
        assert!(updates.is_empty());

        let point = StreamPoint::new(usize_to_stream_id(1), [0; STREAM_VAL_LEN]);
        updates.push(point);
        assert_eq!(updates.len(), 1);

        for update in updates.iter() {
            assert_eq!(update.id, usize_to_stream_id(1));
        }
    }
}
