pub mod utils;

use utils::{Digest, MyCircuitBuilder as CircuitBuilder, MyPartialWitness as PartialWitness, F, H};

use plonky2::field::types::Field;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::config::Hasher;

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

    // TODO: Should we use hash_or_noop or hash_pad here?
    let checkpoint_commitment = H::hash_or_noop(checkpoint_commitment_inputs.as_slice());
    let f = [prev_head.elements, checkpoint_commitment.elements].concat();
    H::hash_or_noop(&f)
}

#[derive(Clone, Debug)]
pub struct StreamPointTarget {
    pub stream_id_t: Target,
    pub stream_val_t: Vec<Target>,
    pub new_flag_t: BoolTarget,
}

impl StreamPointTarget {
    pub fn new(builder: &mut CircuitBuilder) -> Self {
        Self {
            stream_id_t: builder.add_virtual_target(),
            stream_val_t: builder.add_virtual_targets(STREAM_VAL_LEN_F),
            new_flag_t: builder.add_virtual_bool_target_safe(),
        }
    }

    pub fn from_existing(
        stream_id_t: Target,
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
        let mut targets = vec![self.stream_id_t];
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
        pw.set_target(self.stream_id_t, encoded_leaf_data.stream_id_f)
            .unwrap();
        for i in 0..encoded_leaf_data.stream_val_f.len() {
            pw.set_target(self.stream_val_t[i], encoded_leaf_data.stream_val_f[i])
                .unwrap();
        }
        pw.set_target(self.new_flag_t.target, encoded_leaf_data.new_flag_f)
            .unwrap();
    }
}
