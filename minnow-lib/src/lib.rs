pub mod utils;

use plonky2::{
    field::types::Field,
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::config::Hasher,
};
use rand::{Rng, TryRngCore};
use serde::{Deserialize, Serialize};
use utils::{Digest, MyCircuitBuilder as CircuitBuilder, MyPartialWitness as PartialWitness, F, H};
use crossbeam::thread;

pub const DEFAULT_NUM_THREADS: usize = 4;

pub const STREAM_VAL_LEN: usize = 32;
pub const STREAM_ID_LEN: usize = 32;
pub const NEW_FLAG_LEN: usize = 4;
// 32 bytes for digest + 32 bytes for stream id + 4 bytes for new flag
pub const STREAM_POINT_LEN: usize = STREAM_VAL_LEN + STREAM_ID_LEN + NEW_FLAG_LEN;

pub type StreamVal = [u8; STREAM_VAL_LEN];
pub type StreamID = [u8; STREAM_ID_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        let mut id = [0; STREAM_ID_LEN];
        let mut digest = [0; STREAM_VAL_LEN];
        let mut rng = rand::rng();
        rng.try_fill_bytes(&mut id).unwrap();
        rng.try_fill_bytes(&mut digest).unwrap();
        let new = rng.random_bool(0.5);
        Self {
            id,
            digest,
            new,
        }
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
}

// How many bytes to pack into a single field element? We use 7 bytes (since Goldilocks field size is slightly less than 2^64).
// So each leaf looks like this:
//  [id_0, id_1, ..., id_4, val_0, val_1, ..., val_4, new_flag]
const CHUNK_SIZE: usize = 7;
pub const STREAM_VAL_LEN_F: usize = (STREAM_VAL_LEN + CHUNK_SIZE - 1) / CHUNK_SIZE; // ceil(STREAM_VAL_LEN / CHUNK_SIZE)
pub const STREAM_ID_LEN_F: usize = (STREAM_ID_LEN + CHUNK_SIZE - 1) / CHUNK_SIZE; // ceil(STREAM_ID_LEN / CHUNK_SIZE)
pub const STREAM_POINT_LEN_F: usize = STREAM_ID_LEN_F + STREAM_VAL_LEN_F + 1; // 11

// EncodedStreamPoint encodes a StreamPoint struct into the Goldilocks field
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

// All our circuits operates on batches of stream points of fixed size.
pub type Batch = Vec<StreamPoint>;

fn compute_batch_commitments_parallel(
    updates: &Vec<Batch>,
    batch_size: usize,
    max_threads: Option<usize>,
) -> Result<Vec<Digest>, String> {
    let max_threads = max_threads.unwrap_or(DEFAULT_NUM_THREADS);
    
    thread::scope(|s| {
        let mut handles = Vec::new();
        
        // Process batches in chunks to limit concurrent threads
        for chunk in updates.chunks(max_threads) {
            let mut chunk_handles = Vec::new();
            
            for batch in chunk {
                let batch = batch.clone();
                let handle = s.spawn(move |_| {
                    if batch.len() > batch_size {
                        return Err(("Batch size is too large").to_string());
                    }
                    if batch.len() < batch_size {
                        let mut padded_batch = batch.to_vec();
                        while padded_batch.len() < batch_size {
                            padded_batch.push(StreamPoint::default());
                        }
                        Ok(commit_batch(&padded_batch))
                    } else {
                        Ok(commit_batch(&batch))
                    }
                });
                chunk_handles.push(handle);
            }
            
            // Wait for current chunk to complete before starting next chunk
            for handle in chunk_handles {
                handles.push(handle.join().map_err(|e| format!("Thread join error: {:?}", e))?);
            }
        }
        
        // Collect all results, returning early if any error occurs
        let mut results = Vec::new();
        for result in handles {
            results.push(result?);
        }
        Ok(results)
    }).unwrap()
}

pub fn hash_commitment(
    updates: &Vec<Batch>,
    batch_size: usize,
    prev_head: &Digest,
) -> Result<Digest, String> {
    let mut batch_commitments = Vec::new();

    // Note: This computation can be parallelized.
    for batch in updates {
        if batch.len() > batch_size {
            return Err(("Batch size is too large").to_string());
        }
        if batch.len() < batch_size {
            let mut padded_batch = batch.to_vec();
            while padded_batch.len() < batch_size {
                padded_batch.push(StreamPoint::default());
            }
            batch_commitments.push(commit_batch(&padded_batch));
        } else {
            batch_commitments.push(commit_batch(batch));
        }
    }

    // Commit to the batches in a hash chain style
    let mut checkpoint_commitment = prev_head.clone();
    for batch_commitment in batch_commitments {
        let f = [checkpoint_commitment.elements, batch_commitment.elements].concat();
        checkpoint_commitment = H::hash_or_noop(&f);
    }
    Ok(checkpoint_commitment)
}

pub fn hash_commitment_parallel(
    updates: &Vec<Batch>,
    batch_size: usize,
    prev_head: &Digest,
    max_threads: Option<usize>,
) -> Result<Digest, String> {
    // Parallelize batch commitment computation
    let batch_commitments = compute_batch_commitments_parallel(updates, batch_size, max_threads)?;

    // Commit to the batches in a hash chain style (sequential)
    let mut checkpoint_commitment = prev_head.clone();
    for batch_commitment in batch_commitments {
        let f = [checkpoint_commitment.elements, batch_commitment.elements].concat();
        checkpoint_commitment = H::hash_or_noop(&f);
    }
    Ok(checkpoint_commitment)
}

pub fn commit_batch(batch: &[StreamPoint]) -> Digest {
    let mut inputs = Vec::new();
    for stream_point in batch {
        inputs.extend(stream_point.encode().to_arr());
    }
    H::hash_or_noop(inputs.as_slice())
}

pub fn hash_commitment_t(
    update_targets: &Vec<Vec<StreamPointTarget>>,
    prev_head: &HashOutTarget,
    builder: &mut CircuitBuilder,
) -> HashOutTarget {
    let mut batch_commitments_t = Vec::new();
    for batch in update_targets {
        let batch_commitment = commit_batch_t(batch, builder);
        batch_commitments_t.push(batch_commitment);
    }

    let mut x = prev_head.clone();
    for c in batch_commitments_t {
        let f = [x.elements, c.elements].concat();
        x = builder.hash_or_noop::<H>(f);
    }
    x
}

pub fn commit_batch_t(
    batch: &Vec<StreamPointTarget>,
    builder: &mut CircuitBuilder,
) -> HashOutTarget {
    let mut inputs = Vec::new();
    for stream_point in batch {
        inputs.extend(stream_point.get_all_targets());
    }
    builder.hash_or_noop::<H>(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::generate_random_batches;

    #[test]
    fn test_hash_commitment_sequential_vs_parallel_small() {
        let updates = generate_random_batches(5, 10);
        let batch_size = 10;
        let prev_head = Digest::ZERO;

        let result_seq = hash_commitment(&updates, batch_size, &prev_head);
        let result_par = hash_commitment_parallel(&updates, batch_size, &prev_head, None);

        assert_eq!(result_seq, result_par, "Sequential and parallel results should be identical for small batches");
    }

    #[test]
    fn test_hash_commitment_sequential_vs_parallel_medium() {
        let updates = generate_random_batches(10, 50);
        let batch_size = 50;
        let prev_head = Digest::ZERO;

        let result_seq = hash_commitment(&updates, batch_size, &prev_head);
        let result_par = hash_commitment_parallel(&updates, batch_size, &prev_head, None);

        assert_eq!(result_seq, result_par, "Sequential and parallel results should be identical for medium batches");
    }

    #[test]
    fn test_hash_commitment_sequential_vs_parallel_large() {
        let updates = generate_random_batches(20, 100);
        let batch_size = 100;
        let prev_head = Digest::ZERO;

        let result_seq = hash_commitment(&updates, batch_size, &prev_head);
        let result_par = hash_commitment_parallel(&updates, batch_size, &prev_head, None);

        assert_eq!(result_seq, result_par, "Sequential and parallel results should be identical for large batches");
    }

    #[test]
    fn test_hash_commitment_with_padding() {
        let mut updates = generate_random_batches(3, 50);
        
        // Add a batch that's smaller than batch_size to test padding
        let mut small_batch = Vec::new();
        for i in 0..25 { // Smaller than batch_size
            let stream_id = {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                id
            };
            let digest = {
                let mut digest = [0u8; 32];
                digest[0] = (i * 2) as u8;
                digest
            };
            small_batch.push(StreamPoint::new(stream_id, digest));
        }
        updates.push(small_batch);
        
        let batch_size = 50;
        let prev_head = Digest::ZERO;

        let result_seq = hash_commitment(&updates, batch_size, &prev_head);
        let result_par = hash_commitment_parallel(&updates, batch_size, &prev_head, None);

        assert_eq!(result_seq, result_par, "Sequential and parallel results should be identical with padding");
    }

    #[test]
    fn test_hash_commitment_deterministic() {
        let updates = generate_random_batches(5, 10);
        let batch_size = 10;
        let prev_head = Digest::ZERO;

        // Test that both functions are deterministic
        let result1_seq = hash_commitment(&updates, batch_size, &prev_head);
        let result2_seq = hash_commitment(&updates, batch_size, &prev_head);
        assert_eq!(result1_seq, result2_seq, "Sequential function should be deterministic");

        let result1_par = hash_commitment_parallel(&updates, batch_size, &prev_head, None);
        let result2_par = hash_commitment_parallel(&updates, batch_size, &prev_head, None);
        assert_eq!(result1_par, result2_par, "Parallel function should be deterministic");
    }

    #[test]
    fn test_hash_commitment_empty_updates() {
        let updates: Vec<Batch> = Vec::new();
        let batch_size = 50;
        let prev_head = Digest::ZERO;

        let result_seq = hash_commitment(&updates, batch_size, &prev_head);
        let result_par = hash_commitment_parallel(&updates, batch_size, &prev_head, None);

        assert_eq!(result_seq, result_par, "Sequential and parallel results should be identical for empty updates");
        assert_eq!(result_seq, Ok(prev_head), "Empty updates should return the previous head");
    }

    #[test]
    fn test_hash_commitment_single_batch() {
        let updates = generate_random_batches(1, 25);
        let batch_size = 25;
        let prev_head = Digest::ZERO;

        let result_seq = hash_commitment(&updates, batch_size, &prev_head);
        let result_par = hash_commitment_parallel(&updates, batch_size, &prev_head, None);

        assert_eq!(result_seq, result_par, "Sequential and parallel results should be identical for single batch");
    }

    #[test]
    fn test_hash_commitment_different_prev_heads() {
        let updates = generate_random_batches(3, 20);
        let batch_size = 20;
        
        let prev_head1 = Digest::ZERO;
        let prev_head2 = {
            let mut digest = Digest::ZERO;
            digest.elements[0] = F::from_canonical_u64(12345);
            digest
        };

        let result1_seq = hash_commitment(&updates, batch_size, &prev_head1);
        let result1_par = hash_commitment_parallel(&updates, batch_size, &prev_head1, None);
        assert_eq!(result1_seq, result1_par, "Results should be identical for prev_head1");

        let result2_seq = hash_commitment(&updates, batch_size, &prev_head2);
        let result2_par = hash_commitment_parallel(&updates, batch_size, &prev_head2, None);
        assert_eq!(result2_seq, result2_par, "Results should be identical for prev_head2");

        // Results should be different for different prev_heads
        assert_ne!(result1_seq, result2_seq, "Results should be different for different prev_heads");
    }

    #[test]
    fn test_hash_commitment_batch_too_large() {
        let mut updates = generate_random_batches(2, 10);
        // Make one batch larger than the specified batch_size
        updates[0].push(StreamPoint::random());
        updates[0].push(StreamPoint::random());
        
        let batch_size = 10;
        let prev_head = Digest::ZERO;

        let result = hash_commitment(&updates, batch_size, &prev_head);
        assert!(result.is_err(), "Hash commitment should return an error for a batch that's too large");
    }

    #[test]
    fn test_hash_commitment_parallel_batch_too_large() {
        let mut updates = generate_random_batches(2, 10);
        // Make one batch larger than the specified batch_size
        updates[0].push(StreamPoint::random());
        updates[0].push(StreamPoint::random());
        
        let batch_size = 10;
        let prev_head = Digest::ZERO;

        let result = hash_commitment_parallel(&updates, batch_size, &prev_head, None);
        assert!(result.is_err(), "Hash commitment should return an error for a batch that's too large");
    }

    #[test]
    fn test_hash_commitment_thread_limited() {
        let updates = generate_random_batches(10, 50);
        let batch_size = 50;
        let prev_head = Digest::ZERO;

        // Test with different thread counts
        for thread_count in [1, 2, 4, 8] {
            let result_seq = hash_commitment(&updates, batch_size, &prev_head);
            let result_par = hash_commitment_parallel(&updates, batch_size, &prev_head, Some(thread_count));
            
            assert_eq!(
                result_seq, result_par, 
                "Thread-limited parallel result should match sequential for {} threads", thread_count
            );
        }
    }

    #[test]
    fn test_hash_commitment_thread_limited_vs_unlimited() {
        let updates = generate_random_batches(15, 75);
        let batch_size = 75;
        let prev_head = Digest::ZERO;

        let result_unlimited = hash_commitment_parallel(&updates, batch_size, &prev_head, None);
        let result_limited = hash_commitment_parallel(&updates, batch_size, &prev_head, Some(4));
        
        assert_eq!(
            result_unlimited, result_limited, 
            "Thread-limited and unlimited parallel results should be identical"
        );
    }
}
