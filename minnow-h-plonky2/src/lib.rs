//! Minnow-H: the ZK service tracks a small, fixed set of streams and commits to
//! their states with a single hash over the list (no Merkle tree). Validators
//! commit to each checkpoint's updates with the same batched hash chain as the
//! main protocols (`minnow_lib::hash_commitment`).

use minnow_lib::{
    utils::{Digest, F, H},
    Batch, StreamID, StreamPoint, STREAM_VAL_LEN,
};
use plonky2::plonk::config::Hasher;

pub mod circuit;

/// Service state: the tracked streams, in a fixed order.
#[derive(Clone)]
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
        let encoded = self
            .stream_points
            .iter()
            .flat_map(|sp| sp.encode().to_arr())
            .collect::<Vec<F>>();
        H::hash_or_noop(&encoded)
    }

    pub fn len(&self) -> usize {
        self.stream_points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.stream_points.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, StreamPoint> {
        self.stream_points.iter()
    }

    /// Applies a checkpoint's updates in order: when a tracked stream is updated
    /// several times, the last update wins (as in the circuit).
    pub fn apply_checkpoint_updates(&mut self, batches: &[Batch]) {
        for point in self.stream_points.iter_mut() {
            for update in batches.iter().flatten() {
                if point.id == update.id {
                    point.digest = update.digest;
                }
            }
        }
    }
}

/// Tracked stream identifiers 1..=m (identifier 0 is the padding value).
pub fn tracked_stream_ids(m: usize) -> Vec<StreamID> {
    (1..=m)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            id
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::MinnowHCircuit;
    use minnow_lib::hash_commitment;
    use plonky2::field::types::Field;
    use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;

    /// Random updates, a few of which hit tracked streams (some twice).
    fn sample_checkpoint(
        num_batches: usize,
        batch_size: usize,
        tracked: &[StreamID],
        seed: u8,
    ) -> Vec<Batch> {
        let mut batches = minnow_lib::utils::generate_random_batches(num_batches, batch_size);
        for (k, id) in tracked.iter().enumerate() {
            let b = k % num_batches;
            let j = (3 * k) % batch_size;
            batches[b][j] = StreamPoint::new(*id, [seed.wrapping_add(k as u8); STREAM_VAL_LEN]);
        }
        // A second update to the first tracked stream, later in the checkpoint.
        let last = num_batches - 1;
        batches[last][batch_size - 1] = StreamPoint::new(tracked[0], [seed ^ 0xff; STREAM_VAL_LEN]);
        batches
    }

    #[test]
    fn proves_and_verifies_a_chain_of_checkpoints() {
        let (num_batches, batch_size, m) = (2, 10, 4);
        let tracked = tracked_stream_ids(m);
        let circuit = MinnowHCircuit::new(num_batches, batch_size, &tracked);
        let data = &circuit.circuit_data;

        let mut state = MinnowHServiceState::new(&tracked);
        let mut head = Digest::ZERO;
        let mut proof = circuit.base_proof();
        for c in 0..3u8 {
            let batches = sample_checkpoint(num_batches, batch_size, &tracked, 10 * c + 1);
            proof = circuit.prove(&batches, &state, &proof, c == 0);
            check_cyclic_proof_verifier_data(&proof, &data.verifier_only, &data.common).unwrap();
            data.verify(proof.clone()).unwrap();

            head = hash_commitment(&batches, batch_size, &head).unwrap();
            state.apply_checkpoint_updates(&batches);
            assert_eq!(proof.public_inputs[0..4], head.elements);
            assert_eq!(proof.public_inputs[4..8], state.commit().elements);
            assert_eq!(proof.public_inputs[8], F::from_canonical_u32(c as u32 + 1));
        }
        assert_eq!(state.stream_points[0].digest, [21 ^ 0xff; STREAM_VAL_LEN]);
    }

    #[test]
    #[should_panic]
    fn rejects_a_tampered_previous_state() {
        let (num_batches, batch_size, m) = (1, 10, 2);
        let tracked = tracked_stream_ids(m);
        let circuit = MinnowHCircuit::new(num_batches, batch_size, &tracked);
        let mut state = MinnowHServiceState::new(&tracked);
        let batches = sample_checkpoint(num_batches, batch_size, &tracked, 1);
        let proof = circuit.prove(&batches, &state, &circuit.base_proof(), true);
        state.apply_checkpoint_updates(&batches);
        state.stream_points[1].digest = [7; STREAM_VAL_LEN]; // not what the proof committed to
        let batches = sample_checkpoint(num_batches, batch_size, &tracked, 2);
        circuit.prove(&batches, &state, &proof, false);
    }
}
