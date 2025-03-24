use crate::merkle::{get_initial_root, n_levels_from_leaves, MerkleTree};
use crate::{CheckpointUpdates, Digest, StreamPoint, StreamPointTarget, StreamPointVecTarget, STREAM_VAL_LEN_F};

use crate::utils::{is_equal_vec, MyCircuitBuilder, MyPartialWitness, H};

use criterion::criterion_main;
use log::info;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::plonk::config::Hasher;

// For now, this file is likely better placed in Minnow-H.
// TODO: Figure out how to leave the core checkpoint building parts here and move the rest to Minnow-H.

pub trait CommitmentStrategy {
    type CheckpointUpdatesTargets;
    type ValidatorState;

    // Initialize the targets to store relevant information about the checkpoint updates
    fn init_targets(
        builder: &mut MyCircuitBuilder,
        num_checkpoint_updates: usize,
    ) -> Self::CheckpointUpdatesTargets {
        todo!()
    }

    fn init_validator_state(checkpoint_updates: &CheckpointUpdates) -> Self::ValidatorState {
        todo!()
    }

    fn commit_t( 
        builder: &mut MyCircuitBuilder, 
        update_targets: &Self::CheckpointUpdatesTargets
    ) -> HashOutTarget {
        todo!()
    }

    fn update_state(
        builder: &mut MyCircuitBuilder,
        in_state_targets: &StreamPointVecTarget,
        update_targets: &Self::CheckpointUpdatesTargets
    ) -> StreamPointVecTarget {
        todo!()
    }

    fn assign_targets( 
        update_targets: &Self::CheckpointUpdatesTargets,
        validator_state: &Self::ValidatorState,
        pw: &mut MyPartialWitness
    ) {
        todo!()
    }

    // (i) Split the updates into batches of fixed size
    // (ii) Commit to each batch using either a Merkle tree or a hash function
    // (iii) Fold the batch commitments in a hash chain
    fn commit(updates: &CheckpointUpdates, prev_head: &Digest, batch_size: usize) -> Digest {
        let mut batch_commitments = Vec::new();
        for batch in updates.elements.chunks(batch_size) {
            if batch.len() < batch_size {
                let mut padded_batch = batch.to_vec();
                while padded_batch.len() < batch_size {
                    padded_batch.push(StreamPoint::default());
                }
                batch_commitments.push(Self::commit_batch(&padded_batch, batch.len()));
            } else {
                batch_commitments.push(Self::commit_batch(batch, batch.len()));
            }
        }

        // Commit to the batches in a hash chain style
        let mut checkpoint_commitment = prev_head.clone();
        for batch_commitment in batch_commitments {
            let f = [checkpoint_commitment.elements, batch_commitment.elements].concat();
            checkpoint_commitment = H::hash_or_noop(&f);
        }
        checkpoint_commitment
    }

    // Commit to a fixed size batch of updates of size updates.len()
    // num_actual_updates is the number of actual updates in the batch (rest are padding)
    fn commit_batch(update_batch: &[StreamPoint], num_actual_updates: usize) -> Digest;
}

pub struct MerkleCommitment;
pub struct HashCommitment;

// Just for benchmarking purposes
pub struct StandardHashCommitment;

impl CommitmentStrategy for MerkleCommitment {
    type CheckpointUpdatesTargets = StreamPointVecTarget;
    type ValidatorState = MerkleTree;

    fn init_targets(builder: &mut MyCircuitBuilder, num_checkpoint_updates: usize) -> Self::CheckpointUpdatesTargets {
        todo!()
    }

    fn commit_t(
        builder: &mut MyCircuitBuilder, 
        checkpoint_update_t: &Self::CheckpointUpdatesTargets
    ) -> HashOutTarget {
        todo!()
    }

    fn update_state(
        builder: &mut MyCircuitBuilder,
        in_state_targets: &StreamPointVecTarget,
        update_targets: &Self::CheckpointUpdatesTargets
    ) -> StreamPointVecTarget {
        todo!()
    }

    fn commit_batch(update_batch: &[StreamPoint], num_actual_updates: usize) -> Digest {
        Self::fast_commit_batch(update_batch, num_actual_updates)
    }
}

impl MerkleCommitment {
    // Only used for testing
    fn naive_commit_batch(update_batch: &[StreamPoint]) -> Digest {
        let num_updates = update_batch.len();
        let num_levels = n_levels_from_leaves(num_updates);

        // If num_updates is not a power of 2, raise an INFO log.
        // Why is this so? We may as well set it to a power of 2 to fill the tree.
        if num_updates != (1 << (num_levels - 1)) {
            info!(
                "number of elements in a batch is not a power of 2: {}",
                num_updates
            );
        }

        let tree = MerkleTree::build_from_stream_points(update_batch, num_levels);
        assert!(tree.get_num_leaves() == num_updates);
        tree.root()
    }

    // updates[..num_actual_updates] are the actual updates
    // updates[num_actual_updates..] are the padded updates
    fn fast_commit_batch(update_batch: &[StreamPoint], num_actual_updates: usize) -> Digest {
        let num_levels = n_levels_from_leaves(num_actual_updates);
        let tree =
            MerkleTree::build_from_stream_points(&update_batch[..num_actual_updates], num_levels);
        let root = tree.root();

        // TODO: Replace with static values
        let mut c = root;
        let mut num_total_levels = n_levels_from_leaves(update_batch.len());
        let mut sibling_root = get_initial_root(num_levels);
        while num_total_levels > num_levels {
            c = H::two_to_one(c, sibling_root.clone());
            sibling_root = H::two_to_one(sibling_root.clone(), sibling_root.clone());
            num_total_levels -= 1;
        }
        c
    }
}

impl CommitmentStrategy for HashCommitment {
    type CheckpointUpdatesTargets = StreamPointVecTarget;
    type ValidatorState = CheckpointUpdates;

    fn init_targets(builder: &mut MyCircuitBuilder, num_checkpoint_updates: usize) -> Self::CheckpointUpdatesTargets {
        StreamPointVecTarget::new(builder, num_checkpoint_updates)
    }

    fn init_validator_state(checkpoint_updates: &CheckpointUpdates) -> Self::ValidatorState {
        checkpoint_updates.clone()
    }

    fn commit_t(
        builder: &mut MyCircuitBuilder, 
        checkpoint_update_t: &Self::CheckpointUpdatesTargets
    ) -> HashOutTarget {
        // TODO: Need to batch
        builder.hash_or_noop::<H>(checkpoint_update_t.get_all_targets())
    }

    fn update_state(
        builder: &mut MyCircuitBuilder,
        in_state_t: &StreamPointVecTarget,
        checkpoint_update_t: &Self::CheckpointUpdatesTargets
    ) -> StreamPointVecTarget {
        let mut out_state_t = StreamPointVecTarget::new(builder, 0);
        for x in &in_state_t.targets {
            let stream_id_t = &x.stream_id_t;
            let mut cur_val_t = x.stream_val_t.clone();

            for y in &checkpoint_update_t.targets {
                let update_id_t = &y.stream_id_t;
                let new_val_t = &y.stream_val_t;

                let b = is_equal_vec(builder, &stream_id_t, &update_id_t);
                for i in 0..STREAM_VAL_LEN_F {
                    cur_val_t[i] = builder.select(b, new_val_t[i], cur_val_t[i]);
                }
            }
            out_state_t.targets.push(StreamPointTarget::from_existing(
                stream_id_t.clone(),
                cur_val_t.to_vec(),
                builder._false(),
            ));
        }
        out_state_t
    }

    fn assign_targets( 
        update_targets: &Self::CheckpointUpdatesTargets,
        validator_state: &Self::ValidatorState,
        pw: &mut MyPartialWitness
    ) {
        let checkpoint_updates = &validator_state.elements;
        assert_eq!(
            checkpoint_updates.len(),
            update_targets.len()
        );
        for (update, target) in checkpoint_updates
            .iter()
            .zip(update_targets.iter())
        {
            target.set_proof_targets(pw, &update.encode());
        }
    }

    fn commit_batch(updates: &[StreamPoint], _num_actual_updates: usize) -> Digest {
        let mut inputs = Vec::new();
        for stream_point in updates {
            inputs.extend(stream_point.encode().to_arr());
        }
        H::hash_or_noop(inputs.as_slice())
    }
}

impl CommitmentStrategy for StandardHashCommitment {
    type CheckpointUpdatesTargets = StreamPointVecTarget;
    type ValidatorState = StreamPointVecTarget;

    fn commit_batch(updates: &[StreamPoint], _num_actual_updates: usize) -> Digest {
        use sha3::{Digest as Sha3Digest, Sha3_256};
        
        let mut hasher = Sha3_256::new();
        for stream_point in updates {
            hasher.update(stream_point.to_bytes().as_slice());
        }
        let result = hasher.finalize();
        
        Digest::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_commitment() {
        let updates = vec![StreamPoint::default(); 100];
        let commitment = HashCommitment::commit_batch(&updates, 100);
        println!("commitment: {:?}", commitment);

        let batch_size = 10;
        let commitment = HashCommitment::commit(
            &CheckpointUpdates::from_iter(updates.into_iter()),
            &Digest::ZERO,
            batch_size,
        );
        println!("commitment: {:?}", commitment);
    }

    #[test]
    fn test_merkle_commitment() {
        let updates_1 = vec![StreamPoint::random(); 64];
        let commitment_batch_1 = MerkleCommitment::commit_batch(&updates_1, 64);

        let updates_2 = vec![StreamPoint::random(); 64];
        let commitment_batch_2 = MerkleCommitment::commit_batch(&updates_2, 64);

        // Build it with a power of 2
        let updates = [updates_1, updates_2].concat();
        let commitment = MerkleCommitment::commit(
            &CheckpointUpdates::from_iter(updates.into_iter()),
            &Digest::ZERO,
            64,
        );

        let mut c = Digest::ZERO;
        c = H::hash_or_noop(&[c.elements, commitment_batch_1.elements].concat());
        c = H::hash_or_noop(&[c.elements, commitment_batch_2.elements].concat());
        assert_eq!(c.elements, commitment.elements);
    }

    #[test]
    fn test_merkle_commitment_fast() {
        let num_levels = 11;
        let num_updates = 1 << (num_levels - 1);

        let real_updates = vec![StreamPoint::random(); 64];
        let default_updates = vec![StreamPoint::default(); num_updates - 64];
        let updates = [real_updates, default_updates].concat();

        let commitment_batch_1 = MerkleCommitment.fast_commit_batch(&updates, 64);
        let commitment_batch_2 = MerkleCommitment.commit_batch(&updates, 64);

        assert_eq!(commitment_batch_1.elements, commitment_batch_2.elements);
    }
}
