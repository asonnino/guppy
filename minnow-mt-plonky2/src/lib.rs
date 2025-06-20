pub mod merkle;
use log::trace;
use merkle::add_merkle_proof_verification_to_circuit;
use merkle::{MerkleProof, MerkleProofTargets, MerkleTree};

pub mod one_step_circuit;
#[cfg(test)]
pub mod test_utils;
pub mod three_step_circuit;
pub mod two_step_circuit;

use minnow_lib::utils::{
    are_two_vectors_equal, Digest, MyCircuitBuilder, MyPartialWitness as PartialWitness,
};

use std::collections::HashMap;

use minnow_lib::{hash_commitment_t, StreamID, StreamPoint};

use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::with_context;

pub const DEFAULT_BATCH_SIZE: usize = 50;

#[derive(Debug)]
pub struct MinnowMTServiceState {
    pub merkle_tree: MerkleTree,
    // used to quickly find the index of a stream point
    stream_id_to_idx: HashMap<StreamID, usize>,

    // The current hash chain head until which we've processed the updates
    pub cur_head: Digest,
}

impl MinnowMTServiceState {
    pub fn new(stream_points: &[StreamPoint], max_log_state_size: usize) -> Self {
        let mut stream_id_to_idx = HashMap::new();
        for (i, stream_point) in stream_points.iter().enumerate() {
            stream_id_to_idx.insert(stream_point.id, i);
        }
        let num_levels = max_log_state_size + 1;
        let merkle_tree = MerkleTree::build_from_stream_points(stream_points, num_levels);
        Self {
            merkle_tree,
            stream_id_to_idx,
            cur_head: Digest::ZERO,
        }
    }

    pub fn get_num_leaves(&self) -> usize {
        self.merkle_tree.get_num_leaves()
    }

    pub fn get_root(&self) -> Digest {
        self.merkle_tree.root()
    }

    pub fn get_proof(&self, index: usize) -> MerkleProof {
        self.merkle_tree.get_proof(index).unwrap()
    }

    pub fn get_idx(&self, stream_id: &StreamID) -> Option<usize> {
        self.stream_id_to_idx.get(stream_id).cloned()
    }

    pub fn get_head(&self) -> Digest {
        self.cur_head
    }

    pub fn update_head(&mut self, new_head: &Digest) {
        self.cur_head = new_head.clone();
    }

    pub fn update_leaf(&mut self, point: &StreamPoint) {
        let idx = self.get_idx(&point.id);
        if idx.is_none() {
            assert!(point.new, "point is new but point.new is false");
            // If the stream point is not in the tree, add it
            let idx = self.merkle_tree.add_leaf(point);
            self.stream_id_to_idx.insert(point.id, idx);
        } else {
            assert!(!point.new, "point is old but point.new is true");
            // If the stream point is already in the tree, update it
            let idx = idx.unwrap();
            self.merkle_tree.update_leaf(idx, &point).unwrap();
        }
    }

    // Add Merkle proof verification to the circuit for a given stream ID.
    // If the stream ID is absent, we use the next available index under the expectation that update_leaf() will be called after this.
    pub fn add_proof_targets(
        &self,
        pw: &mut PartialWitness,
        targets: &MerkleProofTargets,
        stream_id: &StreamID,
    ) {
        let mut index = self.get_idx(stream_id);
        if index.is_none() {
            trace!("add_proof_targets: adding to end");
            index = Some(self.merkle_tree.get_num_leaves());
        }
        let index = index.unwrap();
        trace!("add_proof_targets: adding verification for stream");

        let proof = self.get_proof(index);
        let root = self.merkle_tree.root();
        let leaf = self.merkle_tree.get_leaf(index);
        proof.set_proof_targets(pw, targets, &root, &leaf, index);
    }
}

// Common circuit state for all Minnow-MT circuits
pub struct CircuitState {
    pub root_t: HashOutTarget,
    pub num_leaves_t: Target,
    pub checkpoint_head_t: HashOutTarget,
}

impl CircuitState {
    pub fn new(builder: &mut MyCircuitBuilder) -> Self {
        CircuitState {
            root_t: builder.add_virtual_hash(),
            num_leaves_t: builder.add_virtual_target(),
            checkpoint_head_t: builder.add_virtual_hash(),
        }
    }
}

pub fn process_many_batches(
    builder: &mut MyCircuitBuilder,
    num_batches: usize,
    batch_size: usize,
    num_levels: usize,
    in_state_t: &CircuitState,
) -> (
    Vec<MerkleProofTargets>,
    Vec<MerkleProofTargets>,
    CircuitState,
) {
    let mut prev_targets = vec![];
    let mut new_targets = vec![];
    let mut all_commitment_inputs = vec![];

    let one = builder.one();

    let mut cur_root_t = in_state_t.root_t;
    let mut cur_num_leaves_t = in_state_t.num_leaves_t;
    let cur_checkpoint_head_t = in_state_t.checkpoint_head_t;

    with_context!(builder, "process checkpoint updates", {
        for _ in 0..num_batches {
            let mut batch_commitment_inputs = vec![];
            for _ in 0..batch_size {
                let t_cur: MerkleProofTargets;
                let t_new: MerkleProofTargets;
                // i) Check inclusion proof
                t_cur = add_merkle_proof_verification_to_circuit(builder, num_levels);
                builder.connect_hashes(t_cur.root_t, cur_root_t);
                prev_targets.push(t_cur.clone());

                // ii) Check inclusion proof after update
                t_new = add_merkle_proof_verification_to_circuit(builder, num_levels);
                new_targets.push(t_new.clone());

                // iii) Connect the siblings
                assert_eq!(t_cur.proof_t.siblings.len(), t_new.proof_t.siblings.len());
                for i in 0..t_cur.proof_t.siblings.len() {
                    builder.connect_hashes(t_cur.proof_t.siblings[i], t_new.proof_t.siblings[i]);
                }

                // (iv) Logic: If old leaf, check that stream IDs match. If new leaf, check that index is incremented.
                // if t_new.leaf_t.new_flag_t
                //  then assert (t_new.index_t == num_leaves) && (num_leaves += 1)
                // else assert (t_new.index_t == t_cur.index_t) && (t_new.leaf_t.stream_id_t == t_cur.leaf_t.stream_id_t)
                let b1 = builder.is_equal(t_new.index_t, cur_num_leaves_t);
                let b2 = are_two_vectors_equal(
                    &t_new.leaf_t.stream_id_t,
                    &t_cur.leaf_t.stream_id_t,
                    builder,
                );
                let b3 = builder.is_equal(t_new.index_t, t_cur.index_t);
                let new_flag = t_new.leaf_t.new_flag_t;

                // if new_flag then b1 = true
                let b5 = builder.select(new_flag, b1.target, one);
                builder.assert_one(b5);

                let next_index = builder.add(cur_num_leaves_t, one);
                cur_num_leaves_t = builder.select(new_flag, next_index, cur_num_leaves_t);

                // if not new_flag then b2 = true
                let b6 = builder.select(new_flag, one, b2.target);
                builder.assert_one(b6);

                // if not new_flag then b3 = true
                let b7 = builder.select(new_flag, one, b3.target);
                builder.assert_one(b7);

                // v) MerkleLeaf === StreamPoint, so we can use the same targets to compute the checkpoint commitment
                batch_commitment_inputs.push(t_new.leaf_t);

                // vi) Update the current root
                cur_root_t = t_new.root_t;
            }
            all_commitment_inputs.push(batch_commitment_inputs);
        }
    });

    let out_checkpoint_com_t: HashOutTarget;
    with_context!(builder, "hash checkpoint commitment", {
        out_checkpoint_com_t =
            hash_commitment_t(&all_commitment_inputs, &cur_checkpoint_head_t, builder);
    });

    (
        prev_targets,
        new_targets,
        CircuitState {
            root_t: cur_root_t,
            num_leaves_t: cur_num_leaves_t,
            checkpoint_head_t: out_checkpoint_com_t,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use minnow_lib::hash_commitment;
    use minnow_lib::{STREAM_ID_LEN, STREAM_VAL_LEN};

    #[test]
    fn test_commit_single_update() {
        let d_prev = Digest::ZERO;
        let batch_size = 2;
        let l = vec![
            vec![
                StreamPoint::new([1; STREAM_ID_LEN], [0; STREAM_VAL_LEN]),
                StreamPoint::new([2; STREAM_ID_LEN], [0; STREAM_VAL_LEN]),
            ],
            vec![
                StreamPoint::new([3; STREAM_ID_LEN], [0; STREAM_VAL_LEN]),
                StreamPoint::new([4; STREAM_ID_LEN], [0; STREAM_VAL_LEN]),
            ],
        ];
        let d = hash_commitment(&l, batch_size, &d_prev);
        println!("{:?}", d);
    }
}
