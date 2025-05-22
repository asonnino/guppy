// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Merkle tree implementation adapted and simplified from Walrus.
use core::fmt::Debug;

use log::{info, trace, warn};
use thiserror::Error;

use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::config::Hasher;
use plonky2::{field::types::Field, hash::hash_types::HashOutTarget};

use minnow_lib::utils::{
    Digest, InnerHasher, MyCircuitBuilder as CircuitBuilder, MyPartialWitness as PartialWitness, F,
    H,
};
use minnow_lib::{EncodedStreamPoint, StreamPoint, StreamPointTarget, STREAM_POINT_LEN_F};

pub type MerkleLeaf = EncodedStreamPoint;
pub type LeafTarget = StreamPointTarget;

pub const LEAF_LEN_F: usize = STREAM_POINT_LEN_F;

#[derive(Clone, Debug)]
pub struct MerkleProofTargets {
    pub proof_t: MerkleProofTarget,
    pub root_t: HashOutTarget,
    pub leaf_t: LeafTarget,
    pub index_t: Target,
}

pub fn add_merkle_proof_verification_to_circuit(
    builder: &mut CircuitBuilder,
    num_levels: usize,
) -> MerkleProofTargets {
    let proof_len = num_levels - 1;
    let proof_t = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(proof_len),
    };
    let cap_t = builder.add_virtual_cap(0);
    let leaf_t = LeafTarget::new(builder);
    let index_t = builder.add_virtual_target();
    let i_bits = builder.split_le(index_t, num_levels);

    builder.verify_merkle_proof_to_cap::<InnerHasher>(
        leaf_t.get_all_targets(),
        &i_bits,
        &cap_t,
        &proof_t,
    );
    MerkleProofTargets {
        proof_t,
        root_t: cap_t.0[0],
        leaf_t,
        index_t,
    }
}

/// Returned if the specified index is out of bounds for a Merkle tree or proof.
#[derive(Error, Debug, PartialEq, Eq)]
#[error("index {0} is too large")]
pub struct LeafIndexOutOfBounds(usize);

/// A proof that some data is at index `leaf_index` in a [`MerkleTree`].
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct MerkleProof {
    /// The sibling hash values on the path from the leaf to the root.
    pub path: Vec<Digest>,
}

impl From<&[Digest]> for MerkleProof {
    fn from(path: &[Digest]) -> Self {
        Self { path: path.into() }
    }
}

impl From<Vec<Digest>> for MerkleProof {
    fn from(path: Vec<Digest>) -> Self {
        Self { path }
    }
}

impl MerkleProof {
    /// Compute the root hash of the Merkle tree from the provided leaf and the path to the leaf.
    pub fn compute_root(&self, leaf: &StreamPoint, leaf_index: usize) -> Option<Digest> {
        if leaf_index >> self.path.len() != 0 {
            return None;
        }
        self.compute_root_from_leaf_hash(leaf_hash(leaf), leaf_index)
    }

    /// Compute the root hash of the Merkle tree given the leaf hash and index.
    pub fn compute_root_from_leaf_hash(
        &self,
        leaf_hash: Digest,
        leaf_index: usize,
    ) -> Option<Digest> {
        let mut current_hash = leaf_hash;
        let mut level_index = leaf_index;
        // println!("path length: {}", self.path.len());
        for sibling in &self.path {
            // The sibling hash of the current node
            if level_index % 2 == 0 {
                // The current node is a left child
                current_hash = inner_hash(&current_hash, sibling);
            } else {
                // The current node is a right child
                current_hash = inner_hash(sibling, &current_hash);
            };
            // Update to the level index one level up in the tree
            level_index /= 2;
        }
        Some(current_hash)
    }

    /// Verify that the root hash of the Merkle tree matches the provided root hash given the leaf
    /// data and index.
    pub fn verify_proof(&self, root: &Digest, leaf: &StreamPoint, leaf_index: usize) -> bool {
        self.compute_root(leaf, leaf_index).as_ref() == Some(root)
    }

    /// Verify that the root hash of the Merkle tree matches the provided root hash given the leaf
    /// hash and index.
    pub fn verify_proof_from_leaf_hash(
        &self,
        root: &Digest,
        leaf_hash: Digest,
        leaf_index: usize,
    ) -> bool {
        self.compute_root_from_leaf_hash(leaf_hash, leaf_index)
            .as_ref()
            == Some(root)
    }

    pub fn set_proof_targets(
        &self,
        pw: &mut PartialWitness,
        targets: &MerkleProofTargets,
        root: &Digest,
        encoded_leaf_data: &MerkleLeaf,
        leaf_index: usize,
    ) {
        assert_eq!(self.path.len(), targets.proof_t.siblings.len());
        for i in 0..self.path.len() {
            pw.set_hash_target(targets.proof_t.siblings[i], self.path[i])
                .unwrap();
        }
        pw.set_hash_target(targets.root_t, *root).unwrap();
        pw.set_target(targets.index_t, F::from_canonical_usize(leaf_index))
            .unwrap();
        targets.leaf_t.set_proof_targets(pw, encoded_leaf_data);
    }
}

/// A fixed-size Merkle tree using the posiedon hash function from the [`plonky2`] crate.
/// Fixed-size: we pad with default elements to make it amenable to circuits.
/// Can hold at most `max_leaves` leaves.
/// The tree has `num_levels` levels.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    // The nodes of the Merkle tree are stored in a vector level by level starting with
    // the leaf hashes.
    // INV: `nodes` always stores at least the (potentially empty) leaf level.
    nodes: Vec<Vec<Digest>>,
    // Just the leaves of the Merkle tree stored in raw form.
    // A raw leaf is of type Vec<F> whereas a hashed one is of type Digest (stored in `nodes`)
    leaves: Vec<MerkleLeaf>,
    // Number of real leaves in the tree (0 <= real_leaves <= max_leaves)
    real_leaves: usize,
    // Total number of leaves in the tree
    max_leaves: usize,
    // Total number of levels in the tree
    num_levels: usize,
    // Proof length
    proof_len: usize,
}

impl MerkleTree {
    pub fn get_num_leaves(&self) -> usize {
        self.real_leaves
    }

    pub fn get_leaf(&self, index: usize) -> &MerkleLeaf {
        self.leaves.get(index).expect("index out of bounds")
    }

    pub fn build_from_stream_points(stream_points: &[StreamPoint], num_levels: usize) -> Self {
        let leaves: Vec<MerkleLeaf> = stream_points.iter().map(|leaf| leaf.encode()).collect();
        Self::build_from_leaves(&leaves, num_levels)
    }

    fn build_from_leaves(leaves: &[MerkleLeaf], num_levels: usize) -> Self {
        let max_leaves = 1 << (num_levels - 1);
        let real_leaves = leaves.len();
        if real_leaves > max_leaves {
            panic!(
                "number of leaves {} is greater than {}",
                real_leaves, max_leaves
            );
        }

        // Pad the leaves
        let mut leaves = leaves.to_vec();
        leaves.extend(vec![MerkleLeaf::default(); max_leaves - real_leaves]);

        info!(
            "building Merkle tree over {} items with {} levels",
            max_leaves, num_levels
        );

        // Create the capacity that we know will be needed, since the vec will be
        // reused by the call to from_leaf_nodes.
        let hashed_leaves: Vec<Digest> = leaves
            .iter()
            .map(|x| H::hash_or_noop(x.to_arr().as_slice()))
            .collect();
        let mut nodes = Vec::with_capacity(num_levels);
        nodes.push(hashed_leaves);

        // Fill all other nodes of the Merkle Tree from the bottom up.
        while nodes.last().expect("nodes should not be empty").len() > 1 {
            let prev_level_nodes = nodes.last().expect("nodes should not be empty");
            let n_level_nodes = prev_level_nodes.len();
            let n_next_level_nodes = n_level_nodes.div_ceil(2);
            let mut next_level_nodes = Vec::with_capacity(n_next_level_nodes);

            (0..n_level_nodes).step_by(2).for_each(|index| {
                next_level_nodes.push(inner_hash(
                    &prev_level_nodes[index],
                    &prev_level_nodes
                        .get(index + 1)
                        .expect("we should always have a right child"),
                ))
            });
            nodes.push(next_level_nodes);
        }

        Self {
            nodes,
            leaves: leaves.to_vec(),
            real_leaves,
            max_leaves,
            num_levels,
            proof_len: num_levels - 1,
        }
    }

    /// Verify that the root of `self` matches the provided root hash.
    pub fn verify_root(&self, root: &Digest) -> bool {
        self.root() == *root
    }

    /// Get a copy of the root hash of `self`.
    pub fn root(&self) -> Digest {
        self.nodes
            .last()
            .expect("tree should always have at least one level")
            .last()
            .expect("tree should always have at least one leaf")
            .clone()
    }

    /// Get the [`MerkleProof`] for the leaf at `leaf_index` consisting
    /// of all sibling hashes on the path from the leaf to the root.
    pub fn get_proof(&self, leaf_index: usize) -> Result<MerkleProof, LeafIndexOutOfBounds> {
        trace!(
            "get_proof: computing Merkle proof for leaf index {}",
            leaf_index
        );
        if leaf_index >= self.max_leaves {
            warn!("leaf index out of bounds");
            return Err(LeafIndexOutOfBounds(leaf_index));
        }
        let mut path = Vec::with_capacity(self.proof_len);
        let mut level_index = leaf_index;
        let mut level = 0;
        while level < self.num_levels - 1 {
            let sibling_index = if level_index % 2 == 0 {
                level_index + 1
            } else {
                level_index - 1
            };
            path.push(
                self.nodes[level]
                    .get(sibling_index)
                    .expect("we should always have a sibling")
                    .clone(),
            );
            // Index of the parent on the next level
            level_index /= 2;
            level += 1;
        }
        assert_eq!(path.len(), self.proof_len);
        Ok(MerkleProof { path })
    }

    /// Add a new leaf to the tree at the next available index.
    pub fn add_leaf(&mut self, leaf: &StreamPoint) -> usize {
        let idx = self.real_leaves;
        trace!("adding leaf {} at index {}", leaf.id, idx);
        self.update_leaf(idx, leaf)
            .expect("leaf index should be in bounds");
        self.real_leaves += 1;
        idx
    }

    /// Update the leaf at `leaf_index` to have the provided digest.
    /// Does not update the `leaves` vector.
    fn update_leaf_hash(
        &mut self,
        leaf_index: usize,
        leaf_hash: Digest,
    ) -> Result<(), LeafIndexOutOfBounds> {
        if leaf_index >= self.max_leaves {
            warn!("leaf index out of bounds");
            return Err(LeafIndexOutOfBounds(leaf_index));
        }
        // Update the leaf node.
        self.nodes[0][leaf_index] = leaf_hash;
        // Update all the inner nodes on the path to the root.
        let mut level = 1;
        let mut level_index = leaf_index / 2;
        while level < self.num_levels {
            let prev_level_nodes = &self.nodes[level - 1];
            let new_digest = inner_hash(
                &prev_level_nodes[level_index * 2],
                &prev_level_nodes
                    .get(level_index * 2 + 1)
                    .expect("we should always have a right child"),
            );
            if self.nodes[level].len() <= level_index {
                self.nodes[level].push(new_digest);
            } else {
                self.nodes[level][level_index] = new_digest;
            }
            level_index /= 2;
            level += 1;
        }
        Ok(())
    }

    /// Update the leaf at `leaf_index` to have the provided data.
    pub fn update_leaf(
        &mut self,
        leaf_index: usize,
        leaf: &StreamPoint,
    ) -> Result<(), LeafIndexOutOfBounds> {
        trace!("updating leaf {} at index {}", leaf.id, leaf_index);
        self.leaves[leaf_index] = leaf.encode();
        self.update_leaf_hash(
            leaf_index,
            H::hash_or_noop(&self.leaves[leaf_index].to_arr()),
        )
    }
}

pub(crate) fn leaf_hash(input: &StreamPoint) -> Digest {
    H::hash_or_noop(&input.encode().to_arr())
}

fn inner_hash(left: &Digest, right: &Digest) -> Digest {
    H::two_to_one(left.clone(), right.clone())
}

pub fn get_initial_root(num_levels: usize) -> Digest {
    let mut h = H::hash_or_noop(&MerkleLeaf::default().to_arr());
    let mut height_diff = num_levels - 1;
    while height_diff > 0 {
        h = inner_hash(&h, &h);
        height_diff -= 1;
    }
    h
}

#[cfg(test)]
mod test {
    use minnow_lib::STREAM_VAL_LEN;

    use super::*;

    const TEST_INPUT: [StreamPoint; 9] = [
        StreamPoint {
            id: 1,
            digest: [1; STREAM_VAL_LEN],
            new: false,
        },
        StreamPoint {
            id: 2,
            digest: [2; STREAM_VAL_LEN],
            new: false,
        },
        StreamPoint {
            id: 3,
            digest: [3; STREAM_VAL_LEN],
            new: false,
        },
        StreamPoint {
            id: 4,
            digest: [4; STREAM_VAL_LEN],
            new: false,
        },
        StreamPoint {
            id: 5,
            digest: [5; STREAM_VAL_LEN],
            new: false,
        },
        StreamPoint {
            id: 6,
            digest: [6; STREAM_VAL_LEN],
            new: false,
        },
        StreamPoint {
            id: 7,
            digest: [7; STREAM_VAL_LEN],
            new: false,
        },
        StreamPoint {
            id: 8,
            digest: [8; STREAM_VAL_LEN],
            new: false,
        },
        StreamPoint {
            id: 9,
            digest: [9; STREAM_VAL_LEN],
            new: false,
        },
    ];
    const NUM_LEVELS: usize = 5;
    const NUM_LEAVES: usize = 1 << (NUM_LEVELS - 1);

    fn n_levels_from_leaves(n_leaves: usize) -> usize {
        usize::try_from(n_leaves.next_power_of_two().ilog2())
            .expect("this is smaller than `n_leaves`")
            + 1
    }

    #[test]
    fn test_basics() {
        let num_levels = 3;
        let num_leaves = 1 << (num_levels - 1);
        println!("num_leaves: {}", num_leaves);
        println!("num_levels: {}", num_levels);
        println!(
            "n_levels_from_leaves(num_leaves): {}",
            n_levels_from_leaves(num_leaves)
        );
        assert_eq!(n_levels_from_leaves(num_leaves), num_levels);
    }

    #[test]
    fn test_leaf_hash() {
        let point = StreamPoint::new(1, [1; STREAM_VAL_LEN]);
        let l = leaf_hash(&point);
        println!("l: {:?}", l);
    }

    #[test]
    fn test_merkle_tree_empty() {
        let mt: MerkleTree = MerkleTree::build_from_stream_points(&[], NUM_LEVELS);
        assert_eq!(mt.root(), get_initial_root(NUM_LEVELS));
    }

    #[test]
    fn test_merkle_tree_single_element() {
        let test_inp = StreamPoint::new(1, [1; STREAM_VAL_LEN]);
        let mt: MerkleTree = MerkleTree::build_from_stream_points(&[test_inp], NUM_LEVELS);
        let mut h = leaf_hash(&test_inp);

        let mut height_diff = NUM_LEVELS - n_levels_from_leaves(1);
        let mut sibling = H::hash_or_noop(&MerkleLeaf::default().to_arr());
        assert_eq!(height_diff, NUM_LEVELS - 1);
        while height_diff > 0 {
            h = inner_hash(&h, &sibling);
            sibling = inner_hash(&sibling, &sibling);
            height_diff -= 1;
        }

        assert_eq!(mt.root(), h);
    }

    #[test]
    fn test_get_path_out_of_bounds() {
        let mt: MerkleTree = MerkleTree::build_from_stream_points(&TEST_INPUT, NUM_LEVELS);
        assert!(mt.get_proof(TEST_INPUT.len()).is_ok());
        assert!(mt.get_proof(TEST_INPUT.len() + 1).is_ok());
        assert!(mt.get_proof(NUM_LEAVES - 1).is_ok());
        assert!(mt.get_proof(NUM_LEAVES).is_err());

        let mt: MerkleTree = MerkleTree::build_from_stream_points(&[], NUM_LEVELS);
        assert!(mt.get_proof(0).is_ok());
    }

    #[test]
    fn test_merkle_path_verify() {
        for i in 0..TEST_INPUT.len() {
            let mt: MerkleTree = MerkleTree::build_from_stream_points(&TEST_INPUT[..i], NUM_LEVELS);
            for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
                let proof = mt.get_proof(index).unwrap();
                assert!(proof.verify_proof(&mt.root(), leaf_data, index));
            }
        }
    }

    #[test]
    fn test_update_and_verify_path() {
        for i in 0..TEST_INPUT.len() {
            let mut mt: MerkleTree =
                MerkleTree::build_from_stream_points(&TEST_INPUT[..i], NUM_LEVELS);
            for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
                let proof = mt.get_proof(index).unwrap();
                assert!(proof.verify_proof(&mt.root(), leaf_data, index));
                mt.update_leaf(
                    index,
                    &StreamPoint::new(index as u32, [index as u8; STREAM_VAL_LEN]),
                )
                .unwrap();
                assert!(proof.verify_proof(
                    &mt.root(),
                    &StreamPoint::new(index as u32, [index as u8; STREAM_VAL_LEN]),
                    index
                ));
            }
        }
    }

    #[test]
    fn test_merkle_path_verify_fails_for_wrong_index() {
        for i in 0..TEST_INPUT.len() {
            let mt: MerkleTree = MerkleTree::build_from_stream_points(&TEST_INPUT[..i], NUM_LEVELS);
            for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
                let proof = mt.get_proof(index).unwrap();
                assert!(!proof.verify_proof(&mt.root(), leaf_data, index + 1));
            }
        }
    }
}
