// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Merkle tree implementation adapted and simplified from Walrus.
use core::fmt::Debug;

use rkyv::{Archive, Deserialize, Serialize};
use sha3::{Digest as HashFunction, Sha3_256};
use thiserror::Error;
use tracing::Level;

use crate::{Digest, DIGEST_LEN};

const LEAF_PREFIX: [u8; 1] = [0];
const INNER_PREFIX: [u8; 1] = [1];
const EMPTY_NODE: [u8; DIGEST_LEN] = [0; DIGEST_LEN];

/// Returned if the specified index is out of bounds for a Merkle tree or proof.
#[derive(Error, Debug, PartialEq, Eq)]
#[error("index {0} is too large")]
pub struct LeafIndexOutOfBounds(usize);

/// A proof that some data is at index `leaf_index` in a [`MerkleTree`].
#[derive(Archive, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct MerkleProof {
    /// The sibling hash values on the path from the leaf to the root.
    path: Vec<Digest>,
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
    pub fn compute_root(&self, leaf: &[u8], leaf_index: usize) -> Option<Digest> {
        if leaf_index >> self.path.len() != 0 {
            return None;
        }
        let mut current_hash = leaf_hash(leaf);
        let mut level_index = leaf_index;
        for sibling in self.path.iter() {
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

    /// Verify that the root hash of the Merkle tree matches the provided root hash.
    pub fn verify_proof(&self, root: &Digest, leaf: &[u8], leaf_index: usize) -> bool {
        self.compute_root(leaf, leaf_index).as_ref() == Some(root)
    }
}

/// Merkle tree using a hash function `T` (default: [`Blake2b256`]) from the [`fastcrypto`] crate.
///
/// The data of the leaves is prefixed with `0x00` before hashing and hashes of inner nodes are
/// computed over the concatenation of their children prefixed with `0x01`. Hashes of empty
/// subtrees (i.e. subtrees without data at their leaves) are replaced with all zeros.
#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
pub struct MerkleTree {
    // The nodes of the Merkle tree are stored in a vector level by level starting with
    // the leaf hashes.
    // TODO: Store the nodes separately for each level to enable adding new leaves.
    nodes: Vec<Digest>,
    n_leaves: usize,
}

impl MerkleTree {
    /// Create the [`MerkleTree`] as a commitment to the provided data.
    pub fn build<I>(iter: I) -> Self
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
        I::Item: AsRef<[u8]>,
    {
        Self::build_from_leaf_hashes(iter.into_iter().map(|leaf| leaf_hash(leaf.as_ref())))
    }

    /// Create the [`MerkleTree`] as a commitment to the provided data hashes.
    pub fn build_from_leaf_hashes<I>(iter: I) -> Self
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator<Item = Digest>,
    {
        let iter = iter.into_iter();
        tracing::trace!("building Merkle tree over {} items", iter.len());

        // Create the capacity that we know will be needed, since the vec will be
        // reused by the call to from_leaf_nodes.
        let mut nodes = Vec::with_capacity(n_nodes(iter.len()));
        nodes.extend(iter);

        let n_leaves = nodes.len();
        let mut level_nodes = n_leaves;
        let mut prev_level_index = 0;

        // Fill all other nodes of the Merkle Tree
        while level_nodes > 1 {
            if level_nodes % 2 == 1 {
                // We need an empty sibling for the last node on the previous level
                nodes.push(EMPTY_NODE);
                level_nodes += 1;
            }

            let new_level_index = prev_level_index + level_nodes;

            (prev_level_index..new_level_index)
                .step_by(2)
                .for_each(|index| nodes.push(inner_hash(&nodes[index], &nodes[index + 1])));

            prev_level_index = new_level_index;
            level_nodes /= 2;
        }

        Self { nodes, n_leaves }
    }

    /// Verify that the root of `self` matches the provided root hash.
    pub fn verify_root(&self, root: &Digest) -> bool {
        self.root().as_ref() == root
    }

    /// Get a copy of the root hash of `self`.
    pub fn root(&self) -> Digest {
        self.nodes.last().map_or(EMPTY_NODE, |val| val.clone())
    }

    /// Get the [`MerkleProof`] for the leaf at `leaf_index` consisting
    /// of all sibling hashes on the path from the leaf to the root.
    #[tracing::instrument(level = Level::WARN, fields(n_leaves = self.n_leaves))]
    pub fn get_proof(&self, leaf_index: usize) -> Result<MerkleProof, LeafIndexOutOfBounds> {
        tracing::trace!("computing Merkle proof");
        if leaf_index >= self.n_leaves {
            tracing::warn!("leaf index out of bounds");
            return Err(LeafIndexOutOfBounds(leaf_index));
        }
        let mut path = Vec::with_capacity(
            usize::try_from(self.n_leaves.ilog2()).expect("this is smaller than `n_leaves`") + 1,
        );
        let mut level_index = leaf_index;
        let mut n_level = self.n_leaves;
        let mut level_base_index = 0;
        while n_level > 1 {
            // All levels contain an even number of nodes
            n_level = n_level.next_multiple_of(2);
            let sibling_index = if level_index % 2 == 0 {
                level_base_index + level_index + 1
            } else {
                level_base_index + level_index - 1
            };
            path.push(self.nodes[sibling_index].clone());
            // Index of the parent on the next level
            level_index /= 2;
            level_base_index += n_level;
            n_level /= 2;
        }
        Ok(MerkleProof { path })
    }

    // TODO: implement function to add new leaves

    // TODO: implement function to update leaf
}

/// Computes the hash of the provided input to be used as a leaf hash of a Merkle tree.
pub(crate) fn leaf_hash(input: &[u8]) -> Digest {
    let mut hasher = Sha3_256::new();
    hasher.update(LEAF_PREFIX);
    hasher.update(input);
    hasher.finalize().into()
}

fn inner_hash(left: &Digest, right: &Digest) -> Digest {
    let mut hasher = Sha3_256::new();
    hasher.update(INNER_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn n_nodes(n_leaves: usize) -> usize {
    let mut lvl_nodes = n_leaves;
    let mut tot_nodes = 0;
    while lvl_nodes > 1 {
        lvl_nodes += lvl_nodes % 2;
        tot_nodes += lvl_nodes;
        lvl_nodes /= 2;
    }
    tot_nodes + lvl_nodes
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_INPUT: [&[u8]; 9] = [
        b"foo", b"bar", b"fizz", b"baz", b"buzz", b"fizz", b"foobar", b"walrus", b"fizz",
    ];

    #[test]
    fn test_n_nodes() {
        assert!(n_nodes(0) == 0);
        assert!(n_nodes(1) == 1);
        assert!(n_nodes(2) == 3);
        assert!(n_nodes(3) == 7);
        assert!(n_nodes(4) == 7);
        assert!(n_nodes(5) == 13);
        assert!(n_nodes(6) == 13);
        assert!(n_nodes(7) == 15);
        assert!(n_nodes(8) == 15);
        assert!(n_nodes(9) == 23);
    }

    #[test]
    fn test_merkle_tree_empty() {
        let mt: MerkleTree = MerkleTree::build::<[&[u8]; 0]>([]);
        assert_eq!(mt.root(), EMPTY_NODE);
    }

    #[test]
    fn test_merkle_tree_single_element() {
        let test_inp = "Test";
        let mt: MerkleTree = MerkleTree::build(&[test_inp.as_bytes()]);
        let mut hasher = Sha3_256::new();
        hasher.update(LEAF_PREFIX);
        hasher.update(test_inp.as_bytes());
        assert_eq!(mt.root(), Digest::from(hasher.finalize()));
    }

    #[test]
    fn test_merkle_tree_empty_element() {
        let mt: MerkleTree = MerkleTree::build(&[&[]]);
        let mut hasher = Sha3_256::new();
        hasher.update(LEAF_PREFIX);
        hasher.update([]);
        assert_eq!(mt.root(), Digest::from(hasher.finalize()));
    }

    #[test]
    fn test_get_path_out_of_bounds() {
        let test_inp: Vec<_> = [
            "foo", "bar", "fizz", "baz", "buzz", "fizz", "foobar", "walrus", "fizz",
        ]
        .iter()
        .map(|x| x.as_bytes())
        .collect();
        for i in 0..test_inp.len() {
            let mt: MerkleTree = MerkleTree::build(&test_inp[..i]);
            match mt.get_proof(i.next_power_of_two()) {
                Err(_) => {}
                Ok(_) => panic!("Expected an error"),
            }
        }
    }

    #[test]
    fn test_merkle_path_verify() {
        for i in 0..TEST_INPUT.len() {
            let mt: MerkleTree = MerkleTree::build(&TEST_INPUT[..i]);
            for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
                let proof = mt.get_proof(index).unwrap();
                assert!(proof.verify_proof(&mt.root(), leaf_data, index));
            }
        }
    }

    #[test]
    fn test_merkle_path_verify_fails_for_wrong_index() {
        for i in 0..TEST_INPUT.len() {
            let mt: MerkleTree = MerkleTree::build(&TEST_INPUT[..i]);
            for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
                let proof = mt.get_proof(index).unwrap();
                assert!(!proof.verify_proof(&mt.root(), leaf_data, index + 1));
            }
        }
    }
}
