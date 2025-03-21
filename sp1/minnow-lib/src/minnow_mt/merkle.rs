// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Merkle tree implementation adapted and simplified from Walrus.
use core::fmt::Debug;

use rkyv::{Archive, Deserialize, Serialize};
use sha3::{Digest as HashFunction, Sha3_256};
use thiserror::Error;

use crate::{Digest, DIGEST_LEN};

const INNER_PREFIX: [u8; 1] = [1];
const EMPTY_NODE: [u8; DIGEST_LEN] = [0; DIGEST_LEN];

#[macro_export]
macro_rules! leaf_hash {
    ( $( $x:expr ),* ) => {
        {
            use sha3::Digest as _;
            const LEAF_PREFIX: [u8; 1] = [0];
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(LEAF_PREFIX);
            $(
                hasher.update($x);
            )*
            hasher.finalize().into()
        }
    };
}

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

    /// Verify that the root hash of the Merkle tree matches the provided root hash given the leaf
    /// data and index.
    pub fn verify_proof(&self, root: &Digest, leaf: &[u8], leaf_index: usize) -> bool {
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
    // INV: `nodes` always stores at least the (potentially empty) leaf level.
    nodes: Vec<Vec<Digest>>,
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
        let leaf_nodes: Vec<Digest> = iter.into_iter().collect();
        let n_leaves = leaf_nodes.len();
        tracing::trace!("building Merkle tree over {} items", n_leaves);

        // Create the capacity that we know will be needed, since the vec will be
        // reused by the call to from_leaf_nodes.
        let mut nodes = Vec::with_capacity(n_levels_from_leaves(n_leaves));
        nodes.push(leaf_nodes);

        // Fill all other nodes of the Merkle Tree from the bottom up.
        while nodes.last().expect("nodes should not be empty").len() > 1 {
            let prev_level_nodes = nodes.last().expect("nodes should not be empty");
            let n_level_nodes = prev_level_nodes.len();
            let n_next_level_nodes = n_level_nodes.div_ceil(2);
            let mut next_level_nodes = Vec::with_capacity(n_next_level_nodes);

            (0..n_level_nodes).step_by(2).for_each(|index| {
                next_level_nodes.push(inner_hash(
                    &prev_level_nodes[index],
                    &prev_level_nodes.get(index + 1).unwrap_or(&EMPTY_NODE),
                ))
            });
            nodes.push(next_level_nodes);
        }

        Self { nodes, n_leaves }
    }

    /// Verify that the root of `self` matches the provided root hash.
    pub fn verify_root(&self, root: &Digest) -> bool {
        self.root().as_ref() == root
    }

    /// Get a copy of the root hash of `self`.
    pub fn root(&self) -> &Digest {
        self.nodes
            .last()
            .expect("tree should always have at least one level")
            .last()
            .unwrap_or(&EMPTY_NODE)
    }

    /// Get the [`MerkleProof`] for the leaf at `leaf_index` consisting
    /// of all sibling hashes on the path from the leaf to the root.
    pub fn get_proof(&self, leaf_index: usize) -> Result<MerkleProof, LeafIndexOutOfBounds> {
        tracing::trace!("computing Merkle proof");
        if leaf_index >= self.n_leaves {
            tracing::warn!("leaf index out of bounds");
            return Err(LeafIndexOutOfBounds(leaf_index));
        }
        let n_levels = n_levels_from_leaves(self.n_leaves);
        let mut path = Vec::with_capacity(n_levels);
        let mut level_index = leaf_index;
        let mut level = 0;
        while level < n_levels - 1 {
            let sibling_index = if level_index % 2 == 0 {
                level_index + 1
            } else {
                level_index - 1
            };
            path.push(
                self.nodes[level]
                    .get(sibling_index)
                    .unwrap_or(&EMPTY_NODE)
                    .clone(),
            );
            // Index of the parent on the next level
            level_index /= 2;
            level += 1;
        }
        Ok(MerkleProof { path })
    }

    /// Add a new leaf hash to the tree at the next available index.
    pub fn add_leaf_hash(&mut self, leaf_hash: Digest) {
        self.n_leaves += 1;
        // Add a new leaf hash to the bottom level. The value doesn't matter as it will be
        // overwritten by the call to `update_leaf_hash`. But we need to ensure that the
        // element exists in the vector of the bottom level.
        self.nodes[0].push(leaf_hash);
        self.update_leaf_hash(self.n_leaves - 1, leaf_hash)
            .expect("leaf index should be in bounds");
    }

    /// Add a new leaf to the tree at the next available index.
    pub fn add_leaf(&mut self, leaf: &[u8]) {
        self.add_leaf_hash(leaf_hash(leaf));
    }

    /// Update the leaf at `leaf_index` to have the provided digest.
    pub fn update_leaf_hash(
        &mut self,
        leaf_index: usize,
        leaf_hash: Digest,
    ) -> Result<(), LeafIndexOutOfBounds> {
        if leaf_index >= self.n_leaves {
            tracing::warn!("leaf index out of bounds");
            return Err(LeafIndexOutOfBounds(leaf_index));
        }
        let n_levels = n_levels_from_leaves(self.n_leaves);
        if self.nodes.len() < n_levels {
            self.nodes.push(Vec::new());
        }
        // Update the leaf node.
        self.nodes[0][leaf_index] = leaf_hash;
        // Update all the inner nodes on the path to the root.
        let mut level = 1;
        let mut level_index = leaf_index / 2;
        while level < n_levels {
            let prev_level_nodes = &self.nodes[level - 1];
            let new_digest = inner_hash(
                &prev_level_nodes[level_index * 2],
                &prev_level_nodes
                    .get(level_index * 2 + 1)
                    .unwrap_or(&EMPTY_NODE),
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
        leaf: &[u8],
    ) -> Result<(), LeafIndexOutOfBounds> {
        self.update_leaf_hash(leaf_index, leaf_hash(leaf))
    }
}

/// Computes the hash of the provided input to be used as a leaf hash of a Merkle tree.
pub(crate) fn leaf_hash(input: &[u8]) -> Digest {
    leaf_hash!(input)
}

fn inner_hash(left: &Digest, right: &Digest) -> Digest {
    let mut hasher = Sha3_256::new();
    hasher.update(INNER_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn n_levels_from_leaves(n_leaves: usize) -> usize {
    usize::try_from(n_leaves.next_power_of_two().ilog2()).expect("this is smaller than `n_leaves`")
        + 1
}

#[cfg(test)]
mod test {
    use super::*;

    const LEAF_PREFIX: [u8; 1] = [0];

    const TEST_INPUT: [&[u8]; 9] = [
        b"foo", b"bar", b"fizz", b"baz", b"buzz", b"fizz", b"foobar", b"walrus", b"fizz",
    ];

    #[test]
    fn test_merkle_tree_empty() {
        let mt: MerkleTree = MerkleTree::build::<[&[u8]; 0]>([]);
        assert_eq!(mt.root(), &EMPTY_NODE);
    }

    #[test]
    fn test_merkle_tree_single_element() {
        let test_inp = "Test";
        let mt: MerkleTree = MerkleTree::build(&[test_inp.as_bytes()]);
        let mut hasher = Sha3_256::new();
        hasher.update(LEAF_PREFIX);
        hasher.update(test_inp.as_bytes());
        assert_eq!(mt.root(), &Digest::from(hasher.finalize()));
    }

    #[test]
    fn test_merkle_tree_empty_element() {
        let mt: MerkleTree = MerkleTree::build(&[&[]]);
        let mut hasher = Sha3_256::new();
        hasher.update(LEAF_PREFIX);
        hasher.update([]);
        assert_eq!(mt.root(), &Digest::from(hasher.finalize()));
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
    fn test_update_and_verify_path() {
        for i in 0..TEST_INPUT.len() {
            let mut mt: MerkleTree = MerkleTree::build(&TEST_INPUT[..i]);
            for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
                let proof = mt.get_proof(index).unwrap();
                assert!(proof.verify_proof(&mt.root(), leaf_data, index));
                mt.update_leaf(index, "new value".as_bytes()).unwrap();
                assert!(proof.verify_proof(&mt.root(), "new value".as_bytes(), index));
            }
        }
    }

    #[test]
    fn test_add_leaf() {
        let mut updated_mt: MerkleTree = MerkleTree::build::<[&[u8]; 0]>([]);
        for i in 0..TEST_INPUT.len() {
            updated_mt.add_leaf(TEST_INPUT[i]);
            let mt: MerkleTree = MerkleTree::build(&TEST_INPUT[..i + 1]);
            assert_eq!(updated_mt.root(), mt.root());
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
