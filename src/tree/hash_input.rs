//! 7.4. Parent Hash
//!
//! struct {
//!     HPKEPublicKey public_key;
//!     opaque parent_hash<0..255>;
//!     HPKEPublicKey original_child_resolution<0..2^32-1>;
//! } ParentHashInput;
//!
//! 7.5. Tree Hashes
//!
//! ```text
//! struct {
//!     uint8 present;
//!     select (present) {
//!         case 0: struct{};
//!         case 1: T value;
//!     }
//! } optional<T>;
//!
//! struct {
//!     uint32 node_index;
//!     optional<KeyPackage> key_package;
//! } LeafNodeHashInput;
//!
//! struct {
//!     HPKEPublicKey public_key;
//!     opaque parent_hash<0..255>;
//!     uint32 unmerged_leaves<0..2^32-1>;
//! } ParentNode;
//!
//! struct {
//!     uint32 node_index;
//!     optional<ParentNode> parent_node;
//!     opaque left_hash<0..255>;
//!     opaque right_hash<0..255>;
//! } ParentNodeTreeHashInput;
//! ```

use super::node::ParentNode;
use super::*;
use crate::ciphersuite::{Ciphersuite, HPKEPublicKey};
use crate::codec::Codec;
use crate::key_packages::KeyPackage;

pub(crate) struct ParentHashInput<'a> {
    pub(crate) public_key: &'a HPKEPublicKey,
    pub(crate) parent_hash: &'a [u8],
    pub(crate) original_child_resolution: Vec<&'a HPKEPublicKey>,
}

impl<'a> ParentHashInput<'a> {
    pub(crate) fn new(
        tree: &'a RatchetTree,
        index: NodeIndex,
        child_index: NodeIndex,
        parent_hash: &'a [u8],
    ) -> Self {
        // It is ok to use `unwrap()` here, since we can be sure the node is not blank
        let public_key = tree.nodes[index].public_hpke_key().unwrap();
        let original_child_resolution = original_child_resolution(tree, child_index);
        Self {
            public_key,
            parent_hash,
            original_child_resolution,
        }
    }
    pub(crate) fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}
pub struct LeafNodeHashInput<'a> {
    pub(crate) node_index: &'a NodeIndex,
    pub(crate) key_package: &'a Option<KeyPackage>,
}

impl<'a> LeafNodeHashInput<'a> {
    pub(crate) fn new(node_index: &'a NodeIndex, key_package: &'a Option<KeyPackage>) -> Self {
        Self {
            node_index,
            key_package,
        }
    }
    pub fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}
pub struct ParentNodeTreeHashInput<'a> {
    pub(crate) node_index: u32,
    pub(crate) parent_node: &'a Option<ParentNode>,
    pub(crate) left_hash: &'a [u8],
    pub(crate) right_hash: &'a [u8],
}

impl<'a> ParentNodeTreeHashInput<'a> {
    pub(crate) fn new(
        node_index: u32,
        parent_node: &'a Option<ParentNode>,
        left_hash: &'a [u8],
        right_hash: &'a [u8],
    ) -> Self {
        Self {
            node_index,
            parent_node,
            left_hash,
            right_hash,
        }
    }
    pub(crate) fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}

// === Parent hashes ===

/// The list of HPKEPublicKey values of the nodes in the resolution of `index`
/// but with the `unmerged_leaves` of the parent node omitted.
pub(crate) fn original_child_resolution(
    tree: &RatchetTree,
    index: NodeIndex,
) -> Vec<&HPKEPublicKey> {
    // Build the exclusion list that consists of the unmerged leaves of the parent
    // node
    let mut unmerged_leaves = vec![];
    // Check if there is a parent_node
    if let Ok(parent_index) = treemath::parent(index, tree.leaf_count()) {
        // Check if the parent node is not blank
        if let Some(parent_node) = &tree.nodes[parent_index].node {
            for index in &parent_node.unmerged_leaves {
                unmerged_leaves.push(NodeIndex::from(*index as usize));
            }
        }
    };
    // Convert te exclusion list to a HashSet for faster searching
    let exclusion_list: HashSet<&NodeIndex> =
        HashSet::from_iter(unmerged_leaves.iter().map(|index| index));
    // Compute the full resolution
    let full_resolution = treemath::descendants(index, tree.leaf_count());
    // Filter out the nodes from the exclusion list
    let resolution = full_resolution
        .into_iter()
        .filter(|index| !exclusion_list.contains(index))
        .collect::<Vec<NodeIndex>>();

    // Build the list of HPKE public keys by iterating over the resolution and
    // filtering out blank leaf nodes
    resolution
        .iter()
        .filter(|index| !tree.nodes[*index].is_blank())
        .map(|index| tree.nodes[*index].public_hpke_key().unwrap())
        .collect()
}

/// Computes the parent hashes for a leaf node and returns the parent hash for
/// the parent hash extension
pub(crate) fn compute_parent_hashes(tree: &mut RatchetTree, index: LeafIndex) -> Vec<u8> {
    // Recursive helper function used to calculate parent hashes
    fn node_parent_hash(tree: &mut RatchetTree, index: NodeIndex, child: NodeIndex) -> Vec<u8> {
        let tree_size = tree.leaf_count();
        let root = treemath::root(tree_size);
        // This should only happen when the group only contains one member
        if index == root {
            return vec![];
        }
        // Calculate the parent's index
        // It is ok to use `unwrap()` here, since we already checked that the index is
        // not the root
        let parent = treemath::parent(index, tree_size).unwrap();
        // Calculate the sibling's index
        // It is ok to use `unwrap()` here, since we already checked that the index is
        // not the root
        let own_sibling = treemath::sibling(index, tree_size).unwrap();
        // Calculate the sibling's index
        // It is ok to use `unwrap()` here, since we already checked that the index is
        // not the root
        let child_sibling = treemath::sibling(child, tree_size).unwrap();
        // If we already reached the tree's root, return the hash of that node
        let parent_hash = if parent == root {
            ParentHashInput::new(tree, parent, own_sibling, &[]).hash(tree.ciphersuite)
        // Otherwise return the hash of the next parent
        } else {
            node_parent_hash(tree, parent, child)
        };
        // If the current node is a parent, replace the parent hash in that node
        let current_node = &tree.nodes[index];
        // Get the parent node
        if let Some(mut parent_node) = current_node.node.clone() {
            // Set the parent hash
            parent_node.set_parent_hash(parent_hash);
            // Put the node back in the tree
            tree.nodes[index].node = Some(parent_node);
            // Calculate the parent hash of the current node and return it
            ParentHashInput::new(
                tree,
                index,
                child_sibling,
                &tree.nodes[index].node.as_ref().unwrap().parent_hash,
            )
            .hash(tree.ciphersuite)
        // Otherwise we reached the leaf level, just return the hash
        } else {
            parent_hash
        }
    }
    // The same index is used for the child index here, since that parameter doesn't
    // matter when starting with a leaf node
    node_parent_hash(tree, index.into(), index.into())
}

// === Tree hash ===

/// Computes the tree hash
pub(crate) fn compute_tree_hash(tree: &RatchetTree) -> Vec<u8> {
    // Recursive helper function to the tree hashes for a node
    fn node_hash(ciphersuite: &Ciphersuite, tree: &RatchetTree, index: NodeIndex) -> Vec<u8> {
        let node = &tree.nodes[index];
        // Depending on the node type, we calculate the hash differently
        match node.node_type {
            // For leaf nodes we just need the index and the KeyPackage
            NodeType::Leaf => {
                let leaf_node_hash = LeafNodeHashInput::new(&index, &node.key_package);
                leaf_node_hash.hash(ciphersuite)
            }
            // For parent nodes we need the hash of the two children as well
            NodeType::Parent => {
                // Unwrapping here is safe, because parent nodes always have children
                let left = treemath::left(index).unwrap();
                let left_hash = node_hash(ciphersuite, tree, left);
                let right = treemath::right(index, tree.leaf_count()).unwrap();
                let right_hash = node_hash(ciphersuite, tree, right);
                let parent_node_hash = ParentNodeTreeHashInput::new(
                    index.as_u32(),
                    &node.node,
                    &left_hash,
                    &right_hash,
                );
                parent_node_hash.hash(ciphersuite)
            }
        }
    }
    // We starte with the root and traverse the tree downwards
    let root = treemath::root(tree.leaf_count());
    node_hash(&tree.ciphersuite, &tree, root)
}
