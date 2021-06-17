//! # Ratchet tree extension
//!
//! > GroupInfo Extension
//!
//! 11.3. Ratchet Tree Extension
//!
//! ```text
//! enum {
//!     reserved(0),
//!     leaf(1),
//!     parent(2),
//!     (255)
//! } NodeType;
//!
//! struct {
//!     NodeType node_type;
//!     select (Node.node_type) {
//!         case leaf:   KeyPackage key_package;
//!         case parent: ParentNode node;
//!     };
//! } Node;
//!
//! optional<Node> ratchet_tree<1..2^32-1>;
//! ```
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize, TlsVecU32};

use crate::tree::node::*;

use super::{
    Deserialize, Extension, ExtensionError, ExtensionStruct, ExtensionType, RatchetTreeError,
    Serialize,
};

#[derive(PartialEq, Clone, Debug, Default, Serialize, Deserialize)]
pub struct RatchetTreeExtension {
    tree: TlsVecU32<Option<Node>>,
}

impl RatchetTreeExtension {
    /// Build a new extension from a vector of `Node`s.
    pub fn new(tree: Vec<Option<Node>>) -> Self {
        RatchetTreeExtension { tree: tree.into() }
    }

    pub(crate) fn into_vector(self) -> Vec<Option<Node>> {
        self.tree.into()
    }
}

#[typetag::serde]
impl Extension for RatchetTreeExtension {
    fn extension_type(&self) -> ExtensionType {
        ExtensionType::RatchetTree
    }

    /// Build a new RatchetTreeExtension from a byte slice.
    fn new_from_bytes(mut bytes: &[u8]) -> Result<Self, ExtensionError> {
        match TlsVecU32::<Option<Node>>::tls_deserialize(&mut bytes) {
            Ok(tree) => Ok(Self { tree }),
            Err(_) => Err(ExtensionError::RatchetTree(RatchetTreeError::Invalid)),
        }
    }

    // TODO: This should return a Result.
    fn to_extension_struct(&self) -> ExtensionStruct {
        let mut extension_data: Vec<u8> = Vec::with_capacity(self.tree.len() + 4);
        self.tree.tls_serialize(&mut extension_data).unwrap();
        let extension_type = ExtensionType::RatchetTree;
        ExtensionStruct::new(extension_type, extension_data)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
