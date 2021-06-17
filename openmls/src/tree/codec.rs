use tls_codec::{Deserialize, Serialize, TlsSize, TlsVecU32, TlsVecU8};

use crate::tree::{node::*, secret_tree::*, *};
use std::{
    convert::TryFrom,
    io::{Read, Write},
};

// Nodes

impl Codec for NodeType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        match NodeType::try_from(u8::decode(cursor)?) {
            Ok(node_type) => Ok(node_type),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

impl tls_codec::Deserialize for NodeType {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let value = u8::tls_deserialize(bytes)?;
        NodeType::try_from(value).map_err(|e| {
            tls_codec::Error::DecodingError(format!("Invalid node type value {}", value))
        })
    }
}

impl tls_codec::TlsSize for NodeType {
    fn serialized_len(&self) -> usize {
        1
    }
}

impl tls_codec::Serialize for NodeType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<(), tls_codec::Error> {
        (*self as u8).tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for Node {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let node_type = NodeType::tls_deserialize(bytes)?;
        let (key_package, node) = match node_type {
            NodeType::Leaf => (Some(KeyPackage::tls_deserialize(bytes)?), None),
            NodeType::Parent => {
                let parent = ParentNode::tls_deserialize(bytes)?;
                (None, Some(parent))
            }
        };
        Ok(Node {
            node_type,
            key_package,
            node,
        })
    }
}

impl tls_codec::TlsSize for Node {
    fn serialized_len(&self) -> usize {
        self.node_type.serialized_len()
            + match self.node_type {
                NodeType::Leaf => self.key_package.as_ref().unwrap().serialized_len(),
                NodeType::Parent => self.node.as_ref().unwrap().serialized_len(),
            }
    }
}

impl tls_codec::Serialize for Node {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<(), tls_codec::Error> {
        self.node_type.tls_serialize(writer)?;
        match self.node_type {
            NodeType::Leaf => self.key_package.as_ref().unwrap().tls_serialize(writer),
            NodeType::Parent => self.node.as_ref().unwrap().tls_serialize(writer),
        }
    }
}

impl tls_codec::Serialize for ParentNode {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<(), tls_codec::Error> {
        self.public_key.tls_serialize(writer)?;
        self.unmerged_leaves.tls_serialize(writer)?;
        self.parent_hash.tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for ParentNode {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let public_key = HpkePublicKey::tls_deserialize(bytes)?;
        let unmerged_leaves = TlsVecU32::tls_deserialize(bytes)?;
        let parent_hash = TlsVecU8::tls_deserialize(bytes)?;

        Ok(ParentNode {
            public_key,
            unmerged_leaves,
            parent_hash,
        })
    }
}

impl tls_codec::TlsSize for ParentNode {
    #[inline]
    fn serialized_len(&self) -> usize {
        self.public_key.serialized_len()
            + VecSize::VecU32.len_len()
            + self.unmerged_leaves.len() * 4
            + VecSize::VecU8.len_len()
            + self.parent_hash.len()
    }
}

impl Codec for UpdatePathNode {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.public_key.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.encrypted_path_secret)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = HpkePublicKey::decode(cursor)?;
        let encrypted_path_secret = decode_vec(VecSize::VecU32, cursor)?;
        Ok(UpdatePathNode {
            public_key,
            encrypted_path_secret,
        })
    }
}

impl Codec for UpdatePath {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.leaf_key_package.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.nodes)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let leaf_key_package = KeyPackage::decode(cursor)?;
        let nodes = decode_vec(VecSize::VecU32, cursor)?;
        Ok(UpdatePath {
            leaf_key_package,
            nodes,
        })
    }
}

// ASTree Codecs

impl Codec for SecretTreeNode {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.secret.encode(buffer)?;
        Ok(())
    }
}

// Hash inputs

impl<'a> tls_codec::Serialize for ParentHashInput<'a> {
    fn tls_serialize<W: Write>(&self, buffer: &mut W) -> Result<(), tls_codec::Error> {
        self.public_key.tls_serialize(buffer)?;

        debug_assert!(self.parent_hash.len() <= u8::MAX as usize);
        buffer.write_all(&[self.parent_hash.len() as u8])?;
        buffer.write_all(&self.parent_hash)?;

        debug_assert!(self.original_child_resolution.len() <= u32::MAX as usize);
        buffer.write_all(&(self.original_child_resolution.len() as u32).to_be_bytes())?;
        for &pk in self.original_child_resolution.iter() {
            pk.tls_serialize(buffer)?;
        }
        Ok(())
    }
}

impl<'a> tls_codec::TlsSize for ParentHashInput<'a> {
    #[inline]
    fn serialized_len(&self) -> usize {
        self.public_key.serialized_len()
            + VecSize::VecU8.len_len()
            + self.parent_hash.len()
            + VecSize::VecU32.len_len()
            + self
                .original_child_resolution
                .iter()
                .fold(0, |acc, e| acc + e.serialized_len())
    }
}

impl<'a> tls_codec::Serialize for ParentNodeTreeHashInput<'a> {
    fn tls_serialize<W: Write>(&self, buffer: &mut W) -> Result<(), tls_codec::Error> {
        buffer.write_all(&self.node_index.to_be_bytes())?;
        self.parent_node.tls_serialize(buffer)?;

        let len = self.left_hash.len();
        debug_assert!(len < u8::MAX as usize);
        if len > u8::MAX as usize {
            return Err(tls_codec::Error::InvalidVectorLength);
        }
        let len = len as u8;
        buffer.write_all(&[len])?;
        buffer.write_all(self.left_hash)?;

        let len = self.right_hash.len();
        debug_assert!(len < u8::MAX as usize);
        if len > u8::MAX as usize {
            return Err(tls_codec::Error::InvalidVectorLength);
        }
        let len = len as u8;
        buffer.write_all(&[len])?;
        buffer.write_all(self.right_hash)?;
        Ok(())
    }
}

impl<'a> tls_codec::TlsSize for ParentNodeTreeHashInput<'a> {
    #[inline]
    fn serialized_len(&self) -> usize {
        VecSize::VecU32.len_len()
            + self.parent_node.serialized_len()
            + VecSize::VecU8.len_len()
            + self.left_hash.len()
            + VecSize::VecU8.len_len()
            + self.right_hash.len()
    }
}

impl<'a> tls_codec::Serialize for LeafNodeHashInput<'a> {
    fn tls_serialize<W: Write>(&self, buffer: &mut W) -> Result<(), tls_codec::Error> {
        buffer.write_all(&self.node_index.as_u32().to_be_bytes())?;
        self.key_package.tls_serialize(buffer)
    }
}

impl<'a> tls_codec::TlsSize for LeafNodeHashInput<'a> {
    #[inline]
    fn serialized_len(&self) -> usize {
        VecSize::VecU32.len_len() + self.key_package.serialized_len()
    }
}

// Index

impl Codec for LeafIndex {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(LeafIndex(u32::decode(cursor)?))
    }
}

impl TlsSize for LeafIndex {
    fn serialized_len(&self) -> usize {
        4 /* u32 */
    }
}

impl tls_codec::Serialize for LeafIndex {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<(), tls_codec::Error> {
        self.0.tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for LeafIndex {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(Self(u32::tls_deserialize(bytes)?))
    }
}

// Secret tree

impl Codec for TreeContext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node.encode(buffer)?;
        self.generation.encode(buffer)?;
        Ok(())
    }
}
