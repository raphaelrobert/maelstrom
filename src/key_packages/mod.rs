// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::ciphersuite::*;
use crate::codec::*;
use crate::config::ProtocolVersion;
use crate::creds::*;
use crate::extensions::{
    CapabilitiesExtension, Extension, ExtensionError, ExtensionStruct, ExtensionType,
    ParentHashExtension,
};
use crate::schedule::*;
use evercrypt::rand_util::*;

mod codec;

mod test_key_packages;

#[derive(Debug, PartialEq)]
pub enum KeyPackageError {
    ExtensionNotPresent,
    MandatoryExtensionsMissing,
    InvalidLifetimeExtension,
    InvalidSignature,
    LibraryError,
}

impl From<ExtensionError> for KeyPackageError {
    fn from(e: ExtensionError) -> Self {
        match e {
            // TODO: error handling #83
            ExtensionError::InvalidExtensionType => KeyPackageError::ExtensionNotPresent,
            ExtensionError::UnknownExtension => KeyPackageError::ExtensionNotPresent,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyPackage {
    protocol_version: ProtocolVersion,
    cipher_suite: CiphersuiteName,
    hpke_init_key: HPKEPublicKey,
    credential: Credential,
    extensions: Vec<Box<dyn Extension>>,
    signature: Signature,
}

/// Mandatory extensions for key packages.
const MANDATORY_EXTENSIONS: [ExtensionType; 2] =
    [ExtensionType::Capabilities, ExtensionType::Lifetime];

impl KeyPackage {
    /// Create a new key package but only with the given `extensions` for the
    /// given `ciphersuite` and `identity`, and the initial HPKE key pair `init_key`.
    fn new(
        ciphersuite_name: CiphersuiteName,
        hpke_init_key: HPKEPublicKey,
        credential_bundle: &CredentialBundle,
        extensions: Vec<Box<dyn Extension>>,
    ) -> Self {
        let mut key_package = Self {
            // TODO: #85 Take from global config.
            protocol_version: ProtocolVersion::default(),
            cipher_suite: ciphersuite_name,
            hpke_init_key,
            credential: credential_bundle.credential().clone(),
            extensions,
            signature: Signature::new_empty(),
        };
        key_package.sign(&credential_bundle);
        key_package
    }

    /// Verify that this key package is valid:
    /// * verify that the signature on this key package is valid
    /// * verify that all mandatory extensions are present
    /// * make sure that the lifetime is valid
    /// Returns `Ok(())` if all checks succeed and `KeyPackageError` otherwise
    pub fn verify(&self) -> Result<(), KeyPackageError> {
        //  First make sure that all mandatory extensions are present.
        let mut mandatory_extensions_found = MANDATORY_EXTENSIONS.to_vec();
        for extension in self.extensions.iter() {
            if let Some(p) = mandatory_extensions_found
                .iter()
                .position(|&e| e == extension.get_type())
            {
                let _ = mandatory_extensions_found.remove(p);
            }
            // Make sure the lifetime is valid.
            if extension.get_type() == ExtensionType::Lifetime {
                match extension.to_lifetime_extension() {
                    Ok(e) => {
                        if !e.is_valid() {
                            return Err(KeyPackageError::InvalidLifetimeExtension);
                        }
                    }
                    Err(e) => {
                        println!("Library error. {:?}", e);
                        return Err(KeyPackageError::LibraryError);
                    }
                }
            }
        }

        // Make sure we found all mandatory extensions.
        if !mandatory_extensions_found.is_empty() {
            return Err(KeyPackageError::MandatoryExtensionsMissing);
        }

        // Verify the signature on this key package.
        if self
            .credential
            .verify(&self.unsigned_payload().unwrap(), &self.signature)
        {
            Ok(())
        } else {
            Err(KeyPackageError::InvalidSignature)
        }
    }

    /// Compute the hash of the encoding of this key package.
    pub(crate) fn hash(&self) -> Vec<u8> {
        let bytes = self.encode_detached().unwrap();
        Ciphersuite::new(self.cipher_suite).hash(&bytes)
    }

    /// Get a reference to the extension of `extension_type`.
    /// Returns `Some(extension)` if present and `None` if the extension is not present.
    #[allow(clippy::borrowed_box)]
    pub(crate) fn get_extension(
        &self,
        extension_type: ExtensionType,
    ) -> Option<&Box<dyn Extension>> {
        for e in &self.extensions {
            if e.get_type() == extension_type {
                return Some(e);
            }
        }
        None
    }

    /// Get the ID of this key package as byte slice.
    /// Returns an error if no Key ID extension is present.
    pub fn get_id(&self) -> Result<&[u8], KeyPackageError> {
        if let Some(key_id_ext) = self.get_extension(ExtensionType::KeyID) {
            return Ok(key_id_ext.to_key_id_extension()?.as_slice());
        }
        Err(KeyPackageError::ExtensionNotPresent)
    }

    /// Update the parent hash extension of this key package.
    pub(crate) fn update_parent_hash(&mut self, parent_hash: &[u8]) {
        self.remove_extension(ExtensionType::ParentHash);
        let extension = Box::new(ParentHashExtension::new(parent_hash));
        self.extensions.push(extension);
    }

    /// Add (or replace) an extension to the KeyPackage.
    /// Make sure to re-sign the package before using it. It will be invalid
    /// after calling this function!
    pub fn add_extension(&mut self, extension: Box<dyn Extension>) {
        self.remove_extension(extension.get_type());
        self.extensions.push(extension);
    }

    /// Remove an extension from the KeyPackage
    /// Make sure to re-sign the package before using it. It will be invalid
    /// after calling this function!
    pub(crate) fn remove_extension(&mut self, extension_type: ExtensionType) {
        self.extensions.retain(|e| e.get_type() != extension_type);
    }

    /// Get a reference to the credential.
    pub(crate) fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Get a reference to the HPKE init key.
    pub(crate) fn hpke_init_key(&self) -> &HPKEPublicKey {
        &self.hpke_init_key
    }

    /// Set a new HPKE init key.
    pub(crate) fn set_hpke_init_key(&mut self, hpke_init_key: HPKEPublicKey) {
        self.hpke_init_key = hpke_init_key;
    }

    /// Get the `CiphersuiteName`.
    pub(crate) fn cipher_suite(&self) -> CiphersuiteName {
        self.cipher_suite
    }

    /// Get a reference to the extensions of this key package.
    pub fn extensions(&self) -> &[Box<dyn Extension>] {
        &self.extensions
    }

    /// Compile the unsigned payload to create the signature required in the
    /// signature field.
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        let buffer = &mut Vec::new();
        self.protocol_version.encode(buffer)?;
        self.cipher_suite.encode(buffer)?;
        self.hpke_init_key.encode(buffer)?;
        self.credential.encode(buffer)?;
        // Get extensions encoded. We need to build a Vec::<ExtensionStruct> first.
        let encoded_extensions: Vec<ExtensionStruct> = self
            .extensions
            .iter()
            .map(|e| e.to_extension_struct())
            .collect();
        encode_vec(VecSize::VecU16, buffer, &encoded_extensions)?;
        Ok(buffer.to_vec())
    }

    /// Populate the `signature` field using the `credential_bundle`.
    pub(crate) fn sign(&mut self, credential_bundle: &CredentialBundle) {
        let payload = &self.unsigned_payload().unwrap();
        self.signature = credential_bundle.sign(payload).unwrap();
    }
}

#[derive(Debug)]
pub struct KeyPackageBundle {
    pub(crate) key_package: KeyPackage,
    pub(crate) private_key: HPKEPrivateKey,
    pub(crate) leaf_secret: Vec<u8>,
}

impl KeyPackageBundle {
    /// Create a new `KeyPackageBundle` for the given `ciphersuite`, `identity`,
    /// and `extensions`. Note that the capabilities extension gets added
    /// automatically, based on the configuration.
    /// This generates a fresh HPKE key pair for this bundle.
    ///
    /// Returns a new `KeyPackageBundle`.
    pub fn new(
        ciphersuite_name: CiphersuiteName,
        credential_bundle: &CredentialBundle,
        extensions: Vec<Box<dyn Extension>>,
    ) -> Self {
        let ciphersuite = Ciphersuite::new(ciphersuite_name);
        let leaf_secret = get_random_vec(ciphersuite.hash_length());
        Self::new_from_leaf_secret(&ciphersuite, credential_bundle, extensions, leaf_secret)
    }

    fn new_from_leaf_secret(
        ciphersuite: &Ciphersuite,
        credential_bundle: &CredentialBundle,
        extensions: Vec<Box<dyn Extension>>,
        leaf_secret: Vec<u8>,
    ) -> Self {
        let leaf_node_secret = Self::derive_leaf_node_secret(ciphersuite, &leaf_secret);
        let keypair = ciphersuite.derive_hpke_keypair(&leaf_node_secret);
        Self::new_with_keypair(
            ciphersuite.name(),
            credential_bundle,
            extensions,
            keypair,
            leaf_secret,
        )
    }

    /// Create a new `KeyPackageBundle` for the given `ciphersuite`, `identity`,
    /// and `extensions`, using the given HPKE `key_pair`.
    ///
    /// Returns a new `KeyPackageBundle`.
    pub fn new_with_keypair(
        ciphersuite_name: CiphersuiteName,
        credential_bundle: &CredentialBundle,
        extensions: Vec<Box<dyn Extension>>,
        key_pair: HPKEKeyPair,
        leaf_secret: Vec<u8>,
    ) -> Self {
        // TODO: #85 this must be configurable.
        let mut final_extensions: Vec<Box<dyn Extension>> =
            vec![Box::new(CapabilitiesExtension::default())];

        let (private_key, public_key) = key_pair.into_keys();
        final_extensions.extend_from_slice(&extensions);
        let key_package = KeyPackage::new(
            ciphersuite_name,
            public_key,
            credential_bundle,
            final_extensions,
        );
        KeyPackageBundle {
            key_package,
            private_key,
            leaf_secret,
        }
    }

    /// Assembles a new KeyPackageBundle from a KeyPackage, a HPKEPrivateKey, and a leaf secret
    pub fn new_from_values(
        key_package: KeyPackage,
        private_key: HPKEPrivateKey,
        leaf_secret: Vec<u8>,
    ) -> Self {
        Self {
            key_package,
            private_key,
            leaf_secret,
        }
    }

    /// Replace the init key in the current KeyPackage with a random one
    pub(crate) fn from_rekeyed_key_package(
        ciphersuite: &Ciphersuite,
        key_package: &KeyPackage,
    ) -> Self {
        let leaf_secret = get_random_vec(ciphersuite.hash_length());
        let leaf_node_secret = Self::derive_leaf_node_secret(ciphersuite, &leaf_secret);
        let (private_key, public_key) = ciphersuite
            .derive_hpke_keypair(&leaf_node_secret)
            .into_keys();

        // Generate new keypair and replace it in current KeyPackage
        let mut new_key_package = key_package.clone();
        new_key_package.set_hpke_init_key(public_key);
        KeyPackageBundle::new_from_values(new_key_package, private_key, leaf_secret)
    }

    /// Update the private key in the bundle.
    pub(crate) fn _set_private_key(&mut self, private_key: HPKEPrivateKey) {
        self.private_key = private_key;
    }

    /// Update the key package in the bundle.
    pub(crate) fn set_key_package(&mut self, key_package: KeyPackage) {
        self.key_package = key_package;
    }

    /// Get a reference to the `KeyPackage`.
    pub fn get_key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// Get a reference to the `KeyPackage`.
    #[cfg(test)]
    pub(crate) fn get_key_package_ref_mut(&mut self) -> &mut KeyPackage {
        &mut self.key_package
    }

    /// Get a reference to the `HPKEPrivateKey`.
    pub(crate) fn get_private_key_ref(&self) -> &HPKEPrivateKey {
        &self.private_key
    }

    /// Get a reference to the `leaf_secret_option`.
    pub(crate) fn get_leaf_secret(&self) -> &[u8] {
        &self.leaf_secret
    }

    /// This function derives the leaf_node_secret from the leaf_secret as described in 5.4 Ratchet Tree Evolution
    pub(crate) fn derive_leaf_node_secret(
        ciphersuite: &Ciphersuite,
        leaf_secret: &[u8],
    ) -> Vec<u8> {
        derive_secret(ciphersuite, &leaf_secret, "node")
    }
}
