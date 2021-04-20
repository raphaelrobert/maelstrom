//! This module provides the `Client` datastructure, which contains the state
//! associated with a client in the context of MLS, along with functions to have
//! that client perform certain MLS operations.
use std::{cell::RefCell, collections::HashMap};

use openmls::{node::Node, prelude::*};

use super::{errors::ClientError, ActionType};

#[derive(Debug)]
/// The client contains the necessary state for a client in the context of MLS.
/// It contains the group states, as well as a reference to a `KeyStore`
/// containing its `CredentialBundle`s. The `key_package_bundles` field contains
/// generated `KeyPackageBundle`s that are waiting to be used for new groups.
pub struct Client {
    /// Name of the client.
    pub(crate) identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub(crate) credentials: HashMap<CiphersuiteName, Credential>,
    pub(crate) key_store: KeyStore,
    pub(crate) groups: RefCell<HashMap<GroupId, ManagedGroup>>,
}

impl Client {
    /// Generate a fresh key package bundle and store it in
    /// `self.key_package_bundles`. The first ciphersuite determines the
    /// credential used to generate the `KeyPackageBundle`. Returns the
    /// corresponding `KeyPackage`.
    pub fn get_fresh_key_package(
        &self,
        ciphersuites: &[CiphersuiteName],
    ) -> Result<KeyPackage, ClientError> {
        if ciphersuites.is_empty() {
            return Err(ClientError::NoCiphersuite);
        }
        let credential = self
            .credentials
            .get(&ciphersuites[0])
            .ok_or(ClientError::CiphersuiteNotSupported)?;
        let mandatory_extensions = Vec::new();
        let key_package: KeyPackage = self
            .key_store
            .generate_key_package_bundle(ciphersuites, credential, mandatory_extensions)
            .unwrap();
        Ok(key_package)
    }

    /// Create a group with the given `group_id`, `ciphersuite` and
    /// `managed_group_config`. Throws an error if the client doesn't support
    /// the `ciphersuite`, i.e. if no corresponding `CredentialBundle` exists.
    pub fn create_group(
        &self,
        group_id: GroupId,
        managed_group_config: ManagedGroupConfig,
        ciphersuite: &Ciphersuite,
    ) -> Result<(), ClientError> {
        let credential = self
            .credentials
            .get(&ciphersuite.name())
            .ok_or(ClientError::CiphersuiteNotSupported)?;
        let mandatory_extensions = Vec::new();
        let key_package: KeyPackage = self
            .key_store
            .generate_key_package_bundle(&[ciphersuite.name()], credential, mandatory_extensions)
            .unwrap();
        let group_state = ManagedGroup::new(
            &self.key_store,
            &managed_group_config,
            group_id.clone(),
            &key_package.hash(),
        )?;
        self.groups.borrow_mut().insert(group_id, group_state);
        Ok(())
    }

    /// Join a group based on the given `welcome` and `ratchet_tree`. The group
    /// is created with the given `ManagedGroupConfig`. Throws an error if no
    /// `KeyPackage` exists matching the `Welcome`, if the client doesn't
    /// support the ciphersuite, or if an error occurs processing the `Welcome`.
    pub fn join_group(
        &self,
        managed_group_config: ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<(), ClientError> {
        let new_group: ManagedGroup = ManagedGroup::new_from_welcome(
            &self.key_store,
            &managed_group_config,
            welcome,
            ratchet_tree,
        )?;
        self.groups
            .borrow_mut()
            .insert(new_group.group_id().to_owned(), new_group);
        Ok(())
    }

    /// Have the client process the given messages. Returns an error if an error
    /// occurs during message processing or if no group exists for one of the
    /// messages.
    pub fn receive_messages_for_group(&self, messages: &[MlsMessage]) -> Result<(), ClientError> {
        let mut group_states = self.groups.borrow_mut();
        for message in messages {
            let group_id = GroupId::from_slice(&message.group_id());
            let group_state = group_states
                .get_mut(&group_id)
                .ok_or(ClientError::NoMatchingGroup)?;
            group_state.process_messages(vec![message.clone()])?;
        }
        Ok(())
    }

    /// Get the credential and the index of each group member of the group with
    /// the given id. Returns an error if no group exists with the given group
    /// id.
    pub fn get_members_of_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(usize, Credential)>, ClientError> {
        let groups = self.groups.borrow();
        let group = groups.get(group_id).ok_or(ClientError::NoMatchingGroup)?;
        let mut members = vec![];
        let tree = group.export_ratchet_tree();
        for (index, leaf) in tree.iter().enumerate() {
            if index % 2 == 0 {
                if let Some(leaf_node) = leaf {
                    let key_package = leaf_node.key_package().unwrap();
                    members.push((index / 2, key_package.credential().clone()));
                }
            }
        }
        Ok(members)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) a self update in the group with the given group id.
    /// Optionally, a `KeyPackageBundle` can be provided, which the client will
    /// update their leaf with. Returns an error if no group with the given
    /// group id can be found or if an error occurs while creating the update.
    pub fn self_update(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<(Vec<MlsMessage>, Option<Welcome>), ClientError> {
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        let action_results = match action_type {
            ActionType::Commit => group.self_update(&self.key_store, key_package_bundle_option)?,
            ActionType::Proposal => (
                group.propose_self_update(&self.key_store, key_package_bundle_option)?,
                None,
            ),
        };
        Ok(action_results)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) adding the clients with the given `KeyPackage`s to the
    /// group with the given group id. Returns an error if no group with the
    /// given group id can be found or if an error occurs while performing the
    /// add operation.
    pub fn add_members(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        key_packages: &[KeyPackage],
        include_path: bool,
    ) -> Result<(Vec<MlsMessage>, Option<Welcome>), ClientError> {
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        let action_results = match action_type {
            ActionType::Commit => {
                let (messages, welcome) =
                    group.add_members(&self.key_store, key_packages, include_path)?;
                (messages, Some(welcome))
            }
            ActionType::Proposal => (
                group.propose_add_members(&self.key_store, key_packages)?,
                None,
            ),
        };
        Ok(action_results)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) removing the clients with the given indices from the
    /// group with the given group id. Returns an error if no group with the
    /// given group id can be found or if an error occurs while performing the
    /// remove operation.
    pub fn remove_members(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        target_indices: &[usize],
    ) -> Result<(Vec<MlsMessage>, Option<Welcome>), ClientError> {
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        let action_results = match action_type {
            ActionType::Commit => group.remove_members(&self.key_store, target_indices)?,
            ActionType::Proposal => (
                group.propose_remove_members(&self.key_store, target_indices)?,
                None,
            ),
        };
        Ok(action_results)
    }
}
