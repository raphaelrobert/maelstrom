use openmls::prelude::*;

mod utils;

use utils::managed_utils::*;

// The following tests are test corresponding the the interop test scenarios
// detailed here:
// https://github.com/mlswg/mls-implementations/blob/master/test-scenarios.md
// The tests are conducted for every available ciphersuite, but currently only
// using BasicCredentials. We can change the test setup once #134 is fixed.

fn default_managed_group_config() -> ManagedGroupConfig {
    let handshake_message_format = HandshakeMessageFormat::Plaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = default_callbacks::default_callbacks();
    ManagedGroupConfig::new(handshake_message_format, update_policy, 10, callbacks)
}

#[test]
fn test_one_to_one_join() {
    let number_of_clients = 2;
    let setup = ManagedTestSetup::new(default_managed_group_config(), number_of_clients);
    setup.create_clients();

    for ciphersuite in Config::supported_ciphersuites() {
        // Create a group with a random creator.
        let group_id = setup
            .create_group(ciphersuite)
            .expect("Error while trying to create group.");
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        let (_, alice_id) = group.members.first().unwrap().clone();

        // A vector including bob's id.
        let bob_id = setup.random_new_members_for_group(group, 1).unwrap();

        setup
            .add_clients(ActionType::Commit, group, &alice_id, bob_id)
            .expect("Error adding Bob");

        // Check that group members agree on a group state.
        setup.check_group_states(group);
    }
}

#[test]
fn test_three_party_join() {
    let number_of_clients = 3;
    let setup = ManagedTestSetup::new(default_managed_group_config(), number_of_clients);
    setup.create_clients();

    for ciphersuite in Config::supported_ciphersuites() {
        // Create a group with a random creator.
        let group_id = setup
            .create_group(ciphersuite)
            .expect("Error while trying to create group.");
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        let (_, alice_id) = group.members.first().unwrap().clone();

        // A vector including Bob's id.
        let bob_id = setup.random_new_members_for_group(group, 1).unwrap();

        // Create the add commit and deliver the welcome.
        setup
            .add_clients(ActionType::Commit, group, &alice_id, bob_id)
            .expect("Error adding Bob");

        // A vector including Charly's id.
        let charly_id = setup.random_new_members_for_group(group, 1).unwrap();

        setup
            .add_clients(ActionType::Commit, group, &alice_id, charly_id)
            .expect("Error adding Charly");

        // Check that group members agree on a group state.
        setup.check_group_states(group);
    }
}

#[test]
fn test_multiple_joins() {
    let number_of_clients = 3;
    let setup = ManagedTestSetup::new(default_managed_group_config(), number_of_clients);
    setup.create_clients();

    for ciphersuite in Config::supported_ciphersuites() {
        // Create a group with a random creator.
        let group_id = setup
            .create_group(ciphersuite)
            .expect("Error while trying to create group.");
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        let (_, alice_id) = group.members.first().unwrap().clone();

        // A vector including Bob's and Charly's id.
        let bob_charly_id = setup.random_new_members_for_group(group, 2).unwrap();

        // Create the add commit and deliver the welcome.
        setup
            .add_clients(ActionType::Commit, group, &alice_id, bob_charly_id)
            .expect("Error adding Bob and Charly");

        // Check that group members agree on a group state.
        setup.check_group_states(group);
    }
}

// TODO #192, #286, #289: The external join test should go here.

#[test]
fn test_update() {
    let number_of_clients = 2;
    let setup = ManagedTestSetup::new(default_managed_group_config(), number_of_clients);
    setup.create_clients();

    for ciphersuite in Config::supported_ciphersuites() {
        // Create a group with two members. Includes the process of adding Bob.
        let group_id = setup
            .create_random_group(2, ciphersuite)
            .expect("Error while trying to create group.");
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        let (_, alice_id) = group.members.first().unwrap().clone();

        // Let Alice create an update with a self-generated KeyPackageBundle.
        setup
            .self_update(ActionType::Commit, group, &alice_id, None)
            .expect("Error self-updating.");

        // Check that group members agree on a group state.
        setup.check_group_states(group);
    }
}

#[test]
fn test_remove() {
    let number_of_clients = 2;
    let setup = ManagedTestSetup::new(default_managed_group_config(), number_of_clients);
    setup.create_clients();

    for ciphersuite in Config::supported_ciphersuites() {
        // Create a group with two members. Includes the process of adding Bob.
        let group_id = setup
            .create_random_group(2, ciphersuite)
            .expect("Error while trying to create group.");
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        let (_, alice_id) = group.members.first().unwrap().clone();
        let (_, bob_id) = group.members.last().unwrap().clone();

        // Have alice remove Bob.
        setup
            .remove_clients(ActionType::Commit, group, &alice_id, vec![bob_id])
            .expect("Error removing Bob from the group.");

        // Check that group members agree on a group state.
        setup.check_group_states(group);
    }
}

// TODO #141, #284: The external PSK, resumption and re-init tests should go here.

// TODO: The large group lifecycle becomes possible once #305 is merged. It
// currently panics, because the decryption key indices are not properly
// computed in large groups.
#[test]
#[should_panic]
fn test_large_group_lifecycle() {
    // "Large" is 20 for now.
    let number_of_clients = 20;
    let setup = ManagedTestSetup::new(default_managed_group_config(), number_of_clients);
    setup.create_clients();

    for ciphersuite in Config::supported_ciphersuites() {
        // Create a group with twenty members. The process includes creating a
        // one-person group and then adding new members in bunches of up to 5,
        // each bunch by a random group member.
        let group_id = setup
            .create_random_group(20, ciphersuite)
            .expect("Error while trying to create group.");
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        let mut group_members = group.members.clone();

        // Have each member in turn update. In between each update, messages are
        // delivered to each member.
        for (_, member_id) in &group_members {
            setup
                .self_update(ActionType::Commit, group, member_id, None)
                .expect("Error while updating group.")
        }

        while group_members.len() > 1 {
            let remover_id = group.random_group_member();
            let mut target_id = group.random_group_member();
            // Get a random member until it's not the one doing the remove operation.
            while remover_id == target_id {
                target_id = group.random_group_member();
            }
            setup
                .remove_clients(ActionType::Commit, group, &remover_id, vec![target_id])
                .expect("Error while removing group member.");
            group_members = group.members.clone();
        }

        // Check that group members agree on a group state.
        setup.check_group_states(group);
    }
}