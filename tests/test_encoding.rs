use openmls::prelude::*;
mod utils;
use utils::*;

/// This test tests encoding and decoding of anything returned by the API that
/// is meant to be sent over the wire. In particular, this includes Welcome,
/// MLSPlaintext and MLSCiphertext messages.
#[test]
fn test_encoding() {
    // Create a test config for a single client supporting all possible
    // ciphersuites.
    let alice_config = TestClientConfig {
        name: "alice",
        ciphersuites: Config::supported_ciphersuite_names(),
    };

    let mut test_group_configs = Vec::new();

    // Create a group config for each ciphersuite.
    for ciphersuite_name in Config::supported_ciphersuite_names() {
        let test_group = TestGroupConfig {
            ciphersuite: ciphersuite_name,
            config: GroupConfig::default(),
            members: vec![alice_config.clone()],
        };
        test_group_configs.push(test_group);
    }

    // Create the test setup config.
    let test_setup_config = TestSetupConfig {
        clients: vec![alice_config],
        groups: test_group_configs,
    };

    // Initialize the test setup according to config.
    let test_setup = setup(test_setup_config);

    let test_clients = test_setup.clients.borrow();
    let alice = test_clients.get("alice").unwrap().borrow();

    // Create a message in each group and test the padding.
    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite().name())
            .unwrap();
        for _ in 0..100 {
            // Test encoding/decoding of Application messages.
            let message = randombytes(random_usize() % 1000);
            let aad = randombytes(random_usize() % 1000);
            let encrypted_message =
                group_state.create_application_message(&aad, &message, &credential_bundle);
            let encrypted_message_bytes = encrypted_message.encode_detached().unwrap();
            let encrypted_message_decoded =
                match MLSCiphertext::decode(&mut Cursor::new(&encrypted_message_bytes)) {
                    Ok(a) => a,
                    Err(err) => panic!("Error decoding MLSCiphertext: {:?}", err),
                };
            assert_eq!(encrypted_message, encrypted_message_decoded);
        }
        // Test encoding/decoding of Proposal messages

        // Updates

        // TODO: Leaving out Extensions completely still yields a decoding
        // error! Should be solved by #164.
        let capabilities_extension = Box::new(CapabilitiesExtension::default());
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Box<dyn Extension>> =
            vec![capabilities_extension, lifetime_extension];

        let key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite().name()],
            credential_bundle,
            mandatory_extensions,
        )
        .unwrap();
        let update = group_state.create_update_proposal(
            &[],
            credential_bundle,
            key_package_bundle.get_key_package().clone(),
        );
        let update_encoded = update.encode_detached().unwrap();
        let update_decoded = match MLSPlaintext::decode(&mut Cursor::new(&update_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding MPLSPlaintext Update: {:?}", err),
        };

        assert_eq!(update, update_decoded);

        // Adds
        let capabilities_extension = Box::new(CapabilitiesExtension::default());
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Box<dyn Extension>> =
            vec![capabilities_extension, lifetime_extension];

        let key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite().name()],
            credential_bundle,
            mandatory_extensions,
        )
        .unwrap();
        let add = group_state.create_add_proposal(
            &[],
            credential_bundle,
            key_package_bundle.get_key_package().clone(),
        );
        let add_encoded = add.encode_detached().unwrap();
        let add_decoded = match MLSPlaintext::decode(&mut Cursor::new(&add_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding MPLSPlaintext Add: {:?}", err),
        };

        assert_eq!(add, add_decoded);

        // Removes
        let remove =
            group_state.create_remove_proposal(&[], credential_bundle, LeafIndex::from(1u32));
        let remove_encoded = remove.encode_detached().unwrap();
        let remove_decoded = match MLSPlaintext::decode(&mut Cursor::new(&remove_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding MPLSPlaintext Remove: {:?}", err),
        };

        assert_eq!(remove, remove_decoded);

        // Commits

        let proposals = vec![add, remove, update];
        let (commit, welcome_option, _key_package_bundle_option) = group_state
            .create_commit(&[], credential_bundle, proposals, true)
            .unwrap();
        let commit_encoded = commit.encode_detached().unwrap();
        let commit_decoded = match MLSPlaintext::decode(&mut Cursor::new(&commit_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding MPLSPlaintext Commit: {:?}", err),
        };

        assert_eq!(commit, commit_decoded);

        // Welcome messages

        let welcome = welcome_option.unwrap();

        let welcome_encoded = welcome.encode_detached().unwrap();
        let welcome_decoded = match Welcome::decode(&mut Cursor::new(&welcome_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding Welcome message: {:?}", err),
        };

        assert_eq!(welcome, welcome_decoded);
    }
}