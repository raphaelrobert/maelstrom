initSidebarItems({"enum":[["EmptyInputError",""],["GroupEvent","Group event that occured while processing messages in `ManagedGroup`."],["HandshakeMessageFormat","Defines whether handshake messages (Proposals & Commits) are encrypted. Application are always encrypted regardless. `Plaintext`: Handshake messages are returned as MLSPlaintext messages `Ciphertext`: Handshake messages are returned as MLSCiphertext messages"],["InvalidMessageError",""],["MLSMessage","Unified message type"],["ManagedGroupError",""],["PendingProposalsError",""],["Removal","This enum lists the 4 different variants of a removal, depending on who the remover and who the leaver is."],["UseAfterEviction",""]],"mod":[["callbacks",""],["codec",""],["config",""],["errors","MLS Group errors`WelcomeError`, `ApplyCommitError`, `DecryptionError`, and `CreateCommitError`."],["errors","MLS Managed Group errors`WelcomeError`, `ApplyCommitError`, `DecryptionError`, and `CreateCommitError`."],["events",""],["group_context",""],["managed_group",""],["mls_group",""]],"struct":[["ApplicationMessageEvent","Event that occurs when an application message is received. `sender` contains the message's sender and `message` contains the application message."],["ErrorEvent","Event that occurs when an error occurred while processing messages in a group. `error` contains the specific error that occurred."],["GroupConfig","Configuration for an MLS group."],["GroupContext",""],["GroupEpoch",""],["GroupId",""],["InvalidMessageEvent","Event that occurs when an invalid message is received. `error` contains the specific error."],["ManagedGroup","A `ManagedGroup` represents an [MlsGroup] with an easier, high-level API designed to be used in production. The API exposes high level functions to manage a group by adding/removing members, get the current member list, etc."],["ManagedGroupCallbacks","Collection of callback functions that are passed to a `ManagedGroup` as part of the configurations. All callback functions are optional."],["ManagedGroupConfig","Specifies the configuration parameters for a managed group"],["MemberAddedEvent","Event that occurs when member `sender` adds member `added_member`."],["MemberRemovedEvent","Event that occurs when a member leaves/is removed from the group. The exact context of the removal is explained in the `Removal` enum."],["MemberUpdatedEvent","Event that occurs when a member updates its leaf. `updated_member` contains the new credential."],["MlsGroup",""],["PskReceivedEvent","Event that occurs when  a PSK is received. `psk_id` contains the PSK ID."],["ReInitEvent","Event that occurs when a `ReInitProposal` is received. `re_init_proposal` contains the `ReInitProposal`."],["UpdatePolicy","Specifies in which intervals the own leaf node should be updated"]],"type":[["AutoSave",""],["CreateCommitResult",""],["PskFetcher","This callback function is used in several places in `MlsGroup`. It gets called whenever the key schedule is advanced and references to PSKs are encountered. Since the PSKs are to be trandmitted out-of-band, they need to be fetched from wherever they are stored."],["ValidateAdd",""],["ValidateRemove",""]]});