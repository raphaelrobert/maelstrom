(function() {var implementors = {};
implementors["openmls"] = [{"text":"impl Freeze for ErrorString","synthetic":true,"types":[]},{"text":"impl Freeze for ErrorPayload","synthetic":true,"types":[]},{"text":"impl Freeze for HKDFError","synthetic":true,"types":[]},{"text":"impl Freeze for CryptoError","synthetic":true,"types":[]},{"text":"impl Freeze for CiphersuiteName","synthetic":true,"types":[]},{"text":"impl Freeze for SignatureScheme","synthetic":true,"types":[]},{"text":"impl Freeze for HpkeCiphertext","synthetic":true,"types":[]},{"text":"impl Freeze for KdfLabel","synthetic":true,"types":[]},{"text":"impl Freeze for Secret","synthetic":true,"types":[]},{"text":"impl Freeze for AeadKey","synthetic":true,"types":[]},{"text":"impl Freeze for ReuseGuard","synthetic":true,"types":[]},{"text":"impl Freeze for AeadNonce","synthetic":true,"types":[]},{"text":"impl Freeze for Signature","synthetic":true,"types":[]},{"text":"impl Freeze for SignaturePrivateKey","synthetic":true,"types":[]},{"text":"impl Freeze for SignaturePublicKey","synthetic":true,"types":[]},{"text":"impl Freeze for SignatureKeypair","synthetic":true,"types":[]},{"text":"impl Freeze for Ciphersuite","synthetic":true,"types":[]},{"text":"impl Freeze for CodecError","synthetic":true,"types":[]},{"text":"impl Freeze for VecSize","synthetic":true,"types":[]},{"text":"impl Freeze for Cursor","synthetic":true,"types":[]},{"text":"impl Freeze for ConfigError","synthetic":true,"types":[]},{"text":"impl Freeze for CONFIG","synthetic":true,"types":[]},{"text":"impl Freeze for Constants","synthetic":true,"types":[]},{"text":"impl Freeze for PersistentConfig","synthetic":true,"types":[]},{"text":"impl Freeze for Config","synthetic":true,"types":[]},{"text":"impl Freeze for ProtocolVersion","synthetic":true,"types":[]},{"text":"impl Freeze for CredentialError","synthetic":true,"types":[]},{"text":"impl Freeze for CredentialType","synthetic":true,"types":[]},{"text":"impl Freeze for Certificate","synthetic":true,"types":[]},{"text":"impl Freeze for MLSCredentialType","synthetic":true,"types":[]},{"text":"impl Freeze for Credential","synthetic":true,"types":[]},{"text":"impl Freeze for BasicCredential","synthetic":true,"types":[]},{"text":"impl Freeze for CredentialBundle","synthetic":true,"types":[]},{"text":"impl Freeze for CapabilitiesExtension","synthetic":true,"types":[]},{"text":"impl Freeze for ExtensionError","synthetic":true,"types":[]},{"text":"impl Freeze for LifetimeExtensionError","synthetic":true,"types":[]},{"text":"impl Freeze for CapabilitiesExtensionError","synthetic":true,"types":[]},{"text":"impl Freeze for KeyPackageIdError","synthetic":true,"types":[]},{"text":"impl Freeze for ParentHashError","synthetic":true,"types":[]},{"text":"impl Freeze for RatchetTreeError","synthetic":true,"types":[]},{"text":"impl Freeze for InvalidExtensionError","synthetic":true,"types":[]},{"text":"impl Freeze for KeyIDExtension","synthetic":true,"types":[]},{"text":"impl Freeze for LifetimeExtension","synthetic":true,"types":[]},{"text":"impl Freeze for ParentHashExtension","synthetic":true,"types":[]},{"text":"impl Freeze for RatchetTreeExtension","synthetic":true,"types":[]},{"text":"impl Freeze for ExtensionType","synthetic":true,"types":[]},{"text":"impl Freeze for ExtensionStruct","synthetic":true,"types":[]},{"text":"impl Freeze for MLSCiphertext","synthetic":true,"types":[]},{"text":"impl Freeze for MLSSenderData","synthetic":true,"types":[]},{"text":"impl Freeze for MLSSenderDataAAD","synthetic":true,"types":[]},{"text":"impl Freeze for MLSCiphertextContent","synthetic":true,"types":[]},{"text":"impl Freeze for MLSCiphertextContentAAD","synthetic":true,"types":[]},{"text":"impl Freeze for MLSPlaintextError","synthetic":true,"types":[]},{"text":"impl Freeze for MLSCiphertextError","synthetic":true,"types":[]},{"text":"impl Freeze for VerificationError","synthetic":true,"types":[]},{"text":"impl Freeze for MLSPlaintext","synthetic":true,"types":[]},{"text":"impl Freeze for ContentType","synthetic":true,"types":[]},{"text":"impl Freeze for MLSPlaintextContentType","synthetic":true,"types":[]},{"text":"impl Freeze for Mac","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for MLSPlaintextTBMPayload&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for MembershipTag","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for MLSPlaintextTBS&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for MLSPlaintextTBSPayload","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for MLSPlaintextCommitContent&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for MLSPlaintextCommitAuthData&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for SenderType","synthetic":true,"types":[]},{"text":"impl Freeze for Sender","synthetic":true,"types":[]},{"text":"impl Freeze for GroupError","synthetic":true,"types":[]},{"text":"impl Freeze for WelcomeError","synthetic":true,"types":[]},{"text":"impl Freeze for ApplyCommitError","synthetic":true,"types":[]},{"text":"impl Freeze for CreateCommitError","synthetic":true,"types":[]},{"text":"impl Freeze for ExporterError","synthetic":true,"types":[]},{"text":"impl Freeze for PskError","synthetic":true,"types":[]},{"text":"impl Freeze for ManagedGroupCallbacks","synthetic":true,"types":[]},{"text":"impl Freeze for HandshakeMessageFormat","synthetic":true,"types":[]},{"text":"impl Freeze for ManagedGroupConfig","synthetic":true,"types":[]},{"text":"impl Freeze for UpdatePolicy","synthetic":true,"types":[]},{"text":"impl Freeze for ManagedGroupError","synthetic":true,"types":[]},{"text":"impl Freeze for EmptyInputError","synthetic":true,"types":[]},{"text":"impl Freeze for UseAfterEviction","synthetic":true,"types":[]},{"text":"impl Freeze for PendingProposalsError","synthetic":true,"types":[]},{"text":"impl Freeze for InvalidMessageError","synthetic":true,"types":[]},{"text":"impl Freeze for GroupEvent","synthetic":true,"types":[]},{"text":"impl Freeze for MemberAddedEvent","synthetic":true,"types":[]},{"text":"impl Freeze for MemberRemovedEvent","synthetic":true,"types":[]},{"text":"impl Freeze for MemberUpdatedEvent","synthetic":true,"types":[]},{"text":"impl Freeze for PskReceivedEvent","synthetic":true,"types":[]},{"text":"impl Freeze for ReInitEvent","synthetic":true,"types":[]},{"text":"impl Freeze for ApplicationMessageEvent","synthetic":true,"types":[]},{"text":"impl Freeze for InvalidMessageEvent","synthetic":true,"types":[]},{"text":"impl Freeze for ErrorEvent","synthetic":true,"types":[]},{"text":"impl Freeze for Removal","synthetic":true,"types":[]},{"text":"impl Freeze for ResumptionSecretStore","synthetic":true,"types":[]},{"text":"impl !Freeze for SerializedManagedGroup","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Freeze for ManagedGroup&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for MLSMessage","synthetic":true,"types":[]},{"text":"impl Freeze for PlaintextSecret","synthetic":true,"types":[]},{"text":"impl !Freeze for MlsGroup","synthetic":true,"types":[]},{"text":"impl Freeze for TranscriptTestVector","synthetic":true,"types":[]},{"text":"impl Freeze for TranscriptTestVectorError","synthetic":true,"types":[]},{"text":"impl Freeze for GroupId","synthetic":true,"types":[]},{"text":"impl Freeze for GroupEpoch","synthetic":true,"types":[]},{"text":"impl Freeze for GroupContext","synthetic":true,"types":[]},{"text":"impl Freeze for GroupConfig","synthetic":true,"types":[]},{"text":"impl Freeze for KeyPackageError","synthetic":true,"types":[]},{"text":"impl Freeze for KeyPackage","synthetic":true,"types":[]},{"text":"impl Freeze for KeyPackageBundle","synthetic":true,"types":[]},{"text":"impl Freeze for ProposalQueueError","synthetic":true,"types":[]},{"text":"impl Freeze for ProposalOrRefTypeError","synthetic":true,"types":[]},{"text":"impl Freeze for QueuedProposalError","synthetic":true,"types":[]},{"text":"impl Freeze for ProposalType","synthetic":true,"types":[]},{"text":"impl Freeze for ProposalOrRefType","synthetic":true,"types":[]},{"text":"impl Freeze for ProposalOrRef","synthetic":true,"types":[]},{"text":"impl Freeze for Proposal","synthetic":true,"types":[]},{"text":"impl Freeze for ProposalReference","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for QueuedProposal&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for ProposalQueue&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for AddProposal","synthetic":true,"types":[]},{"text":"impl Freeze for UpdateProposal","synthetic":true,"types":[]},{"text":"impl Freeze for RemoveProposal","synthetic":true,"types":[]},{"text":"impl Freeze for PreSharedKeyProposal","synthetic":true,"types":[]},{"text":"impl Freeze for ReInitProposal","synthetic":true,"types":[]},{"text":"impl Freeze for Welcome","synthetic":true,"types":[]},{"text":"impl Freeze for EncryptedGroupSecrets","synthetic":true,"types":[]},{"text":"impl Freeze for Commit","synthetic":true,"types":[]},{"text":"impl Freeze for ConfirmationTag","synthetic":true,"types":[]},{"text":"impl Freeze for GroupInfo","synthetic":true,"types":[]},{"text":"impl Freeze for PathSecret","synthetic":true,"types":[]},{"text":"impl Freeze for GroupSecrets","synthetic":true,"types":[]},{"text":"impl Freeze for PublicGroupState","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for PublicGroupStateTBS&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for ErrorState","synthetic":true,"types":[]},{"text":"impl Freeze for KeyScheduleError","synthetic":true,"types":[]},{"text":"impl Freeze for PskSecretError","synthetic":true,"types":[]},{"text":"impl Freeze for KSTestVectorError","synthetic":true,"types":[]},{"text":"impl Freeze for PSKType","synthetic":true,"types":[]},{"text":"impl Freeze for ExternalPsk","synthetic":true,"types":[]},{"text":"impl Freeze for ExternalPskBundle","synthetic":true,"types":[]},{"text":"impl Freeze for ReinitPsk","synthetic":true,"types":[]},{"text":"impl Freeze for BranchPsk","synthetic":true,"types":[]},{"text":"impl Freeze for Psk","synthetic":true,"types":[]},{"text":"impl Freeze for PreSharedKeyID","synthetic":true,"types":[]},{"text":"impl Freeze for PreSharedKeys","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for PskLabel&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for PskSecret","synthetic":true,"types":[]},{"text":"impl Freeze for Epoch","synthetic":true,"types":[]},{"text":"impl Freeze for KeyScheduleTestVector","synthetic":true,"types":[]},{"text":"impl Freeze for CommitSecret","synthetic":true,"types":[]},{"text":"impl Freeze for InitSecret","synthetic":true,"types":[]},{"text":"impl Freeze for JoinerSecret","synthetic":true,"types":[]},{"text":"impl Freeze for State","synthetic":true,"types":[]},{"text":"impl Freeze for KeySchedule","synthetic":true,"types":[]},{"text":"impl Freeze for IntermediateSecret","synthetic":true,"types":[]},{"text":"impl Freeze for WelcomeSecret","synthetic":true,"types":[]},{"text":"impl Freeze for EpochSecret","synthetic":true,"types":[]},{"text":"impl Freeze for EncryptionSecret","synthetic":true,"types":[]},{"text":"impl Freeze for ExporterSecret","synthetic":true,"types":[]},{"text":"impl Freeze for AuthenticationSecret","synthetic":true,"types":[]},{"text":"impl Freeze for ExternalSecret","synthetic":true,"types":[]},{"text":"impl Freeze for ConfirmationKey","synthetic":true,"types":[]},{"text":"impl Freeze for MembershipKey","synthetic":true,"types":[]},{"text":"impl Freeze for ResumptionSecret","synthetic":true,"types":[]},{"text":"impl Freeze for SenderDataSecret","synthetic":true,"types":[]},{"text":"impl !Freeze for EpochSecrets","synthetic":true,"types":[]},{"text":"impl Freeze for TreeError","synthetic":true,"types":[]},{"text":"impl Freeze for ParentHashError","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for ParentHashInput&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for LeafNodeHashInput&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for ParentNodeTreeHashInput&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for NodeIndex","synthetic":true,"types":[]},{"text":"impl Freeze for LeafIndex","synthetic":true,"types":[]},{"text":"impl Freeze for NodeType","synthetic":true,"types":[]},{"text":"impl Freeze for Node","synthetic":true,"types":[]},{"text":"impl Freeze for ParentNode","synthetic":true,"types":[]},{"text":"impl Freeze for PathKeys","synthetic":true,"types":[]},{"text":"impl Freeze for PrivateTree","synthetic":true,"types":[]},{"text":"impl Freeze for SecretTreeError","synthetic":true,"types":[]},{"text":"impl Freeze for SecretType","synthetic":true,"types":[]},{"text":"impl Freeze for TreeContext","synthetic":true,"types":[]},{"text":"impl Freeze for SecretTreeNode","synthetic":true,"types":[]},{"text":"impl Freeze for SecretTree","synthetic":true,"types":[]},{"text":"impl Freeze for SenderRatchet","synthetic":true,"types":[]},{"text":"impl Freeze for TreeMathError","synthetic":true,"types":[]},{"text":"impl Freeze for SenderDataInfo","synthetic":true,"types":[]},{"text":"impl Freeze for RatchetStep","synthetic":true,"types":[]},{"text":"impl Freeze for LeafSequence","synthetic":true,"types":[]},{"text":"impl Freeze for EncryptionTestVector","synthetic":true,"types":[]},{"text":"impl Freeze for EncTestVectorError","synthetic":true,"types":[]},{"text":"impl Freeze for TreeMathTestVector","synthetic":true,"types":[]},{"text":"impl Freeze for TMTestVectorError","synthetic":true,"types":[]},{"text":"impl Freeze for RatchetTree","synthetic":true,"types":[]},{"text":"impl Freeze for ApplyProposalsValues","synthetic":true,"types":[]},{"text":"impl Freeze for UpdatePathNode","synthetic":true,"types":[]},{"text":"impl Freeze for UpdatePath","synthetic":true,"types":[]}];
implementors["test_macros"] = [{"text":"impl Freeze for TestInput","synthetic":true,"types":[]}];
implementors["tls_codec"] = [{"text":"impl&lt;T&gt; Freeze for TlsVecU8&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Freeze for TlsVecU16&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Freeze for TlsVecU32&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for Error","synthetic":true,"types":[]},{"text":"impl !Freeze for Cursor","synthetic":true,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()