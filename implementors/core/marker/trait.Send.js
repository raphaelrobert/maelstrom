(function() {var implementors = {};
implementors["openmls"] = [{"text":"impl Send for ErrorString","synthetic":true,"types":[]},{"text":"impl Send for ErrorPayload","synthetic":true,"types":[]},{"text":"impl Send for HpkeCiphertext","synthetic":true,"types":[]},{"text":"impl Send for KdfLabel","synthetic":true,"types":[]},{"text":"impl Send for Secret","synthetic":true,"types":[]},{"text":"impl Send for AeadKey","synthetic":true,"types":[]},{"text":"impl Send for ReuseGuard","synthetic":true,"types":[]},{"text":"impl Send for AeadNonce","synthetic":true,"types":[]},{"text":"impl Send for Signature","synthetic":true,"types":[]},{"text":"impl Send for SignaturePrivateKey","synthetic":true,"types":[]},{"text":"impl Send for SignaturePublicKey","synthetic":true,"types":[]},{"text":"impl Send for SignatureKeypair","synthetic":true,"types":[]},{"text":"impl !Send for Ciphersuite","synthetic":true,"types":[]},{"text":"impl Send for CiphersuiteName","synthetic":true,"types":[]},{"text":"impl Send for SignatureScheme","synthetic":true,"types":[]},{"text":"impl Send for HKDFError","synthetic":true,"types":[]},{"text":"impl Send for CryptoError","synthetic":true,"types":[]},{"text":"impl Send for Cursor","synthetic":true,"types":[]},{"text":"impl Send for VecSize","synthetic":true,"types":[]},{"text":"impl Send for CodecError","synthetic":true,"types":[]},{"text":"impl Send for CONFIG","synthetic":true,"types":[]},{"text":"impl Send for Constants","synthetic":true,"types":[]},{"text":"impl !Send for PersistentConfig","synthetic":true,"types":[]},{"text":"impl !Send for Config","synthetic":true,"types":[]},{"text":"impl Send for ProtocolVersion","synthetic":true,"types":[]},{"text":"impl Send for ConfigError","synthetic":true,"types":[]},{"text":"impl Send for Certificate","synthetic":true,"types":[]},{"text":"impl Send for Credential","synthetic":true,"types":[]},{"text":"impl Send for BasicCredential","synthetic":true,"types":[]},{"text":"impl Send for CredentialBundle","synthetic":true,"types":[]},{"text":"impl Send for CredentialType","synthetic":true,"types":[]},{"text":"impl Send for MLSCredentialType","synthetic":true,"types":[]},{"text":"impl Send for CredentialError","synthetic":true,"types":[]},{"text":"impl Send for ExtensionStruct","synthetic":true,"types":[]},{"text":"impl Send for ExtensionType","synthetic":true,"types":[]},{"text":"impl Send for CapabilitiesExtension","synthetic":true,"types":[]},{"text":"impl Send for ExtensionError","synthetic":true,"types":[]},{"text":"impl Send for LifetimeExtensionError","synthetic":true,"types":[]},{"text":"impl Send for CapabilitiesExtensionError","synthetic":true,"types":[]},{"text":"impl Send for KeyPackageIdError","synthetic":true,"types":[]},{"text":"impl Send for ParentHashError","synthetic":true,"types":[]},{"text":"impl Send for RatchetTreeError","synthetic":true,"types":[]},{"text":"impl Send for InvalidExtensionError","synthetic":true,"types":[]},{"text":"impl Send for KeyIDExtension","synthetic":true,"types":[]},{"text":"impl Send for LifetimeExtension","synthetic":true,"types":[]},{"text":"impl Send for ParentHashExtension","synthetic":true,"types":[]},{"text":"impl Send for RatchetTreeExtension","synthetic":true,"types":[]},{"text":"impl Send for MLSCiphertext","synthetic":true,"types":[]},{"text":"impl Send for MLSSenderData","synthetic":true,"types":[]},{"text":"impl Send for MLSSenderDataAAD","synthetic":true,"types":[]},{"text":"impl Send for MLSCiphertextContent","synthetic":true,"types":[]},{"text":"impl Send for MLSCiphertextContentAAD","synthetic":true,"types":[]},{"text":"impl Send for MLSPlaintextError","synthetic":true,"types":[]},{"text":"impl Send for MLSCiphertextError","synthetic":true,"types":[]},{"text":"impl Send for VerificationError","synthetic":true,"types":[]},{"text":"impl Send for MLSPlaintext","synthetic":true,"types":[]},{"text":"impl Send for Mac","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for MLSPlaintextTBMPayload&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for MembershipTag","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for MLSPlaintextTBS&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for MLSPlaintextTBSPayload","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for MLSPlaintextCommitContent&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for MLSPlaintextCommitAuthData&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for ContentType","synthetic":true,"types":[]},{"text":"impl Send for MLSPlaintextContentType","synthetic":true,"types":[]},{"text":"impl Send for Sender","synthetic":true,"types":[]},{"text":"impl Send for SenderType","synthetic":true,"types":[]},{"text":"impl Send for ManagedGroupCallbacks","synthetic":true,"types":[]},{"text":"impl Send for ManagedGroupConfig","synthetic":true,"types":[]},{"text":"impl Send for UpdatePolicy","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for ManagedGroup&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for MlsGroup","synthetic":true,"types":[]},{"text":"impl Send for GroupId","synthetic":true,"types":[]},{"text":"impl Send for GroupEpoch","synthetic":true,"types":[]},{"text":"impl Send for GroupContext","synthetic":true,"types":[]},{"text":"impl Send for GroupConfig","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for Removal&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for HandshakeMessageFormat","synthetic":true,"types":[]},{"text":"impl Send for EmptyInputError","synthetic":true,"types":[]},{"text":"impl Send for InvalidMessageError","synthetic":true,"types":[]},{"text":"impl Send for ManagedGroupError","synthetic":true,"types":[]},{"text":"impl Send for PendingProposalsError","synthetic":true,"types":[]},{"text":"impl Send for UseAfterEviction","synthetic":true,"types":[]},{"text":"impl Send for MLSMessage","synthetic":true,"types":[]},{"text":"impl Send for GroupError","synthetic":true,"types":[]},{"text":"impl Send for WelcomeError","synthetic":true,"types":[]},{"text":"impl Send for ApplyCommitError","synthetic":true,"types":[]},{"text":"impl Send for CreateCommitError","synthetic":true,"types":[]},{"text":"impl Send for ExporterError","synthetic":true,"types":[]},{"text":"impl Send for SerializedManagedGroup","synthetic":true,"types":[]},{"text":"impl Send for PlaintextSecret","synthetic":true,"types":[]},{"text":"impl Send for KeyPackage","synthetic":true,"types":[]},{"text":"impl Send for KeyPackageBundle","synthetic":true,"types":[]},{"text":"impl Send for KeyPackageError","synthetic":true,"types":[]},{"text":"impl Send for Welcome","synthetic":true,"types":[]},{"text":"impl Send for EncryptedGroupSecrets","synthetic":true,"types":[]},{"text":"impl Send for Commit","synthetic":true,"types":[]},{"text":"impl Send for ConfirmationTag","synthetic":true,"types":[]},{"text":"impl Send for GroupInfo","synthetic":true,"types":[]},{"text":"impl Send for PathSecret","synthetic":true,"types":[]},{"text":"impl Send for GroupSecrets","synthetic":true,"types":[]},{"text":"impl Send for PublicGroupState","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for PublicGroupStateTBS&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for ProposalQueueError","synthetic":true,"types":[]},{"text":"impl Send for ProposalOrRefTypeError","synthetic":true,"types":[]},{"text":"impl Send for QueuedProposalError","synthetic":true,"types":[]},{"text":"impl Send for ProposalReference","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for QueuedProposal&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for ProposalQueue&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for AddProposal","synthetic":true,"types":[]},{"text":"impl Send for UpdateProposal","synthetic":true,"types":[]},{"text":"impl Send for RemoveProposal","synthetic":true,"types":[]},{"text":"impl Send for PreSharedKeyProposal","synthetic":true,"types":[]},{"text":"impl Send for ReInitProposal","synthetic":true,"types":[]},{"text":"impl Send for ProposalType","synthetic":true,"types":[]},{"text":"impl Send for ProposalOrRefType","synthetic":true,"types":[]},{"text":"impl Send for ProposalOrRef","synthetic":true,"types":[]},{"text":"impl Send for Proposal","synthetic":true,"types":[]},{"text":"impl Send for CommitSecret","synthetic":true,"types":[]},{"text":"impl Send for InitSecret","synthetic":true,"types":[]},{"text":"impl Send for JoinerSecret","synthetic":true,"types":[]},{"text":"impl Send for KeySchedule","synthetic":true,"types":[]},{"text":"impl Send for IntermediateSecret","synthetic":true,"types":[]},{"text":"impl Send for WelcomeSecret","synthetic":true,"types":[]},{"text":"impl Send for EpochSecret","synthetic":true,"types":[]},{"text":"impl Send for EncryptionSecret","synthetic":true,"types":[]},{"text":"impl Send for ExporterSecret","synthetic":true,"types":[]},{"text":"impl Send for AuthenticationSecret","synthetic":true,"types":[]},{"text":"impl Send for ExternalSecret","synthetic":true,"types":[]},{"text":"impl Send for ConfirmationKey","synthetic":true,"types":[]},{"text":"impl Send for MembershipKey","synthetic":true,"types":[]},{"text":"impl Send for ResumptionSecret","synthetic":true,"types":[]},{"text":"impl Send for SenderDataSecret","synthetic":true,"types":[]},{"text":"impl Send for EpochSecrets","synthetic":true,"types":[]},{"text":"impl Send for State","synthetic":true,"types":[]},{"text":"impl Send for ErrorState","synthetic":true,"types":[]},{"text":"impl Send for KeyScheduleError","synthetic":true,"types":[]},{"text":"impl Send for ExternalPsk","synthetic":true,"types":[]},{"text":"impl Send for ReinitPsk","synthetic":true,"types":[]},{"text":"impl Send for BranchPsk","synthetic":true,"types":[]},{"text":"impl Send for PreSharedKeyID","synthetic":true,"types":[]},{"text":"impl Send for PreSharedKeys","synthetic":true,"types":[]},{"text":"impl Send for PSKType","synthetic":true,"types":[]},{"text":"impl Send for Psk","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for LeafNodeHashInput&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for ParentNodeTreeHashInput&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for RatchetTree","synthetic":true,"types":[]},{"text":"impl Send for ApplyProposalsValues","synthetic":true,"types":[]},{"text":"impl Send for UpdatePathNode","synthetic":true,"types":[]},{"text":"impl Send for UpdatePath","synthetic":true,"types":[]},{"text":"impl Send for TreeError","synthetic":true,"types":[]},{"text":"impl Send for ParentHashError","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for ParentHashInput&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for NodeIndex","synthetic":true,"types":[]},{"text":"impl Send for LeafIndex","synthetic":true,"types":[]},{"text":"impl Send for Node","synthetic":true,"types":[]},{"text":"impl Send for ParentNode","synthetic":true,"types":[]},{"text":"impl Send for NodeType","synthetic":true,"types":[]},{"text":"impl Send for PathKeys","synthetic":true,"types":[]},{"text":"impl Send for PrivateTree","synthetic":true,"types":[]},{"text":"impl Send for TreeContext","synthetic":true,"types":[]},{"text":"impl Send for SecretTreeNode","synthetic":true,"types":[]},{"text":"impl Send for SecretTree","synthetic":true,"types":[]},{"text":"impl Send for SecretTreeError","synthetic":true,"types":[]},{"text":"impl Send for SecretType","synthetic":true,"types":[]},{"text":"impl Send for SenderRatchet","synthetic":true,"types":[]},{"text":"impl Send for TreeMathError","synthetic":true,"types":[]}];
implementors["test_macros"] = [{"text":"impl !Send for TestInput","synthetic":true,"types":[]}];
implementors["tls_codec"] = [{"text":"impl&lt;T&gt; Send for TlsVecU16&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Send for TlsVecU32&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Send for TlsVecU8&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Send for Cursor","synthetic":true,"types":[]},{"text":"impl Send for Error","synthetic":true,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()