use crate::group::*;

#[derive(Clone)]
pub enum HandshakeMessageFormat {
    Plaintext,
    Ciphertext,
}
/// Specifies the configuration parameters for a managed group
#[derive(Clone)]
pub struct ManagedGroupConfig {
    /// Defines whether handshake messages should be encrypted
    pub(crate) handshake_message_format: HandshakeMessageFormat,
    /// Defines the update policy
    pub(crate) update_policy: UpdatePolicy,
    /// Callbacks
    pub(crate) callbacks: ManagedGroupCallbacks,
}

impl ManagedGroupConfig {
    pub fn new(
        handshake_message_format: HandshakeMessageFormat,
        update_policy: UpdatePolicy,
        callbacks: ManagedGroupCallbacks,
    ) -> Self {
        ManagedGroupConfig {
            handshake_message_format,
            update_policy,
            callbacks,
        }
    }
}

/// Specifies in which intervals the own leaf node should be updated
#[derive(Clone)]
pub struct UpdatePolicy {
    /// Maximum time before an update in seconds
    pub(crate) maximum_time: u32,
    /// Maximum messages that are sent before an update in seconds
    pub(crate) maximum_sent_messages: u32,
    /// Maximum messages that are received before an update in seconds
    pub(crate) maximum_received_messages: u32,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        UpdatePolicy {
            maximum_time: 2_592_000, // 30 days in seconds
            maximum_sent_messages: 100,
            maximum_received_messages: 1_000,
        }
    }
}
