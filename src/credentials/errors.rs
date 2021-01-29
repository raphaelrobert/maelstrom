use crate::ciphersuite::*;
use crate::config::ConfigError;

implement_error! {
    pub enum CredentialError {
        Simple {
            UnsupportedCredentialType = "Unsupported credential type.",
            InvalidSignature = "Invalid signature.",
        }
        Complex {
            ConfigError(ConfigError) = "See `ConfigError` for details.",
            CryptoError(CryptoError) = "See `CryptoError` for details.",
        }
    }
}
