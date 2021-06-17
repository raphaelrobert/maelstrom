use crate::config::{Config, ProtocolVersion};
use crate::extensions::*;
use crate::key_packages::*;

impl Codec for KeyPackage {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.extend_from_slice(&self.encoded);
        self.signature.encode(buffer)?;
        Ok(())
    }
}

impl tls_codec::TlsSize for KeyPackage {
    #[inline]
    fn serialized_len(&self) -> usize {
        self.encoded.len() + self.signature.serialized_len()
    }
}

impl tls_codec::Serialize for KeyPackage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<(), tls_codec::Error> {
        writer.write_all(&self.encoded)?;
        self.signature.tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for KeyPackage {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let protocol_version = ProtocolVersion::tls_deserialize(bytes)?;
        let cipher_suite_name = CiphersuiteName::tls_deserialize(bytes)?;
        let hpke_init_key = HpkePublicKey::tls_deserialize(bytes)?;
        let credential = Credential::tls_deserialize(bytes)?;
        let extensions = extensions_vec_from_reader(bytes)?;
        let signature = Signature::tls_deserialize(bytes)?;
        let payload = KeyPackagePayload {
            protocol_version,
            ciphersuite: Config::ciphersuite(cipher_suite_name).map_err(|e| {
                tls_codec::Error::DecodingError(format!("Invalid cipher suite {:?}", e))
            })?,
            hpke_init_key,
            credential,
            extensions,
        };
        let encoded = payload.unsigned_payload().map_err(|e| {
            tls_codec::Error::DecodingError(format!("Error serializing the payload {:?}", e))
        })?;
        let kp = KeyPackage {
            payload,
            signature,
            encoded,
        };

        if kp.verify().is_err() {
            let msg = format!("Error verifying a key package after decoding\n{:?}", kp);
            log::error!("{}", msg);
            return Err(tls_codec::Error::DecodingError(msg));
        }
        Ok(kp)
    }
}
