use super::*;

impl Codec for ProtocolVersion {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(Self::try_from(u8::decode(cursor)?)?)
    }
}

impl tls_codec::Deserialize for ProtocolVersion {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let val = u8::tls_deserialize(bytes)?;
        Self::try_from(val).map_err(|e| {
            tls_codec::Error::DecodingError(format!(
                "{} is not a valid protocol version: {:?}",
                val, e
            ))
        })
    }
}
