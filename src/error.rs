// src/error.rs

#[derive(Debug)]
pub enum Error {
    /// Counter exhausted with no off-curve address found. Try a different Falcon key.
    CounterExhausted,
    /// Address is not valid base32 or decodes to the wrong length.
    InvalidAddressEncoding,
    /// Address checksum mismatch.
    InvalidAddressChecksum,
    /// Address is a valid Ed25519 public key and may have a corresponding private key.
    Ed25519CurvePoint,
    /// Falcon signature is empty or exceeds the maximum compressed size of 1423 bytes.
    InvalidSignatureSize,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CounterExhausted => f.write_str("counter exhausted with no off-curve address found; try a different Falcon key."),
            Self::InvalidAddressEncoding => f.write_str("address is not valid base32 or decodes to the wrong length."),
            Self::InvalidAddressChecksum => f.write_str("address checksum mismatch."),
            Self::Ed25519CurvePoint => f.write_str("address must not be a standard Ed25519 public key that has corresponding private key."),
            Self::InvalidSignatureSize => f.write_str("Falcon signature is empty or exceeds the maximum compressed size of 1423 bytes."),
        }
    }
}

impl core::error::Error for Error {}
