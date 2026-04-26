// src/error.rs

#[derive(Debug)]
pub enum Error {
    /// Counter exhausted with no off-curve address found. Try a different Falcon key.
    CounterExhausted,
    /// Address is not valid base32 or decodes to the wrong length.
    BadAddressEncoding,
    /// Address checksum mismatch.
    BadAddressChecksum,
    /// Address is a valid Ed25519 public key and may have a corresponding private key.
    Ed25519Address,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CounterExhausted => f.write_str("counter exhausted with no off-curve address found; try a different Falcon key."),
            Self::BadAddressEncoding => f.write_str("address is not valid base32 or decodes to the wrong length."),
            Self::BadAddressChecksum => f.write_str("address checksum mismatch."),
            Self::Ed25519Address => f.write_str("address must not be a standard Ed25519 public key that has corresponding private key."),
        }
    }
}

impl core::error::Error for Error {}
