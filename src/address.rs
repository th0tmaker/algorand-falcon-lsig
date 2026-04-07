// src/address.rs

use std::fmt;

use sha2::{Digest, Sha512_256};

use crate::BYTECODE_SIZE;

/// A 32-byte address acting as a valid Algorand account when funded
/// 
/// This type **only** supports address derivation `from_bytecode`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address(pub(crate) [u8; 32]);

impl Address {
    /// Derives `self` from `SHA512/256("Program" || bytecode))`
    pub(crate) fn from_bytecode(bytecode: &[u8; BYTECODE_SIZE]) -> Self {
        let mut h = Sha512_256::new();
        h.update(b"Program");
        h.update(bytecode);
        Self(h.finalize().into())
    }

    /// Returns the underlying bytes of `self`.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Address {
    /// Formats `self` as `base32(self || checksum)` into a human-readable string,
    /// e.g. `VCMJKWOY5P5POAA53TPWFF6ROMZEGVBKOR3DFR6GH6XKRMCMLE5ZWRFNN`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hash bytes of self to derive checksum
        let checksum = Sha512_256::digest(&self.0);
        
        // Create 36-byte mutable buffer (32-byte self + 4-byte checksum)
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(&self.0);
        buf[32..].copy_from_slice(&checksum[28..]);

        // Base32 encode (no padding) into final string
        f.write_str(&base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf))
    }
}
