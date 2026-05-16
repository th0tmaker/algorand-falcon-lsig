// src/address.rs

use core::{fmt, str::FromStr};

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512_256};

use crate::{constants::ED25519_PUBKEY_SIZE, error::Error};

/// Returns `true` if `bytes` represent a valid Ed25519 public key —
/// i.e. they decompress to a curve point that lies in the prime-order subgroup.
pub(crate) fn is_valid_ed25519_pubkey(bytes: &[u8; ED25519_PUBKEY_SIZE]) -> bool {
    CompressedEdwardsY(*bytes)
        .decompress()
        .map(|p| p.is_torsion_free())
        .unwrap_or(false)
}

/// A 32-byte address acting as a valid Algorand account when funded
///
/// Supports derivation from program bytecode and parsing via [`FromStr`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address([u8; ED25519_PUBKEY_SIZE]);

impl Address {
    /// Derives `self` from `SHA512/256("Program" || bytecode)`
    pub(crate) fn from_bytecode(bytecode: &[u8]) -> Self {
        let mut h = Sha512_256::new();
        h.update(b"Program");
        h.update(bytecode);
        Self(h.finalize().into())
    }

    /// Returns the underlying bytes of `self`.
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBKEY_SIZE] {
        &self.0
    }
}

impl FromStr for Address {
    type Err = Error;

    /// Parses a base32-encoded Algorand address string into an [`Address`].
    ///
    /// Verifies the 4-byte checksum and rejects any address that is a valid Ed25519
    /// curve point, since such an address could belong to a standard Algorand account
    /// with a corresponding private key.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded: [u8; 36] = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
            .and_then(|v| v.try_into().ok())
            .ok_or(Error::InvalidAddressEncoding)?;

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded[..32]);

        let expected = Sha512_256::digest(bytes);

        if decoded[32..] != expected[28..] {
            return Err(Error::InvalidAddressChecksum);
        }

        if is_valid_ed25519_pubkey(&bytes) {
            return Err(Error::Ed25519CurvePoint);
        }

        Ok(Self(bytes))
    }
}

impl fmt::Display for Address {
    /// Formats `self` as `base32(self || checksum)` into a human-readable string,
    /// e.g. `VCMJKWOY5P5POAA53TPWFF6ROMZEGVBKOR3DFR6GH6XKRMCMLE5ZWRFNN`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let checksum = Sha512_256::digest(self.0);
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(&self.0);
        buf[32..].copy_from_slice(&checksum[28..]);
        f.write_str(&base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;

    fn encode_address(bytes: &[u8; ED25519_PUBKEY_SIZE]) -> String {
        let checksum = Sha512_256::digest(bytes);
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(bytes);
        buf[32..].copy_from_slice(&checksum[28..]);
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf)
    }

    #[test]
    fn roundtrip() {
        let addr = Address::from_bytecode(b"test");
        let parsed: Address = addr.to_string().parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn bad_encoding() {
        assert!(matches!("invalid base32".parse::<Address>(), Err(Error::InvalidAddressEncoding)));
    }

    #[test]
    fn wrong_length() {
        let short = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &[0u8; 10]);
        assert!(matches!(short.parse::<Address>(), Err(Error::InvalidAddressEncoding)));
    }

    #[test]
    fn bad_checksum() {
        // 36 zero bytes encodes fine but the checksum won't match
        let s = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &[0u8; 36]);
        assert!(matches!(s.parse::<Address>(), Err(Error::InvalidAddressChecksum)));
    }

    #[test]
    fn ed25519_address_rejected() {
        let bytes = ED25519_BASEPOINT_COMPRESSED.to_bytes();
        let s = encode_address(&bytes);
        assert!(matches!(s.parse::<Address>(), Err(Error::Ed25519CurvePoint)));
    }
}
