// src/program.rs

use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::address::Address;
use crate::error::Error;

/// Size of a Falcon public key in bytes.
pub const PUBKEY_SIZE: usize = 1793;

/// Size of the FalconVerifier AVM bytecode in bytes.
pub const BYTECODE_SIZE: usize = 1805;

/// A FalconVerifier LogicSig.
///
/// Field names mirror the Algorand wire format:
/// 
/// * `l` (the AVM bytecode) maps to `lsig.l`
/// *  `arg` (the Falcon compressed signature) maps to `lsig.arg[0]`
/// 
/// The delegation fields (`sig`, `msig`, `lmsig`)
/// are not relevant here — a FalconVerifier account is its own authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicSig {
    /// Takes `AVM bytecode` representing a program's logic.
    /// Maps to `lsig.l` in the Algorand wire format.
    l: [u8; BYTECODE_SIZE],
    /// Takes a Falcon compressed signature over the transaction ID as bytes.
    /// Maps to `lsig.arg[0]` in the Algorand wire format.
    arg: Box<[u8]>,
}

impl LogicSig {
    /// Returns `self` AVM bytecode. Maps to `lsig.l` in the Algorand wire format.
    pub fn l(&self) -> &[u8; BYTECODE_SIZE] {
        &self.l
    }

    /// Returns `self` compressed Falcon signature. Maps to `lsig.arg[0]` in the Algorand wire format.
    pub fn arg(&self) -> &[u8] {
        &self.arg
    }
}

/// A FalconVerifier program.
///
/// The AVM bytecode format:
///
/// ```text
/// offset    bytes        instruction
///      0    0c           #pragma version 12
///    1-4    26 01 01 XX  bytecblock XX (XX = counter byte, offset 4)
///    5-6    31 17        txn TxID
///      7    2d           arg 0
///   8-10    80 81 0e     pushbytes (1793-byte length prefix)
///  11-1803  [pubkey]     Falcon-1024 pubkey
///   1804    85           falcon_verify
/// ```
///
/// The counter at offset 4 is incremented until the derived address is not a valid
/// Ed25519 curve point, ensuring no Ed25519 private key can authorize transactions
/// from this account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program([u8; BYTECODE_SIZE]);

impl Program {
    /// Compiles FalconVerifier AVM bytecode with an embedded Falcon public key.
    ///
    /// Assembles the bytecode, then iterates counters 0–255 until the derived
    /// address is **not** a valid Ed25519 curve point.
    /// Returns `Err(Error::NoSafeAddress)` if all 256 attempts fail.
    pub fn compile(pubkey: &[u8; PUBKEY_SIZE]) -> Result<Self, Error> {
        // Create 1805-byte mutable buffer and assemble the program
        let mut p = [0u8; BYTECODE_SIZE];
        p[0] = 0x0c;
        p[1..5].copy_from_slice(&[0x26, 0x01, 0x01, 0x00]);
        p[5..7].copy_from_slice(&[0x31, 0x17]);
        p[7] = 0x2d;
        p[8..11].copy_from_slice(&[0x80, 0x81, 0x0e]);
        p[11..1804].copy_from_slice(pubkey);
        p[1804] = 0x85;

        // Loop through u8 range
        for counter in 0..=255 {
            // Add counter value to program at index 4
            p[4] = counter;
            
            // Derive the program address from bytecode
            let addr = Address::from_bytecode(&p);

            // Return Ok if address bytes are not a valid ed25519 curve point
            if CompressedEdwardsY(*addr.as_bytes()).decompress().is_none() {
                return Ok(Self(p));
            }
        }
        // Throw error if no safe address
        Err(Error::NoSafeAddress)
    }

    /// Returns the underlying AVM bytecode.
    pub fn as_bytes(&self) -> &[u8; BYTECODE_SIZE] {
        &self.0
    }

    /// Returns the 32-byte [`Address`] derived from the underlying AVM bytecode.
    pub fn address(&self) -> Address {
        Address::from_bytecode(&self.0)
    }

    /// Bundles the AVM bytecode with a Falcon signature into a [`LogicSig`] 
    ///
    /// `sig` - is not part of the bytecode itself but
    /// represents a runtime argument passed alongside the program.
    /// It must be a Falcon signature in compressed format 
    /// produced over the transaction ID as the data.
    /// 
    /// The [`LogicSig`] must be added into the `lsig` field of an Algorand signed 
    /// transaction in order to make this program the signing authority and sender.
    /// After that, anyone can attempt to submit the signed transaction to the network,
    /// which will be succeed if the program evalutes to `true`
    /// (finishes with a single non-zero `u64` value on the stack).
    pub fn to_lsig(&self, sig: &[u8]) -> LogicSig {
        LogicSig {
            l: self.0,
            arg: sig.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_PUBKEY: &[u8; PUBKEY_SIZE] = &[0u8; PUBKEY_SIZE];

    fn build_bytecode(pubkey: &[u8; PUBKEY_SIZE], counter: u8) -> [u8; BYTECODE_SIZE] {
        let mut p = [0u8; BYTECODE_SIZE];
        p[0] = 0x0c;
        p[1..5].copy_from_slice(&[0x26, 0x01, 0x01, counter]);
        p[5..7].copy_from_slice(&[0x31, 0x17]);
        p[7] = 0x2d;
        p[8..11].copy_from_slice(&[0x80, 0x81, 0x0e]);
        p[11..1804].copy_from_slice(pubkey);
        p[1804] = 0x85;
        p
    }

    #[test]
    fn bytecode_length() {
        assert_eq!(build_bytecode(ZERO_PUBKEY, 0).len(), BYTECODE_SIZE);
    }

    #[test]
    fn bytecode_structure() {
        let bytecode = build_bytecode(ZERO_PUBKEY, 0x42);
        assert_eq!(bytecode[0], 0x0c);                              // version 12
        assert_eq!(bytecode[4], 0x42);                              // counter
        assert_eq!(&bytecode[5..7], &[0x31, 0x17]);                // txn TxID
        assert_eq!(bytecode[7], 0x2d);                              // arg 0
        assert_eq!(&bytecode[8..11], &[0x80, 0x81, 0x0e]);         // pushbytes prefix
        assert_eq!(&bytecode[11..1804], ZERO_PUBKEY.as_slice());    // pubkey
        assert_eq!(bytecode[1804], 0x85);                           // falcon_verify
    }

    #[test]
    fn counter_affects_only_offset_4() {
        let b0 = build_bytecode(ZERO_PUBKEY, 0x00);
        let b1 = build_bytecode(ZERO_PUBKEY, 0x01);
        assert_ne!(b0, b1);
        assert_eq!(b0[4], 0x00);
        assert_eq!(b1[4], 0x01);
        assert_eq!(&b0[..4], &b1[..4]);
        assert_eq!(&b0[5..], &b1[5..]);
    }

    #[test]
    fn address_is_deterministic() {
        let bytecode = build_bytecode(ZERO_PUBKEY, 0);
        assert_eq!(Address::from_bytecode(&bytecode), Address::from_bytecode(&bytecode));
    }

    #[test]
    fn different_pubkeys_give_different_addresses() {
        let mut other_pubkey = [0u8; PUBKEY_SIZE];
        other_pubkey[0] = 0x01;
        let addr1 = Address::from_bytecode(&build_bytecode(ZERO_PUBKEY, 0));
        let addr2 = Address::from_bytecode(&build_bytecode(&other_pubkey, 0));
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn to_lsig_attaches_sig() {
        let program = Program(build_bytecode(ZERO_PUBKEY, 0));
        let fake_sig = vec![0xAB, 0xCD, 0xEF];
        let lsig = program.to_lsig(&fake_sig);
        assert_eq!(lsig.l(), program.as_bytes());
        assert_eq!(lsig.arg(), fake_sig.as_slice());
    }
}
