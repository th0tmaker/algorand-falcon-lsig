// src/program.rs

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512_256};

use crate::{error::Error, lsig::LogicSig};

/// Size of a Falcon det1024 public key in bytes.
pub const FALCON_DET1024_PUBKEY_SIZE: usize = 1793;

/// Size of a `FalconVerifyProgram` in bytes.
///
/// 1 (version) + 4 (bytecblock) + 2 (txn TxID) + 1 (arg 0) + 3 (pushbytes prefix) + 1793 (pubkey) + 1 (falcon_verify)
pub const FALCON_VERIFY_PROGRAM_SIZE: usize = 1805;

/// A Falcon det1024 LogicSig program with the public key embedded.
///
/// The program is always exactly 1805 bytes:
///
/// ```text
/// offset  bytes        instruction
///      0  0c           #pragma version 12
///    1-4  26 01 01 XX  bytecblock XX   (XX = counter byte, offset 4)
///    5-6  31 17        txn TxID
///      7  2d           arg 0
///   8-10  80 81 0e     pushbytes (1793-byte length prefix)
///  11-1803 [pubkey]   Falcon-1024 public key
///   1804  85           falcon_verify
/// ```
///
/// The counter at offset 4 is incremented until the derived address is not a valid
/// Ed25519 curve point, ensuring no Ed25519 private key can authorize transactions
/// from this account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FalconVerifyProgram([u8; FALCON_VERIFY_PROGRAM_SIZE]);

impl FalconVerifyProgram {
    /// Derive a `FalconVerifyProgram` from a Falcon det1024 public key.
    ///
    /// Tries counter values 0–255 and returns the first program whose derived
    /// address is not a valid Ed25519 curve point. Returns `Err(Error::NoValidCounter)`
    /// if all 256 counters fail, which is vanishingly unlikely in practice.
    pub fn derive(pubkey: &[u8; FALCON_DET1024_PUBKEY_SIZE]) -> Result<Self, Error> {
        let mut program = [0u8; FALCON_VERIFY_PROGRAM_SIZE];
        program[0] = 0x0c;
        program[1..5].copy_from_slice(&[0x26, 0x01, 0x01, 0x00]);
        program[5..7].copy_from_slice(&[0x31, 0x17]);
        program[7] = 0x2d;
        program[8..11].copy_from_slice(&[0x80, 0x81, 0x0e]);
        program[11..1804].copy_from_slice(pubkey);
        program[1804] = 0x85;

        for counter in 0u8..=255 {
            program[4] = counter;
            let addr = address_of(&program);
            if CompressedEdwardsY(addr).decompress().is_none() {
                return Ok(Self(program));
            }
        }
        Err(Error::NoValidCounter)
    }

    /// Returns the raw AVM program bytes.
    pub fn as_bytes(&self) -> &[u8; FALCON_VERIFY_PROGRAM_SIZE] {
        &self.0
    }

    /// Derives the on-chain address: `SHA512/256("Program" || program)`.
    ///
    /// Fund this address before submitting any transactions from it.
    pub fn address(&self) -> [u8; 32] {
        address_of(&self.0)
    }

    /// Attach a Falcon signature to produce a `LogicSig` ready for submission.
    ///
    /// `sig` should be the compressed Falcon signature over the transaction ID
    /// (`SHA512/256("TX" || msgpack(txn))`). The caller is responsible for
    /// computing the transaction ID and signing it with the corresponding private key.
    pub fn to_lsig(&self, sig: &[u8]) -> LogicSig {
        LogicSig {
            logic: self.0,
            sig: sig.into(),
        }
    }
}

/// Computes `SHA512/256("Program" || program)` — the Algorand contract account address.
fn address_of(program: &[u8]) -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(b"Program");
    h.update(program);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_PUBKEY: &[u8; FALCON_DET1024_PUBKEY_SIZE] = &[0u8; FALCON_DET1024_PUBKEY_SIZE];

    fn build_program(pubkey: &[u8; FALCON_DET1024_PUBKEY_SIZE], counter: u8) -> [u8; FALCON_VERIFY_PROGRAM_SIZE] {
        let mut p = [0u8; FALCON_VERIFY_PROGRAM_SIZE];
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
    fn program_length() {
        let program = build_program(ZERO_PUBKEY, 0);
        assert_eq!(program.len(), FALCON_VERIFY_PROGRAM_SIZE);
    }

    #[test]
    fn program_structure() {
        let program = build_program(ZERO_PUBKEY, 0x42);
        assert_eq!(program[0], 0x0c);           // version 12
        assert_eq!(program[4], 0x42);           // counter
        assert_eq!(&program[5..7], &[0x31, 0x17]); // txn TxID
        assert_eq!(program[7], 0x2d);           // arg 0
        assert_eq!(&program[8..11], &[0x80, 0x81, 0x0e]); // pushbytes prefix
        assert_eq!(&program[11..1804], ZERO_PUBKEY.as_slice()); // pubkey
        assert_eq!(program[1804], 0x85);        // falcon_verify
    }

    #[test]
    fn counter_affects_only_offset_4() {
        let p0 = build_program(ZERO_PUBKEY, 0x00);
        let p1 = build_program(ZERO_PUBKEY, 0x01);
        assert_ne!(p0, p1);
        assert_eq!(p0[4], 0x00);
        assert_eq!(p1[4], 0x01);
        // Everything else is identical
        assert_eq!(&p0[..4], &p1[..4]);
        assert_eq!(&p0[5..], &p1[5..]);
    }

    #[test]
    fn address_is_32_bytes_and_deterministic() {
        let program = build_program(ZERO_PUBKEY, 0);
        let a1 = address_of(&program);
        let a2 = address_of(&program);
        assert_eq!(a1.len(), 32);
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_pubkeys_give_different_addresses() {
        let mut other_pubkey = [0u8; FALCON_DET1024_PUBKEY_SIZE];
        other_pubkey[0] = 0x01;
        let a1 = address_of(&build_program(ZERO_PUBKEY, 0));
        let a2 = address_of(&build_program(&other_pubkey, 0));
        assert_ne!(a1, a2);
    }

    #[test]
    fn to_lsig_attaches_sig() {
        let lsig = FalconVerifyProgram(build_program(ZERO_PUBKEY, 0));
        let fake_sig = vec![0xAB, 0xCD, 0xEF];
        let auth = lsig.to_lsig(&fake_sig);
        assert_eq!(&auth.logic, lsig.as_bytes());
        assert_eq!(&*auth.sig, fake_sig.as_slice());
    }
}
