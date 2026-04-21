// src/program.rs

use crate::{
    address::{Address, is_valid_ed25519_pubkey}, 
    constants::{ED25519_PUBKEY_SIZE, ED25519_SIG_SIZE, FALCON_BYTECODE_SIZE, FALCON_PUBKEY_SIZE, HYBRID_BYTECODE_SIZE},
    error::Error
};

/// A FalconTxnSigner LogicSig.
///
/// Field names map to the Algorand wire format:
/// 
/// * `l` (the AVM bytecode) maps to `lsig.l`
/// *  `falcon_sig` (the Falcon compressed signature) maps to `lsig.arg[0]`
/// 
/// The delegation fields (`sig`, `msig`, `lmsig`)
/// are not relevant here — a [FalconTxnSignerProgram] account is its own authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FalconTxnSignerLogicSig {
    /// The `AVM bytecode` representing the `FalconTxnSigner` program's logic.
    /// Maps to `lsig.l` in the Algorand wire format.
    l: [u8; FALCON_BYTECODE_SIZE],
    /// The Falcon compressed signature over the transaction ID as bytes.
    /// Maps to `lsig.arg[0]` in the Algorand wire format.
    falcon_sig: Box<[u8]>
}

impl FalconTxnSignerLogicSig {
    /// Returns `self.l`, the AVM bytecode representing the `FalconTxnSigner` program logic.
    /// Maps to `lsig.l` in the Algorand wire format.
    pub fn l(&self) -> &[u8; FALCON_BYTECODE_SIZE] {
        &self.l
    }

    /// Returns `self.falcon_sig`, the compressed Falcon signature.
    /// Maps to `lsig.arg[0]` in the Algorand wire format.
    pub fn falcon_sig(&self) -> &[u8] {
        &self.falcon_sig
    }
}

/// A `FalconTxnSigner` program.
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
pub struct FalconTxnSigner([u8; FALCON_BYTECODE_SIZE]);

impl FalconTxnSigner {
    /// Compiles the `FalconTxnSigner` AVM bytecode with an embedded Falcon public key.
    ///
    /// Assembles the bytecode, then iterates counters 0–255 until the derived
    /// address is **not** a valid Ed25519 curve point.
    /// Returns `Err(Error::CounterExhausted)` if all 256 attempts fail.
    pub fn compile(pubkey: &[u8; FALCON_PUBKEY_SIZE]) -> Result<Self, Error> {
        // Create 1805-byte mutable buffer and assemble the program
        let mut p = [0u8; FALCON_BYTECODE_SIZE];
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
            if !is_valid_ed25519_pubkey(addr.as_bytes()) {
                return Ok(Self(p));
            }
        }
        // Throw error if no safe address
        Err(Error::CounterExhausted)
    }

    /// Returns the underlying AVM bytecode.
    pub fn as_bytes(&self) -> &[u8; FALCON_BYTECODE_SIZE] {
        &self.0
    }

    /// Returns the 32-byte [Address] derived from the underlying AVM bytecode.
    pub fn address(&self) -> Address {
        Address::from_bytecode(&self.0)
    }

    /// Bundles the underlying AVM bytecode as `l` and
    /// the Falcon compressed signature as `arg[0]`
    /// into a [FalconTxnSignerLogicSig]
    ///
    /// `falcon_sig` is not part of the bytecode itself but
    /// represents a runtime argument passed alongside the program.
    /// It must be a valid Falcon signature in compressed format 
    /// produced over the transaction ID as the data.
    /// 
    /// The [FalconTxnSignerLogicSig] must be added into the `lsig` field of an 
    /// Algorand signed transaction in order to make this program the signing authority 
    /// and sender. After that, anyone can attempt to submit the signed transaction
    /// to the network, which will succeed if the program evalutes to `true`
    /// (finishes with a single non-zero `u64` value on the stack).
    pub fn to_lsig(&self, sig: &[u8]) -> FalconTxnSignerLogicSig {
        FalconTxnSignerLogicSig {
            l: self.0,
            falcon_sig: sig.into(),
        }
    }
}

/// A HybridTxnSigner LogicSig.
///
/// Field names map the Algorand wire format:
/// 
/// * `l` (the AVM bytecode) maps to `lsig.l`
/// *  `falcon_sig` (the Falcon compressed signature) maps to `lsig.arg[0]`
/// *  `ed25519_sig` (the Ed25519 signature) maps to `lsig.arg[1]`
/// 
/// The delegation fields (`sig`, `msig`, `lmsig`)
/// are not relevant here — a [HybridTxnSignerProgram] account is its own authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridTxnSignerLogicSig {
    /// The `AVM bytecode` representing the `HybridTxnSigner` program's logic.
    /// Maps to `lsig.l` in the Algorand wire format.
    l: [u8; HYBRID_BYTECODE_SIZE],
    /// The Falcon compressed signature over the transaction ID as bytes.
    /// Maps to `lsig.arg[0]` in the Algorand wire format.
    falcon_sig: Box<[u8]>,
    /// The Ed25519 signature over the transaction ID as bytes.
    /// Maps to `lsig.arg[1]` in the Algorand wire format.
    ed25519_sig: [u8; ED25519_SIG_SIZE]
}

impl HybridTxnSignerLogicSig {
    /// Returns `self.l`, the AVM bytecode representing the `HybridTxnSigner` program logic.
    /// Maps to `lsig.l` in the Algorand wire format.
    pub fn l(&self) -> &[u8; HYBRID_BYTECODE_SIZE] {
        &self.l
    }

    /// Returns `self.falcon_sig`, the compressed Falcon signature.
    /// Maps to `lsig.arg[0]` in the Algorand wire format.
    pub fn falcon_sig(&self) -> &[u8] {
        &self.falcon_sig
    }

    /// Returns `self.ed25519_sig`, the Ed25519 signature.
    /// Maps to `lsig.arg[1]` in the Algorand wire format.
    pub fn ed25519_sig(&self) -> &[u8; ED25519_SIG_SIZE] {
        &self.ed25519_sig
    }
}

/// A `HybridTxnSigner` program.
///
/// The AVM bytecode format:
///
/// ```text
/// offset      bytes        instruction
///      0      0c           #pragma version 12
///    1-3      26 01 01     bytecblock (1 constant, 1 byte long)
///      4      XX           counter byte (XX, found via off-curve rejection loop)
///    5-6      31 17        txn TxID
///      7      2d           arg 0
///   8-10      80 81 0e     pushbytes 1793
///  11-1803    [1793 bytes] Falcon-1024 public key
///   1804      85           falcon_verify()
///
///  1805-1806  31 17        txn TxID
///  1807       2e           arg 1
///  1808-1809  80 20        pushbytes 32
///  1810-1841  [32 bytes]   Ed25519 public key
///  1842       84           ed25519verify_bare()
///
///  1843       14           &&
/// ```
///
/// The counter at offset 4 is incremented until the derived address is not a valid
/// Ed25519 curve point, ensuring no Ed25519 private key can authorize transactions
/// from this account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridTxnSigner([u8; HYBRID_BYTECODE_SIZE]);

impl HybridTxnSigner {
    /// Compiles the `HybridTxnSigner` AVM bytecode with an embedded Falcon public key
    /// and an embedded Ed25519 public key.
    ///
    /// Assembles the bytecode, then iterates counters 0–255 until the derived
    /// address is **not** a valid Ed25519 curve point.
    /// Returns `Err(Error::CounterExhausted)` if all 256 attempts fail.
    pub fn compile(falcon_pubkey: &[u8; FALCON_PUBKEY_SIZE], ed25519_pubkey:&[u8; ED25519_PUBKEY_SIZE]) -> Result<Self, Error> {
        // Create 1844-byte mutable buffer and assemble the program
        let mut p = [0u8; HYBRID_BYTECODE_SIZE];
        p[0] = 0x0c;
        p[1..5].copy_from_slice(&[0x26, 0x01, 0x01, 0x00]);
        p[5..7].copy_from_slice(&[0x31, 0x17]);
        p[7] = 0x2d;
        p[8..11].copy_from_slice(&[0x80, 0x81, 0x0e]);
        p[11..1804].copy_from_slice(falcon_pubkey);
        p[1804] = 0x85;
        p[1805..1807].copy_from_slice(&[0x31, 0x17]);
        p[1807] = 0x2e;
        p[1808..1810].copy_from_slice(&[0x80, 0x20]);
        p[1810..1842].copy_from_slice(ed25519_pubkey);
        p[1842] = 0x84;
        p[1843] = 0x14;

        // Loop through u8 range
        for counter in 0..=255 {
            // Add counter value to program at index 4
            p[4] = counter;
            
            // Derive the program address from bytecode
            let addr = Address::from_bytecode(&p);

            // Return Ok if address bytes are not a valid ed25519 curve point
            if !is_valid_ed25519_pubkey(addr.as_bytes()) {
                return Ok(Self(p));
            }
        }
        // Throw error if no safe address
        Err(Error::CounterExhausted)
    }
    
    /// Returns the underlying AVM bytecode.
    pub fn as_bytes(&self) -> &[u8; HYBRID_BYTECODE_SIZE] {
        &self.0
    }

    /// Returns the 32-byte [Address] derived from the underlying AVM bytecode.
    pub fn address(&self) -> Address {
        Address::from_bytecode(&self.0)
    }

    /// Bundles the underlying AVM bytecode as `l`, the Falcon compressed signature as `arg[0]`
    /// and the Ed25519 signature as `arg[1]` into a [HybridTxnSignerLogicSig]
    /// 
    /// `falcon_sig` and `ed25519_sig` are not part of the bytecode itself but
    /// represent runtime arguments passed alongside the program.
    /// They must be a valid Falcon signature in compressed format,
    /// and a valid Ed25519 signature, produced over the transaction ID as the data.
    /// 
    /// The [HybridTxnSignerLogicSig] must be added into the `lsig` field of an Algorand signed 
    /// transaction in order to make this program the signing authority and sender.
    /// After that, anyone can attempt to submit the signed transaction to the network,
    /// which will succeed if the program evalutes to `true`
    /// (finishes with a single non-zero `u64` value on the stack).
    pub fn to_lsig(
        &self,
        falcon_sig: &[u8],
        ed25519_sig: &[u8; ED25519_SIG_SIZE]
    ) -> HybridTxnSignerLogicSig {
        HybridTxnSignerLogicSig {
            l: self.0,
            falcon_sig: falcon_sig.into(),
            ed25519_sig: *ed25519_sig
        }
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_PUBKEY: &[u8; FALCON_PUBKEY_SIZE] = &[0u8; FALCON_PUBKEY_SIZE];

    fn build_bytecode(pubkey: &[u8; FALCON_PUBKEY_SIZE], counter: u8) -> [u8; FALCON_BYTECODE_SIZE] {
        let mut p = [0u8; FALCON_BYTECODE_SIZE];
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
        assert_eq!(build_bytecode(ZERO_PUBKEY, 0).len(), FALCON_BYTECODE_SIZE);
    }

    #[test]
    fn bytecode_structure() {
        let bytecode = build_bytecode(ZERO_PUBKEY, 0x42);
        assert_eq!(bytecode[0], 0x0c);  // version 12
        assert_eq!(bytecode[4], 0x42);  // counter
        assert_eq!(&bytecode[5..7], &[0x31, 0x17]);  // txn TxID
        assert_eq!(bytecode[7], 0x2d);  // arg 0
        assert_eq!(&bytecode[8..11], &[0x80, 0x81, 0x0e]);  // pushbytes prefix
        assert_eq!(&bytecode[11..1804], ZERO_PUBKEY.as_slice());  // pubkey
        assert_eq!(bytecode[1804], 0x85);  // falcon_verify
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
        let mut other_pubkey = [0u8; FALCON_PUBKEY_SIZE];
        other_pubkey[0] = 0x01;
        let addr1 = Address::from_bytecode(&build_bytecode(ZERO_PUBKEY, 0));
        let addr2 = Address::from_bytecode(&build_bytecode(&other_pubkey, 0));
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn to_lsig_attaches_sig() {
        let program = FalconTxnSigner(build_bytecode(ZERO_PUBKEY, 0));
        let fake_sig = vec![0xAB, 0xCD, 0xEF];
        let lsig = program.to_lsig(&fake_sig);
        assert_eq!(lsig.l(), program.as_bytes());
        assert_eq!(lsig.falcon_sig(), fake_sig.as_slice());
    }

    // --- HybridTxnSignerProgram tests ---

    const ZERO_ED25519_PUBKEY: &[u8; ED25519_PUBKEY_SIZE] = &[0u8; ED25519_PUBKEY_SIZE];

    fn build_hybrid_bytecode(
        falcon_pubkey: &[u8; FALCON_PUBKEY_SIZE],
        ed25519_pubkey: &[u8; ED25519_PUBKEY_SIZE],
        counter: u8,
    ) -> [u8; HYBRID_BYTECODE_SIZE] {
        let mut p = [0u8; HYBRID_BYTECODE_SIZE];
        p[0] = 0x0c;
        p[1..5].copy_from_slice(&[0x26, 0x01, 0x01, counter]);
        p[5..7].copy_from_slice(&[0x31, 0x17]);
        p[7] = 0x2d;
        p[8..11].copy_from_slice(&[0x80, 0x81, 0x0e]);
        p[11..1804].copy_from_slice(falcon_pubkey);
        p[1804] = 0x85;
        p[1805..1807].copy_from_slice(&[0x31, 0x17]);
        p[1807] = 0x2e;
        p[1808..1810].copy_from_slice(&[0x80, 0x20]);
        p[1810..1842].copy_from_slice(ed25519_pubkey);
        p[1842] = 0x84;
        p[1843] = 0x14;
        p
    }

    #[test]
    fn hybrid_bytecode_length() {
        assert_eq!(
            build_hybrid_bytecode(ZERO_PUBKEY, ZERO_ED25519_PUBKEY, 0).len(),
            HYBRID_BYTECODE_SIZE
        );
    }

    #[test]
    fn hybrid_bytecode_structure() {
        let bytecode = build_hybrid_bytecode(ZERO_PUBKEY, ZERO_ED25519_PUBKEY, 0x42);
        assert_eq!(bytecode[0], 0x0c);
        assert_eq!(bytecode[4], 0x42);
        assert_eq!(&bytecode[5..7], &[0x31, 0x17]);
        assert_eq!(bytecode[7], 0x2d);
        assert_eq!(&bytecode[8..11], &[0x80, 0x81, 0x0e]);
        assert_eq!(&bytecode[11..1804], ZERO_PUBKEY.as_slice());
        assert_eq!(bytecode[1804], 0x85);
        assert_eq!(&bytecode[1805..1807], &[0x31, 0x17]);
        assert_eq!(bytecode[1807], 0x2e);
        assert_eq!(&bytecode[1808..1810], &[0x80, 0x20]);
        assert_eq!(&bytecode[1810..1842], ZERO_ED25519_PUBKEY.as_slice());
        assert_eq!(bytecode[1842], 0x84);
        assert_eq!(bytecode[1843], 0x14);
    }

    #[test]
    fn hybrid_different_pubkeys_give_different_addresses() {
        let mut other_falcon = [0u8; FALCON_PUBKEY_SIZE];
        other_falcon[0] = 0x01;
        let addr1 = Address::from_bytecode(&build_hybrid_bytecode(ZERO_PUBKEY, ZERO_ED25519_PUBKEY, 0));
        let addr2 = Address::from_bytecode(&build_hybrid_bytecode(&other_falcon, ZERO_ED25519_PUBKEY, 0));
        assert_ne!(addr1, addr2);

        let mut other_ed25519 = [0u8; ED25519_PUBKEY_SIZE];
        other_ed25519[0] = 0x01;
        let addr3 = Address::from_bytecode(&build_hybrid_bytecode(ZERO_PUBKEY, &other_ed25519, 0));
        assert_ne!(addr1, addr3);
    }

    #[test]
    fn hybrid_to_lsig_attaches_sigs() {
        let program = HybridTxnSigner(build_hybrid_bytecode(ZERO_PUBKEY, ZERO_ED25519_PUBKEY, 0));
        let fake_falcon_sig = vec![0xAB, 0xCD, 0xEF];
        let fake_ed25519_sig = [0x42u8; ED25519_SIG_SIZE];
        let lsig = program.to_lsig(&fake_falcon_sig, &fake_ed25519_sig);
        assert_eq!(lsig.l(), program.as_bytes());
        assert_eq!(lsig.falcon_sig(), fake_falcon_sig.as_slice());
        assert_eq!(lsig.ed25519_sig(), &fake_ed25519_sig);
    }
}
