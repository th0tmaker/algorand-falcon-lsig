// src/lsig.rs

use crate::program::FALCON_VERIFY_PROGRAM_SIZE;

/// A Falcon LogicSig ready for submission to the Algorand network.
///
/// Mirrors the Algorand SDK `LogicSig` wire format. For a Falcon contract account:
/// `logic` holds the program bytes and `args[0]` holds the Falcon compressed signature.
/// The `sig`/`msig`/`lmsig` delegation fields are not relevant here — a Falcon
/// contract account is its own authority; no Ed25519 delegation is involved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicSig {
    /// Compiled AVM program bytecode (versioned).
    pub logic: [u8; FALCON_VERIFY_PROGRAM_SIZE],
    /// Falcon compressed signature over the transaction ID.
    /// Maps to `args[0]` in the Algorand wire format.
    pub sig: Box<[u8]>,
}
