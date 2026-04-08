// src/constants.rs

/// Size of a Falcon-1024 public key in bytes.
pub const FALCON_PUBKEY_SIZE: usize = 1793;

/// Size of an Ed25519 public key in bytes.
pub const ED25519_PUBKEY_SIZE: usize = 32;

/// Size of an Ed25519 signature in bytes.
pub const ED25519_SIG_SIZE: usize = 64;

/// Size of the `FalconTxnSigner` AVM bytecode in bytes.
pub const FALCON_BYTECODE_SIZE: usize = 1805;

/// Size of the `HybridTxnSigner` AVM bytecode in bytes.
pub const HYBRID_BYTECODE_SIZE: usize = 1844;
