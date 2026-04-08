// src/lib.rs

mod address;
mod constants;
mod error;
mod program;

pub use {
    address::Address,
    constants::{
        ED25519_PUBKEY_SIZE, ED25519_SIG_SIZE, FALCON_BYTECODE_SIZE,
        FALCON_PUBKEY_SIZE, HYBRID_BYTECODE_SIZE
    },
    error::Error,
    program::{
        FalconTxnSignerLogicSig, FalconTxnSigner,
        HybridTxnSignerLogicSig, HybridTxnSigner
    }
};