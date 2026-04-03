// src/lib.rs

mod error;
mod lsig;
mod program;

pub use error::Error;
pub use lsig::LogicSig;
pub use program::{FalconVerifyProgram, FALCON_DET1024_PUBKEY_SIZE, FALCON_VERIFY_PROGRAM_SIZE};
