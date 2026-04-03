// src/error.rs

#[derive(Debug)]
pub enum Error {
    /// All 256 counter values produced a valid Ed25519 curve point.
    /// Vanishingly unlikely in practice (probability ≈ 2^-256).
    NoValidCounter,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoValidCounter => f.write_str(
                "all 256 counter values yield a valid Ed25519 address; key is unsuitable",
            ),
        }
    }
}

impl std::error::Error for Error {}
