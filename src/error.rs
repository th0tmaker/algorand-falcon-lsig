// src/error.rs

#[derive(Debug)]
pub enum Error {
    /// All 256 counter values were exhausted without finding a safe address that is not a
    /// valid Ed25519 curve point. Try using a different Falcon key.
    NoSafeAddress,
}

impl std::fmt::Display for Error {
    /// Formats self variants into a human-readable strings
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSafeAddress => f.write_str(
                "all counter values were exhausted without finding a safe address \
                that is not a valid Ed25519 curve point. try using a different Falcon key.",
            ),
        }
    }
}

impl std::error::Error for Error {}
