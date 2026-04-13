# algorand-falcon-lsig

Rust types for constructing Algorand Logic Signature (LogicSig) programs that verify post-quantum **Falcon-1024** signatures on-chain. Two program variants are provided: a Falcon-only signer and a hybrid Falcon + Ed25519 signer.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API and internal derivation parameters are subject to potentially breaking changes.

## Installation

Add the crate to your `Cargo.toml` directly from GitHub. Pinning to a specific commit with `rev` is recommended — the API is subject to potentially breaking changes:

```toml
[dependencies]
algorand-falcon-lsig = { git = "https://github.com/th0tmaker/algorand-falcon-lsig", rev = "<commit-sha>" }
```

Replace `<commit-sha>` with the full commit hash you want to target, e.g. `rev = "a1b2c3d"`.

## Overview

On Algorand, a **Logic Signature** (LogicSig) account is controlled by an AVM program rather than an Ed25519 private key. A transaction is authorized when the program evaluates to `true` (finishes with a single non-zero value on the stack). The account's address is derived deterministically from the program bytecode:

```
address = SHA512/256("Program" || bytecode)
```

This crate compiles AVM bytecode programs that call the `falcon_verify` (and optionally `ed25519verify_bare`) opcodes, embedding the relevant public keys directly into the bytecode. At submission time, the corresponding signatures are passed as runtime `arg` values alongside the program.

The crate currently covers:

- **`FalconTxnSigner`** — compiles AVM bytecode that verifies a Falcon-1024 signature over the transaction ID
- **`HybridTxnSigner`** — compiles AVM bytecode that verifies both a Falcon-1024 signature and an Ed25519 signature over the transaction ID (both must pass)
- **Address derivation** — derives the 32-byte program address from bytecode via SHA512/256
- **Off-curve rejection** — iterates a counter byte (0–255) until the derived address is not a valid Ed25519 curve point, ensuring no Ed25519 private key can control the account

## Program variants

### `FalconTxnSigner`

Compiles a 1805-byte AVM program embedding a Falcon-1024 public key. Authorization requires a valid Falcon compressed signature over the transaction ID.

```
offset    bytes        instruction
     0    0c           #pragma version 12
   1-4    26 01 01 XX  bytecblock XX (XX = counter byte)
   5-6    31 17        txn TxID
     7    2d           arg 0            ← Falcon compressed signature
  8-10    80 81 0e     pushbytes 1793
 11-1803  [pubkey]     Falcon-1024 public key
  1804    85           falcon_verify
```

### `HybridTxnSigner`

Compiles a 1844-byte AVM program embedding both a Falcon-1024 public key and an Ed25519 public key. Authorization requires valid signatures from **both** schemes over the transaction ID.

```
offset      bytes        instruction
     0      0c           #pragma version 12
   1-4      26 01 01 XX  bytecblock XX (XX = counter byte)
   5-6      31 17        txn TxID
     7      2d           arg 0            ← Falcon compressed signature
  8-10      80 81 0e     pushbytes 1793
 11-1803    [1793 bytes] Falcon-1024 public key
  1804      85           falcon_verify
 1805-1806  31 17        txn TxID
  1807      2e           arg 1            ← Ed25519 signature
 1808-1809  80 20        pushbytes 32
 1810-1841  [32 bytes]   Ed25519 public key
  1842      84           ed25519verify_bare
  1843      14           &&
```

## Core API

### Compiling a program

```rust
use algorand_falcon_lsig::{FalconTxnSigner, HybridTxnSigner};

// Falcon-only
let signer = FalconTxnSigner::compile(&falcon_pubkey)?;

// Hybrid (Falcon + Ed25519)
let hybrid = HybridTxnSigner::compile(&falcon_pubkey, &ed25519_pubkey)?;
```

`compile` iterates counter bytes 0–255 until the derived address is not a valid Ed25519 curve point. Returns `Err(Error::CounterExhausted)` if all 256 attempts fail (extremely unlikely in practice).

### Deriving the account address

```rust
let address: Address = signer.address();
println!("{address}"); // base32-encoded Algorand address string

// Fund this address to activate the logic sig account on-chain
```

### Building a LogicSig

Once you have signatures over the transaction ID:

```rust
// Falcon-only
let lsig = signer.to_lsig(&falcon_sig);

// Hybrid
let lsig = hybrid.to_lsig(&falcon_sig, &ed25519_sig);
```

The resulting `FalconTxnSignerLogicSig` / `HybridTxnSignerLogicSig` maps directly to the Algorand wire format `lsig` object:

| Rust field | Wire format |
|---|---|
| `lsig.l()` | `lsig.l` (AVM bytecode) |
| `lsig.falcon_sig()` | `lsig.arg[0]` |
| `lsig.ed25519_sig()` | `lsig.arg[1]` (hybrid only) |

### Parsing an address

`Address` implements `FromStr`. Parsing validates the base32 encoding, the 4-byte checksum, and rejects any address that is a valid Ed25519 curve point:

```rust
use algorand_falcon_lsig::Address;

let addr: Address = "VCMJKWOY5P5POAA53TPWFF6ROMZEGVBKOR3DFR6GH6XKRMCMLE5ZWRFNN".parse()?;
```

### Error handling

All fallible functions return `Result<_, Error>`:

```rust
use algorand_falcon_lsig::Error;

match result {
    Err(Error::CounterExhausted)   => { /* no off-curve address found in 256 attempts */ }
    Err(Error::BadAddressEncoding) => { /* invalid base32 or wrong decoded length */ }
    Err(Error::BadAddressChecksum) => { /* checksum bytes did not match */ }
    Err(Error::Ed25519Address)     => { /* address is a valid Ed25519 public key */ }
    Ok(_) => { /* success */ }
}
```

## Wire format

This crate produces the `lsig` object. To submit a signed transaction to algod (`POST /v2/transactions`), the caller must wrap it in a `SignedTxn` msgpack envelope:

```
SignedTxn (canonical msgpack)
├── "txn"  → unsigned transaction object
└── "lsig" → {
      "l":   lsig.l()
      "arg": [lsig.falcon_sig()]          // Falcon-only
           | [lsig.falcon_sig(),
              lsig.ed25519_sig()]         // Hybrid
    }
```

The `sgnr` (authorizer) field is omitted — the program address is both the sender and the authorizer. The `sig` and `msig` fields must be absent.

## Sizes

| Item | Size |
|---|---|
| Falcon-1024 public key | 1793 bytes |
| Ed25519 public key | 32 bytes |
| Ed25519 signature | 64 bytes |
| `FalconTxnSigner` bytecode | 1805 bytes |
| `HybridTxnSigner` bytecode | 1844 bytes |

## Building

```sh
cargo build
cargo test
```

The minimum supported Rust edition is **2024**.

## License

This crate is MIT licensed. See [LICENSE](LICENSE) for details.
