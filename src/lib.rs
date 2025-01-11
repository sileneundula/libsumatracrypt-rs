/// Asymmetric Public Key Encryption Algorithms including ECIES-CURVE25519 and RSA4096
#[cfg(feature = "encryption")]
pub mod encryption;

/// Hash Functions including SHA2, SHA3, SHAKE256, BLAKE2B, BLAKE3
#[cfg(feature = "digests")]
pub mod digest;

/// Digital Signatures including Ed25519, Schnorr Signatures over Ristretto compressed Ed25519 points, and Ed448
#[cfg(feature = "signatures")]
pub mod signatures;

/// Cryptographically Secure Pseudorandom Number Generator (Using Operating System)
pub mod csprng;

/// Key Exchanges including x448
#[cfg(feature = "dh")]
pub mod dh;

#[cfg(feature = "pq")]
pub mod pq;

/// Symmetric Encryption (CHACHA20,AES)
pub mod sym_encryption;

/// Errors
pub mod errors;

/// BIP39
pub mod bip39;

/// Utilities (A simple interface for encrypting data)
pub mod utils;

pub mod argon2;