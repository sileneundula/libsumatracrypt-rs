# libsumatracrypt-rs

`libsumatracrypt-rs` is a cryptography library for simple applications and allows for many operations to be done securely. Its main focus is encryption but is also used for other applications such as hash digests, digital signatures, vrfs, CSPRNGs, among others. It will be extended over-time and act as a library that takes a collection of other crates to create a secure environment that can easily be used for cryptography.

## Encryption

* ECIES-Curve25519 (Elliptic Curve) (Primary)
* RSA4096

## Hash Functions

* SHA2 (SHA224,SHA256,SHA384,SHA512)
* SHA3 (SHA3-224,SHA3-256,SHA3-384,SHA3-512)
* SHAKE256
* BLAKE2B (Variable Digest)
* BLAKE3

## Digital Signatures

* Schnorr (to-do)
* ED25519
* RSA4096
