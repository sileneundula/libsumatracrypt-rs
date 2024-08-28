# libsumatracrypt-rs

[![Crates.io Version](https://img.shields.io/crates/v/libsumatracrypt-rs?style=flat-square)](https://crates.io/crates/libsumatracrypt-rs)
[![docs.rs](https://img.shields.io/docsrs/libsumatracrypt-rs)](https://docs.rs/libsumatracrypt-rs/latest/libsumatracrypt_rs/)
![Crates.io License](https://img.shields.io/crates/l/libsumatracrypt-rs?style=flat-square)
![Crates.io Total Downloads](https://img.shields.io/crates/d/libsumatracrypt-rs?style=flat-square)
| ![Discord](https://img.shields.io/discord/1261440665821253632?style=flat-square&logo=Discord)

`libsumatracrypt-rs` is an **open-source cryptography library** written in pure-rust that is **strictly-and-inherently secure-by-design**, has **ease of access**, has **strong documentation**, and offers extensions of **advanced cryptography** (Zero-Knowledge Proofs, Homomorphic Encryption, Post-Quantum Cryptography) while maintaining a simple-to-use interface. It uses the `Sumatracrypt-Standardized-API-Model` to offer an easy-to-use API interface that is hard to blunder by design. It has loads of documentation detailing out certain design choices, how it works under-the-hood, among other things.

It currently **has the following cryptographic protocols implemented**:

### Public-Key Encryption Schemes

* Elliptic Curve Integrated Encryption System (ECIES) using CURVE25519
* RSA4096-OAEP

### Digital Signature Schemes

* ED25519
* Schnorr over Ristretto Compressed Ed25519 points
* ED448 (not implemented yet)

### Key Exchanges

* X448 (on Curve448)

### Hash Functions (Digests)

* SHA1
* SHA2 (SHA2-224,SHA2-256,SHA2-384,SHA2-512)
* BLAKE2B (Variable Length, Supports Keyed-Hash)
* BLAKE3
* SHA3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
* SHAKE256 (512-bits)

### Cryptographically Secure Random Number Generator (CSPRNG)

* a crossplatform `getrandom()` for getting operating system's cryptographically secure pseudorandom number generator (CSPRNG)

## Post-Quantum

### Signatures

* FALCON1024

---

# General

`libsumatracrypt-rs` is:

* Easy-to-use

* Pure-rust (so memory-safe)

* Lightweight

* **Strictly secure by design** with a hard focus made on security (including side-channel attacks and advanced adversaries)

* **Minimalistic**, with minimal dependecies and optional dependecies

* has **standardized API** known as `Sumatracrypt-Standardized-API-Model`

* has a *substancial* amount of documentation, community-talk, and deep-dives into the code

* has **extensions** that use **Advanced Cryptography** (like Zero-Knowledge Proofs, Homomorphic Encryption, Post-Quantum Cryptography, Verifiable Random Functions, Verifiable Delay Functions) with **Standardized API** known as `sumatracryptadvanced-standardized-api`

## Library Purpose

### For General User

The purpose of `libsumatracrypt-rs` is to make a lightweight, pure-rust, cryptography library available to more people with **security at its core** (defending against even the most advanced attacks, like side-channel attacks) while maintaing **ease-of-access** and **easy-to-use API**, even against advanced attackers.

It also wants to offer easy usage of more advanced cryptographic algorithms like **Zero-Knowledge Proofs**, **Homomorphic Encryption**, and **Post-Quantum Cryptography** to the general public with simple front-facing API.

### For Developers

The idea of development for future developers/contributors for `libsumatracrypt-rs` is to remain:

* **Easy-To-Use** with a **simple interface** and **Standardized API** using `Sumatra-Standardized-API-Model`.
* **Lightweight** with **minimal dependecies** (and for these dependecies to be later **audited** and/or later **forked**)
* **Hard Focus on Strict Security** (including measures against side-channel attacks, timing-attacks, and advanced adversaries)
* **Make Dependecies Optional** by *default* and seperate into different crates
* Make it **absurdly hard** for the general user to botch (misconfigure, having issues with secrets, other user configuration attacks)
* Have *substancial* documentation and in-depth discussions
* Have **examples** in every crate

#### For Developers (Security)

It also is meant to combat **side-channel attacks** and **remain constant-time**. Other security measures are also desirable.

# General Overview

## Encryption

### ECIES (Curve25519) (Primary)

**Elliptic Curve Integrated Encryption Scheme** (ECIES) on `curve25519-dalek` is chosen as the primary choice for encryption.

### RSA4096-OAEP

**RSA4096-OAEP** uses the pure-rust `rsa` crate. It only gener
 
**PKCS#8 Note:** uses `LF` (`\n`) by default for privacy so no-one can figure out where you generated the key from.

## Hash Functions

* SHA2 (SHA224,SHA256,SHA384,SHA512)
* SHA3 (SHA3-224,SHA3-256,SHA3-384,SHA3-512)
* SHAKE256
* BLAKE2B (Variable Digest)
* BLAKE3

## Digital Signatures

* Schnorr
* ED25519
* RSA4096 (to-do)

# List of Availble Protocols Currently Implemented

## Encryption

- [X] ECIES-Curve25519
- [X] RSA4096-OAEP

### ECIES-CURVE25519

- [X] [Security] Implements `Zeroize/ZeroizeOnDrop` for all structs

### RSA4096

- [X] [Encoding] Implements PEM (PKCS#8)

## Digital Signatures

- [X] Schnorr Signature over CURVE25519
- [X] ED25519

### ED25519

**ED25519** is a cryptographic digital signature algorithm that uses **Curve25519**.

**PublicKey:** 32-bytes (256 bits)

**SecretKey:** 32-bytes (256 bits)

**Signature:** 64 bytes (512 bits)

#### Details

By default, all keys are encoded as a `String` in upper-hexadecimal encoding and will result in `2*x` the size in characters. This means the public key is 64 characters long, the secret key is 64 characters long, and the signature is 128 characters long.



#### Security

- [X] [Security] [Secret-Key-Generation] **Secret Key** comes from **Operating-System CSPRNG** of size 32-bytes as an array.
- [X] [Security] [Zeroize] Implements `Zeroize/ZeroizeOnDrop` for all structs


#### Developer Notes

The structs (`ED25519PublicKey`, `ED25519SecretKey`, `ED25519Signature`) are stored as `String` in **Upper-Hexadecimal Encoding**.

- [X] [Security] **Secret Key** is generated from **32-bytes (256)** of **CSPRNG from operating system** as an `[u8;32]` | `array`

---

# TODO:

## Encryption

### `SumatraEncryptECIES` | **Elliptic Curve Integrated Encryption Scheme (ECIES)** over **Twisted Edwards Curve25519** using **AES-GCM** and **HKDF-SHA256** in pure-rust.
  -  Boasts strong security guarentees, fast speeds, and small key sizes.
  -  **Depends On:** Uses the `ecies-ed25519` crate with the `pure` feature flag.
### `SumatraRSA4096` | **RSA4096** using **Optimal Asymmetric Encryption Padding (OAEP)** in pure-rust.
  - Boasts **strong security** with well-reviewed, classical security arguments against the well-tested RSA algorithm, offering only one key size (the highest key size with the most security).
  - Generation takes around 3-5 minutes for a new RSA4096 key. Good for long-term keys with classical security assumptions.
  - **Depends On:** Uses the audited `rsa` crate

## Digital Signatures

### `SumatraEd25519` | Constant-Time ED25519 Sinature Scheme in pure-rust.

**Ed25519** (view [Website](https://ed25519.cr.yp.to/)) is a cryptographic digital signature scheme that offers **strong security** with protection against various side-channel attacks and branching prediction. It is blazingly fast, offering

`SumatraEd25519` offers strong security through its extensive use of the `ed25519-dalek` crate for ED25519 signatures. These signatures offer **strong security** by remaining constant-time, implementing zeroize, and being less vulnerable to side-channel attacks. It uses Curve25519.


Constant-Time
* Schnorr Signatures

## Hash Functions

- [X] SHA2 (SHA224,SHA256,SHA384,SHA512)
- [X] 
