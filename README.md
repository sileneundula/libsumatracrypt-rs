# libsumatracrypt-rs

[![Crates.io Version](https://img.shields.io/crates/v/libsumatracrypt-rs?style=flat-square)](https://crates.io/crates/libsumatracrypt-rs)
[![docs.rs](https://img.shields.io/docsrs/libsumatracrypt-rs)](https://docs.rs/libsumatracrypt-rs/latest/libsumatracrypt_rs/)
![Crates.io License](https://img.shields.io/crates/l/libsumatracrypt-rs?style=flat-square)
![Crates.io Total Downloads](https://img.shields.io/crates/d/libsumatracrypt-rs?style=flat-square)
| ![Discord](https://img.shields.io/discord/1261440665821253632?style=flat-square&logo=Discord)






`libsumatracrypt-rs` is an **Open-Source Cryptography Library** written in pure-rust that is **Strictly-and-Inherently-Secure-By-Design**, has **Ease of Access**, has **Strong Documentation**, and offers extensions of **Advanced Cryptography** while maintaining a simple-to-use interface. It uses the `Sumatracrypt-Standardized-API-Model` to offer an easy-to-use API interface that is hard to blunder by design. It has loads of documentation detailing out certain design choices, how it works under-the-hood, among other things. It is:

* easy-to-use

* pure-rust (so memory-safe)

* lightweight

* **strictly secure by design** with a hard focus made on security (including side-channel attacks and advanced adversaries)

* **minimalistic**, with minimal dependecies and optional dependecies

* has **standardized API** known as `Sumatracrypt-Standardized-API-Model`

* has a *substancial* amount of documentation, community-talk, and deep-dives into the code

* has **extensions** that use **Advanced Cryptography** (like Zero-Knowledge Proofs, Homomorphic Encryption, Post-Quantum Cryptography, Verifiable Random Functions, Verifiable Delay Functions) with **Standardized API** known as `sumatracryptadvanced-standardized-api`

## Purpose

### General

The purpose of `libsumatracrypt-rs` is to make a lightweight, pure-rust, cryptography library available to more people with **security at its core** (defending against even the most advanced attacks, like side-channel attacks) while maintaing **ease-of-access** and **easy-to-use API**, even against advanced attackers.

It also wants to offer easy usage of more advanced cryptographic algorithms like **Zero-Knowledge Proofs**, **Homomorphic Encryption**, and **Post-Quantum Cryptography** to the general public with simple front-facing API.

### Developers

The idea of development for future developers/contributors for `libsumatracrypt-rs` is to remain:

* **Easy-To-Use** with a **simple interface** and **Standardized API** using `Sumatra-Standardized-API`.
* **Lightweight** with **minimal dependecies** (and for these dependecies to be later audited or forked)
* Have a **hard focus on security** (against side-channel attacks, timing-attacks, and advanced adversaries)
* **Stay minimal in dependecies** and **fork projects when ready**
* **Audit Specific Portions of the library one at a time**
* **Make dependecies optional**
* Make it **stupid hard** for the general user to misconfigure or have issues with keeping secure.

`libsumatracrypt-rs` also boasts lots of documentation, lots of useful information for developers to use, constant talk around different mechanisms, and constant updates. Its goal is to fork other projects over-time and make sure all the code is secure and useful.

It also is meant to combat **side-channel attacks** and **remain constant-time**.

## How `libsumatracrypt-rs` Is Designed?

Every piece of the code is looked at carefully and newer features are added in as time goes on. It is **well-maintained** and it focuses on `getting it right the first time`. It will be developed over a long period for optimal security against advanced attackers. It will also have easy to use API.

## Purpose and Problems Addressed by libsumatracrypt-rs

#### Basic Format

As for now, all types are stored as `String` in usually hexadecimal-encoding

### Format
- [X] Minimalistic and Easy To Use API
- [X] Uses Basic Encoding of `String` By Default Using **Hexadecimal/Base32/Base58** and PKCS#8 (working on changing)
- [X] All `PublicKeys`, `SecretKeys`, `Ciphertexts`, `DecodedMessages`, `Signatures`, `Digests`, and more have their own **type** with useful methods and security features built-in.

### Side-Channel Security
- [X] All structs use `Zeroize/ZeroizeOnDrop` for **protection against stealing secrets (and some non-sensitive data is still zeroized for privacy) from memory after usage**. [[MITRE:T1212]](https://attack.mitre.org/techniques/T1212/)
- [X] All verification is done using `Subtle` for **constant-time cryptography** to protect against timing attacks. | [A Beginners Guide To Constant Time](https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html)

### General Security
- [X] Protection Against **Downgrading-Attacks** [(MITRE:T1562.010)](https://attack.mitre.org/techniques/T1562/010/) by not having any insecure protocols/algorithms by default.




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

## Hash Functions

- [X] SHA2 (SHA224,SHA256,SHA384,SHA512)
- [X] 
