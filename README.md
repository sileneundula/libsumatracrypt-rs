# libsumatracrypt-rs

`libsumatracrypt-rs` is a cryptography library for simple applications and allows for many operations to be done securely. Its main focus is encryption but is also used for other applications such as hash digests, digital signatures, vrfs, CSPRNGs, among others. It will be extended over-time and act as a library that takes a collection of other crates to create a secure environment that can easily be used for cryptography. It is lightweight and easy to use. Below is some information about the crate. These crates are written in **pure rust** and implement security measures.

## Purpose and Problems Addressed by libsumatracrypt-rs

### Cryptographic Algorithms/Protocols Used In libsumatracrypt-rs

#### 

### Format
- [X] Minimalistic and Easy To Use API
- [X] Uses Basic Encoding of `String` By Default Using **Hexadecimal/Base32/Base58** and PKCS#8 (working on changing)
- [X] All `PublicKeys`, `SecretKeys`, `Ciphertexts`, `DecodedMessages`, `Signatures`, `Digests`, and more have their own **type** with useful methods and security features built-in.

### Side-Channel Security
- [X] All structs use `Zeroize/ZeroizeOnDrop` for **protection against stealing secrets (and some non-sensitive data is still zeroized for privacy) from memory after usage**. [[MITRE:T1212]](https://attack.mitre.org/techniques/T1212/)
- [X] All verification is done using `Subtle` for **constant-time cryptography** to protect against timing attacks. | [A Beginners Guide To Constant Time](https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html)

### General Security
- [X] Protection Against **Downgrading-Attacks** [(MITRE:T1562.010)](https://attack.mitre.org/techniques/T1562/010/) by not having any insecure protocols/algorithms by default.


## Projects That Will Be Using It:

* **sumatracrypt**
* **sumatracrypt-base** (GUI)

## Binaries (will include GUIs and be cross-platform)

* **sumatradigest** (implements various hash functions, and removes insecure ones)
* **sumatraencrypt** (implements ECIES-CURVE25519 and RSA4096 for encryption)
* **sumatrasign** (implements ED25519, Schnorr over Curve25519, and ED448)
* **sumatracsprng** (CSPRNG from operating system with simple usage and security)

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
