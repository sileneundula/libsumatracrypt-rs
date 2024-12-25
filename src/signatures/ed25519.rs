/// # ED25519 (Dalek)
/// 
/// ## Description
/// 
/// Uses ED25519-dalek digital signature scheme.
/// 
/// ## Developer Notes
/// 
/// **Randomness:** Uses 32-bytes of os-csprng to generate key.

use crate::csprng::SumatraCSPRNG;

use serde::{Serialize,Deserialize};

use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signature;
use ed25519_dalek::*;

use bs58;
use base32;

use zeroize::*;

// Built-In Error-Checking
use crate::errors::SumatraCryptErrors;

/// # SumatraED25519 Struct
/// 
/// This struct is used to generate a secret key and to verify signatures.
/// 
/// It includes the methods:
/// 
/// - new()
/// 
/// - verify()
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SumatraED25519;

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ED25519PublicKey(String);
#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ED25519SecretKey(String);
#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ED25519Signature(String);

impl SumatraED25519 {
    /// Generates a new ED25519 Secret Key using 32-bytes of os-csprng from the operating system and encodes into hexadecimal.
    pub fn new() -> ED25519SecretKey {        
        // Generate 32-bytes of OS-CSPRNG
        let csprng = SumatraCSPRNG::new_32();

        // Secrekt Key From Bytes
        let sk = SigningKey::from_bytes(&csprng);

        // Returns Encoded Key
        return ED25519SecretKey(hex::encode_upper(sk.as_bytes()));
        
    }
    /// Verifies an ED25519 Digital Signature using bytes
    pub fn verify<T: AsRef<[u8]>>(pk: ED25519PublicKey, bytes: T, signature: ED25519Signature) -> bool {
        // Verifying Key
        let vk = pk.decode_from_hex();
        
        // Signature
        let sig = signature.decode_from_hex();

        // Verify Strictly The ED25519 Signature
        let is_valid = vk.verify_strict(bytes.as_ref(), &sig);

        // Return Result
        if is_valid.is_ok() {
            return true
        }
        else {
            return false
        }
    }
}

impl ED25519SecretKey {
    /// Signing Key From Bytes
    pub fn new(key: [u8;32]) -> Self {
        Self(hex::encode_upper(ed25519_dalek::SigningKey::from_bytes(&key).as_bytes()))
    }
    /// Generates a new keypair from 32-bytes of OS-CSPRNG
    pub fn generate() -> Self {
        return SumatraED25519::new()
    }
    pub fn from_str<T: AsRef<str>>(pk_hex: T) -> Self {
        return Self(pk_hex.as_ref().to_owned())
    }
    pub fn sign<T: AsRef<[u8]>>(&self, bytes: T) -> ED25519Signature {
        let signingkey = self.decode_from_hex();

        let sig = signingkey.try_sign(bytes.as_ref()).expect("Failed To Sign Message Using ED25519");

        return ED25519Signature(hex::encode_upper(sig.to_bytes()))
    }
    pub fn decode_from_hex(&self) -> ed25519_dalek::SigningKey {
        let mut bytes_array: [u8;32] = [0u8;32];
        
        let bytes = hex::decode(&self.0).expect("Failed To Decode ED25519 From Secret Key");

        for i in 0..bytes.len() {
            bytes_array[i] = bytes[i];
        }

        return SigningKey::from_bytes(&bytes_array)
    }
    pub fn to_public_key(&self) -> ED25519PublicKey {
        return ED25519PublicKey(hex::encode_upper(self.decode_from_hex().verifying_key().as_bytes()));
    }
    // Dangerous
    pub fn to_string(&self) -> String {
        return self.0.clone()
    }
    /// Converts to &str
    pub fn as_str(&self) -> &str {
        return self.0.as_str()
    }
}

impl ED25519PublicKey {
    pub fn new<T: AsRef<str>>(pk_hex: T) -> Self {
        return Self(pk_hex.as_ref().to_string())
    }
    pub fn verify<T: AsRef<[u8]>>(&self, bytes: T, signature: ED25519Signature) -> bool {
        let vk = self.decode_from_hex();
        let sig = signature.decode_from_hex();
        let is_valid = vk.verify_strict(bytes.as_ref(), &sig);

        if is_valid.is_ok() {
            return true
        }
        else {
            return false
        }
    }
    pub fn decode_from_hex(&self) -> VerifyingKey {
        let mut bytes_array: [u8;32] = [0u8;32];
        
        let bytes = hex::decode(&self.0).expect("Failed To Decode");

        for i in 0..bytes.len() {
            bytes_array[i] = bytes[i];
        }

        let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes_array).expect("Failed To Get Verifying Key From Bytes");

        return vk
    }
    pub fn to_string(&self) -> String {
        return self.0.clone()
    }
    pub fn to_base32(&self) -> String {
        let bytes = hex::decode(&self.0).expect("Failed To Convert To Hex");
        let bs32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false },&bytes);
        return bs32
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Self {
        let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s.as_ref()).expect("Failed To Decode Base58");
        return Self(hex::encode_upper(bytes))
    }
}

impl ED25519Signature {
    pub fn decode_from_hex(&self) -> ed25519_dalek::Signature {
        let mut bytes_array: [u8;64] = [0u8;64];

        let bytes = hex::decode(&self.0).expect("Failed To Decode Hex");

        for i in 0..bytes.len() {
            bytes_array[i] = bytes[i];
        }

        return ed25519_dalek::Signature::from_bytes(&bytes_array)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes = hex::decode(&self.0).expect("Failed To Decode From Hex");

        return bytes
    }
    pub fn to_string(&self) -> String {
        self.0.clone()
    }
    pub fn to_base58(&self) -> String {
        let bytes = self.to_bytes();
        let s = bs58::encode(bytes).into_string();

        return s
    }
    pub fn from_base58<T: AsRef<str>>(sig_as_bs58: T) -> Self {
        let s: Vec<u8> = bs58::decode(sig_as_bs58.as_ref()).into_vec().expect("Failed TO Convert To Base58");
        Self(hex::encode_upper(s))
    }
}