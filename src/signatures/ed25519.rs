use crate::csprng::SumatraCSPRNG;

use serde::{Serialize,Deserialize};

use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signature;
use ed25519_dalek::*;

use zeroize::*;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SumatraED25519;

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ED25519PublicKey(String);
#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ED25519SecretKey(String);
#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ED25519Signature(String);

impl SumatraED25519 {
    pub fn new() -> ED25519SecretKey {        
        let csprng = SumatraCSPRNG::new_32();

        let sk = SigningKey::from_bytes(&csprng);

        return ED25519SecretKey(hex::encode_upper(sk.as_bytes()));
        
    }
    pub fn verify<T: AsRef<[u8]>>(pk: ED25519PublicKey, bytes: T, signature: ED25519Signature) -> bool {
        let vk = pk.decode_from_hex();
        let sig = signature.decode_from_hex();

        let is_valid = vk.verify_strict(bytes.as_ref(), &sig);

        if is_valid.is_ok() {
            return true
        }
        else {
            return false
        }
    }
}

impl ED25519SecretKey {
    pub fn new(key: [u8;32]) -> Self {
        Self(hex::encode_upper(ed25519_dalek::SigningKey::from_bytes(&key).as_bytes()))
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
    pub fn to_string(&self) -> String {
        self.0.clone()
    }
}