use crate::csprng::SumatraCSPRNG;

use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signature;
use ed25519_dalek::*;

pub struct SumatraED25519;

pub struct ED25519PublicKey(String);
pub struct ED25519SecretKey(String);

pub struct ED25519Signature(String);

impl SumatraED25519 {
    pub fn new() -> ED25519SecretKey {        
        let csprng = SumatraCSPRNG::new_32();

        let sk = SigningKey::from_bytes(&csprng);

        return ED25519SecretKey(hex::encode_upper(sk.as_bytes()));
        
    }
}

impl ED25519SecretKey {
    pub fn new(key: [u8;32]) -> Self {
        Self(hex::encode_upper(ed25519_dalek::SigningKey::from_bytes(&key).as_bytes()))
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
}
