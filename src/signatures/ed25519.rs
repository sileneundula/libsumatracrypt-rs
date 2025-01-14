/// # ED25519 (Dalek)
/// 
/// ## Description
/// 
/// Uses ED25519-dalek digital signature scheme.
/// 
/// ## Developer Notes
/// 
/// **Randomness:** Uses 32-bytes of os-csprng to generate key.
/// 
/// Added BIP39 From Seed. Must use 32-bytes.

use crate::csprng::SumatraCSPRNG;



use bip39::Language;
use serde::{Serialize,Deserialize};

use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signature;
use ed25519_dalek::*;

use crate::bip39::MnemonicPhrase;

use bs58;
use base32;

use zeroize::*;

// Built-In Error-Checking
use crate::errors::SumatraCryptErrors;
use crate::errors::SumatraCryptEncoding;
use crate::errors::SumatraCryptContext;

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
    pub fn from_seed(seed: [u8;32]) -> ED25519SecretKey {
        let sk = SigningKey::from_bytes(&seed);
        return ED25519SecretKey(hex::encode_upper(sk.as_bytes()));
    }
    /// Verifies an ED25519 Digital Signature using bytes
    pub fn verify<T: AsRef<[u8]>>(pk: ED25519PublicKey, bytes: T, signature: ED25519Signature) -> Result<bool,SumatraCryptErrors> {
        // Verifying Key
        let vk = pk.decode_from_hex()?;
        
        // Signature
        let sig = signature.decode_from_hex()?;

        // Verify Strictly The ED25519 Signature
        let is_valid = vk.verify_strict(bytes.as_ref(), &sig);

        // Return Result
        if is_valid.is_ok() {
            return Ok(true)
        }
        else {
            return Ok(false)
        }
    }
}

impl ED25519SecretKey {
    /// Signing Key From Bytes
    pub fn new(key: [u8;32]) -> Self {
        Self(hex::encode_upper(ed25519_dalek::SigningKey::from_bytes(&key).as_bytes()))
    }
    pub fn from_seed(seed: [u8;32]) -> Self {
        let sk = SigningKey::from_bytes(&seed);
        return Self(hex::encode_upper(sk.as_bytes()))
    }
    /// Generates a new keypair from 32-bytes of OS-CSPRNG
    pub fn generate() -> Self {
        return SumatraED25519::new()
    }
    pub fn from_str<T: AsRef<str>>(pk_hex: T) -> Self {
        return Self(pk_hex.as_ref().to_owned())
    }
    pub fn sign<T: AsRef<[u8]>>(&self, bytes: T) -> Result<ED25519Signature,SumatraCryptErrors> {
        let signingkey = self.decode_from_hex()?;

        let sig = signingkey.try_sign(bytes.as_ref());

        if sig.is_err() {
            return Err(SumatraCryptErrors::InvalidSigning { ctx: crate::errors::SumatraCryptContext::Signature_ED25519 })
        }

        return Ok(ED25519Signature(hex::encode_upper(sig.unwrap().to_bytes())))
    }
    pub fn decode_from_hex(&self) -> Result<ed25519_dalek::SigningKey,SumatraCryptErrors> {
        let mut bytes_array: [u8;32] = [0u8;32];
        
        let bytes = hex::decode(&self.0);

        if bytes.is_err() {
            return Err(SumatraCryptErrors::DecodingError { ctx: SumatraCryptContext::Signature_ED25519})
        }

        let unwrapped_bytes = bytes.unwrap();

        for i in 0..unwrapped_bytes.len() {
            bytes_array[i] = unwrapped_bytes[i];
        }

        return Ok(SigningKey::from_bytes(&bytes_array))
    }
    pub fn to_public_key(&self) -> Result<ED25519PublicKey,SumatraCryptErrors> {
        let key = self.decode_from_hex()?;

        return Ok(ED25519PublicKey(hex::encode_upper(key.verifying_key().as_bytes())));
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
    pub fn verify<T: AsRef<[u8]>>(&self, bytes: T, signature: ED25519Signature) -> Result<bool,SumatraCryptErrors> {
        let vk = self.decode_from_hex()?;
        let sig = signature.decode_from_hex()?;
        let is_valid = vk.verify_strict(bytes.as_ref(), &sig);

        if is_valid.is_ok() {
            return Ok(true)
        }
        else {
            return Ok(false)
        }
    }
    pub fn decode_from_hex(&self) -> Result<VerifyingKey,SumatraCryptErrors> {
        let mut bytes_array: [u8;32] = [0u8;32];
        
        let bytes = hex::decode(&self.0);

        if bytes.is_err() {
            return Err(SumatraCryptErrors::DecodingError { ctx: SumatraCryptContext::Signature_ED25519 })
        }

        let unwrapped_bytes = bytes.unwrap();

        for i in 0..unwrapped_bytes.len() {
            bytes_array[i] = unwrapped_bytes[i];
        }

        let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes_array);

        if vk.is_err() {
            return Err(SumatraCryptErrors::DecodingError { ctx: SumatraCryptContext::Signature_ED25519 })
        }

        return Ok(vk.unwrap())
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
    pub fn decode_from_hex(&self) -> Result<ed25519_dalek::Signature,SumatraCryptErrors> {
        let mut bytes_array: [u8;64] = [0u8;64];

        let bytes = hex::decode(&self.0);

        if bytes.is_err() {
            return Err(SumatraCryptErrors::DecodingError { ctx: SumatraCryptContext::Signature_ED25519} )
        }

        let unwrapped_bytes = bytes.unwrap();

        for i in 0..unwrapped_bytes.len() {
            bytes_array[i] = unwrapped_bytes[i];
        }

        return Ok(ed25519_dalek::Signature::from_bytes(&bytes_array))
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>,SumatraCryptErrors> {
        let bytes = hex::decode(&self.0);

        if bytes.is_err() {
            return Err(SumatraCryptErrors::DecodingError { ctx: SumatraCryptContext::Signature_ED25519 })
        }

        return Ok(bytes.unwrap())
    }
    pub fn to_string(&self) -> String {
        self.0.clone()
    }
    pub fn to_base58(&self) -> Result<String,SumatraCryptErrors> {
        let bytes = self.to_bytes()?;
        let s = bs58::encode(bytes).into_string();

        return Ok(s)
    }
    pub fn from_base58<T: AsRef<str>>(sig_as_bs58: T) -> Result<Self,SumatraCryptErrors> {
        let s = bs58::decode(sig_as_bs58.as_ref()).into_vec();

        if s.is_err() {
            return Err(SumatraCryptErrors::DecodingError { ctx: SumatraCryptContext::Signature_ED25519 })
        }
        Ok(Self(hex::encode_upper(s.unwrap())))
    }
}