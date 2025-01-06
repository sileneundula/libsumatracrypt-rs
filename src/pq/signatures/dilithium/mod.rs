use pqcrypto_dilithium::dilithium3::*;
use pqcrypto_traits::sign::{PublicKey,SecretKey,SignedMessage,DetachedSignature};
use hex::*;
use bs58;
use serde::{Serialize,Deserialize};
use zeroize::{ZeroizeOnDrop,Zeroize};

pub struct SumatraDilithium3;

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]

pub struct Dilithium3PublicKey(String);

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]

pub struct Dilithium3SecretKey(String);

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]

pub struct Dilithium3Signature(String);

impl SumatraDilithium3 {
    pub fn new() -> (Dilithium3SecretKey,Dilithium3PublicKey) {
        let (pk,sk) = keypair();
        let pk_hex = hex::encode_upper(pk.as_bytes());
        let sk_hex = hex::encode_upper(sk.as_bytes());
        return (Dilithium3SecretKey(sk_hex),Dilithium3PublicKey(pk_hex))
    }
}

impl Dilithium3SecretKey {
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Dilithium3Signature {
        let sk = self.to_pqcrtop();
        let signature = detached_sign(msg.as_ref(), &sk);
        return Dilithium3Signature(hex::encode_upper(signature.as_bytes()));
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes = hex::decode(&self.0).expect("Failed To Decode");
        return bytes
    }
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Self {
        Self(hex::encode_upper(bytes.as_ref()))
    }
    pub fn to_pqcrtop(&self) -> pqcrypto_dilithium::dilithium3::SecretKey {
        let bytes = self.to_bytes();
        return SecretKey::from_bytes(&bytes).expect("Failed To Decode Falcon1024 From Bytes")
    }
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
    pub fn from_str<T: AsRef<str>>(s: T) -> Self {
        Self(s.as_ref().to_string())
    }
}

impl Dilithium3PublicKey {
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Self {
        Self(hex::encode_upper(bytes.as_ref()))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes = hex::decode(&self.0).expect("Failed To Convert");
        return bytes
    }
    pub fn to_pqcrtop(&self) -> pqcrypto_dilithium::dilithium3::PublicKey {
        let bytes = self.to_bytes();
        return PublicKey::from_bytes(&bytes).expect("Failed To Convert From Bytes")
    }
    pub fn verify<T: AsRef<[u8]>>(&self, sig: Dilithium3Signature, msg: T) -> bool {
            let pk = self.to_pqcrtop();
            return verify_detached_signature(&sig.to_pqcrtop(), msg.as_ref(), &pk).is_ok()
    }
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
    pub fn from_str<T: AsRef<str>>(s: T) -> Self {
        Self(s.as_ref().to_string())
    }
}

impl Dilithium3Signature {
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Self {
        Self(hex::encode_upper(bytes.as_ref()))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.0).expect("Failed To Decode From Hex")
    }
    pub fn to_pqcrtop(&self) -> pqcrypto_dilithium::dilithium3::DetachedSignature {
        let bytes = self.to_bytes();
        return DetachedSignature::from_bytes(&bytes).expect("Failed To Get Falcon1024 Signature")
    }
    pub fn to_bs58(&self) -> String {
        let bytes = self.to_bytes();
        return bs58::encode(bytes).into_string()
    }
    pub fn from_bs58<T: AsRef<str>>(sig: T) -> Self {
        let bytes = bs58::decode(sig.as_ref()).into_vec().expect("Failed To Convert From Base58");
        Self(hex::encode_upper(bytes))
    }
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
    pub fn from_str<T: AsRef<str>>(s: T) -> Self {
        return Self(s.as_ref().to_string())
    }
}