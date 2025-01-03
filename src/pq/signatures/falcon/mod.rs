use pqcrypto_traits::sign::*;
use pqcrypto_falcon::falcon512;
use pqcrypto_falcon::falcon1024;
use hex::*;
use bs58;

use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};

pub struct SumatraFalcon512;
pub struct SumatraFalcon1024;

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct Falcon512PublicKey(String);
#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct Falcon512SecretKey(String);
#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct Falcon512Signature(String);

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct Falcon1024PublicKey(String);

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct Falcon1024SecretKey(String);

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct Falcon1024Signature(String);


impl SumatraFalcon512 {
    pub fn new() -> (Falcon512SecretKey,Falcon512PublicKey) {
        let keypair = falcon512::keypair();
        let sk = hex::encode_upper(keypair.1.as_bytes());
        let pk = hex::encode_upper(keypair.0.as_bytes());
        return (Falcon512SecretKey(sk),Falcon512PublicKey(pk))
    }
}

impl SumatraFalcon1024 {
    pub fn new() -> (Falcon1024SecretKey,Falcon1024PublicKey) {
        let keypair = falcon1024::keypair();
        let sk = hex::encode_upper(keypair.1.as_bytes());
        let pk = hex::encode_upper(keypair.0.as_bytes());
        return (Falcon1024SecretKey(sk),Falcon1024PublicKey(pk))
    }
}

impl Falcon1024SecretKey {
    pub fn to_pqcrtop(&self) -> falcon1024::SecretKey {
        let bytes = self.to_bytes();
        return falcon1024::SecretKey::from_bytes(&bytes).expect("Failed To Decode Falcon1024 From Bytes")
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes = hex::decode(&self.0).expect("Failed To Decode");
        return bytes
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Falcon1024Signature {
        let sk = self.to_pqcrtop();
        let signature = falcon1024::detached_sign(msg.as_ref(), &sk);
        return Falcon1024Signature(hex::encode_upper(signature.as_bytes()));
    }
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl Falcon1024PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes = hex::decode(&self.0).expect("Failed To Convert");
        return bytes
    }
    pub fn to_pqcrtop(&self) -> falcon1024::PublicKey {
        let bytes = self.to_bytes();
        return falcon1024::PublicKey::from_bytes(&bytes).expect("Failed To Convert From Bytes")
    }
    pub fn verify<T: AsRef<[u8]>>(&self, sig: Falcon1024Signature, msg: T) -> bool {
        let pk = self.to_pqcrtop();
        return falcon1024::verify_detached_signature(&sig.to_pqcrtop(), msg.as_ref(), &pk).is_ok()
    }
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl Falcon1024Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.0).expect("Failed To Decode From Hex")
    }
    pub fn to_pqcrtop(&self) -> falcon1024::DetachedSignature {
        let bytes = self.to_bytes();
        return falcon1024::DetachedSignature::from_bytes(&bytes).expect("Failed To Get Falcon1024 Signature")
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
}