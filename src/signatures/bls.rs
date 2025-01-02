/// # BLS Signatures
/// 
/// BLS Signatures offer a signature solution that is easy to aggregate. It uses Filecoins implementation of BLS Signatures.
/// 
/// ## Developer Notes
/// 
/// The input to each keypair is 64-bytes of os-randomness as opposed to 32-bytes.
/// 
/// BIP39 added using 64-bytes

use crate::csprng::SumatraCSPRNG;

use bls_signatures::{self, PublicKey};
use bls_signatures::*;
use bls_signatures::Serialize as blsSerialize;

use bs58;
use base32;

use zeroize::*;

use serde::{Serialize,Deserialize};

/// # SumatraBLS
/// 
/// Generation of BLS Keypair using Filecoin's `bls_signatures` crate.
pub struct SumatraBLS;

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct BLSPublicKey(String);

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct BLSSecretKey(String);

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct BLSSignature(String);

impl SumatraBLS {
    pub fn new() -> (BLSSecretKey,BLSPublicKey) {
        let rng_bytes = SumatraCSPRNG::get_64_bytes_from_os();
        let sk_as_bls = bls_signatures::PrivateKey::new(rng_bytes);
        let pk_as_bls = sk_as_bls.public_key();
        
        let sk = hex::encode_upper(sk_as_bls.as_bytes());
        let pk = hex::encode_upper(pk_as_bls.as_bytes());

        return (BLSSecretKey(sk),BLSPublicKey(pk))
    }
    pub fn from_seed(seed: [u8;64]) -> (BLSSecretKey,BLSPublicKey) {
        let sk_as_bls = bls_signatures::PrivateKey::new(seed);
        let pk_as_bls = sk_as_bls.public_key();
        
        let sk = hex::encode_upper(sk_as_bls.as_bytes());
        let pk = hex::encode_upper(pk_as_bls.as_bytes());

        return (BLSSecretKey(sk),BLSPublicKey(pk))
    }
    pub fn aggregate_slow(signatures: &[BLSSignature]) -> BLSSignature {
        let mut aggregated: Vec<bls_signatures::Signature> = Vec::new();
        
        for sig in signatures {
            let usable_sig = sig.to_usable_type();
            aggregated.push(usable_sig);
        }

        let signature = bls_signatures::aggregate(&aggregated).expect("Failed To Aggregate");
        return BLSSignature(hex::encode_upper(signature.as_bytes()))
    }
    pub fn verify_messages_slow(signature: &BLSSignature, messages: &[&[u8]], pk: &[BLSPublicKey]) -> bool {

        let mut aggregated_pks: Vec<bls_signatures::PublicKey> = Vec::new();

        for publickeys in pk {
            let usable_pk = publickeys.to_usable_type();
            aggregated_pks.push(usable_pk);
        }

        let verification = bls_signatures::verify_messages(&signature.to_usable_type(), messages, &aggregated_pks);

        return verification
    }
}

impl BLSPublicKey {
    pub fn from_str<T: AsRef<str>>(s: T) -> Self{
        return Self(s.as_ref().to_string())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let pk_as_bytes = hex::decode(&self.0).expect("Failed To Convert Hex To Bytes");
        return pk_as_bytes
    }
    pub fn to_usable_type(&self) -> bls_signatures::PublicKey {
        return bls_signatures::PublicKey::from_bytes(&self.to_bytes()).expect("Failed to get BLS Public Key From Bytes");
    }
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, sig: BLSSignature) -> bool {
        self.to_usable_type().verify(sig.to_usable_type(), msg.as_ref())
    }
}

impl BLSSecretKey {
    pub fn from_seed(seed: [u8;64]) -> Self {
        let sk_as_bls = bls_signatures::PrivateKey::new(seed);
        let sk = hex::encode_upper(sk_as_bls.as_bytes());
        Self(sk)
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        return Self(hex::encode_upper(bytes))
    }
    pub fn from_str<T: AsRef<str>>(s: T) -> Self {
        return Self(s.as_ref().to_string())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let sk_as_bytes = hex::decode(&self.0).expect("Failed To Decode From Hex");
        return sk_as_bytes
    }
    pub fn to_usable_type(&self) -> bls_signatures::PrivateKey {
        return bls_signatures::PrivateKey::from_bytes(&self.to_bytes()).expect("Failed to get BLS Private Key For BLS Type");
    }
    pub fn public_key(&self) -> BLSPublicKey {
        let sk = self.to_usable_type();
        BLSPublicKey(hex::encode_upper(sk.public_key().as_bytes()))
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> BLSSignature {
        let secretkey = self.to_usable_type();
        let signature = secretkey.sign(msg);

        return BLSSignature(hex::encode_upper(signature.as_bytes()))
    }
}

impl BLSSignature {
    pub fn from_str<T: AsRef<str>>(s: T) -> Self {
        Self(s.as_ref().to_string())
    }
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Self {
        return Self(hex::encode_upper(bytes.as_ref()))
    }
    pub fn signature(&self) -> &str {
        self.0.as_str()
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.0).expect("Failed To Decode To Bytes")
    }
    pub fn to_usable_type(&self) -> bls_signatures::Signature {
        let bytes = self.to_bytes();
        return bls_signatures::Signature::from_bytes(&bytes).expect("Failed To Get BLS Signature From Bytes")
    }

}