// Ed448-Goldilocks
use ed448_goldilocks_plus::elliptic_curve::group::*;
use ed448_goldilocks_plus::*;
use ed448_goldilocks_plus::ScalarBytes;
use ed448_goldilocks_plus::{EdwardsPoint, CompressedEdwardsY, Scalar, elliptic_curve::hash2curve::ExpandMsgXof, sha3::Shake256};
use new_rand::rngs::OsRng;

use serde::{Serialize,Deserialize};
use zeroize::*;

use subtle_encoding;

pub struct SumatraEd448;

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct Ed448PublicKey(String);
#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct Ed448SecretKey(String);
#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct Ed448Signature(String);

impl SumatraEd448 {
    pub fn new() -> (Ed448SecretKey,Ed448PublicKey) {
        let secret_key = Scalar::random(&mut OsRng);
        let public_key = EdwardsPoint::GENERATOR * &secret_key;
        let compressed_public_key = public_key.compress();
        assert_eq!(compressed_public_key.to_bytes().len(), 57);

        let compressed_pk_hex = hex::encode_upper(compressed_public_key.as_bytes());
        let secret_key_hex = hex::encode_upper(secret_key.to_bytes());

        return (Ed448SecretKey(secret_key_hex),Ed448PublicKey(compressed_pk_hex))
    }
}

impl Ed448PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        hex::decode(&self.0).expect("Failed To Decode From Hex")
    }
    pub fn public_key(&self) -> &str {
        return &self.0
    }
    pub fn to_usable_public_key(&self) -> CompressedEdwardsY {
        let bytes = self.to_bytes();
        let pk_compressed = CompressedEdwardsY::try_from(bytes).expect("Failed To Convert To Usable Type");
        return pk_compressed

        //return EdwardsPoint::from_bytes(bytes)
    }
    pub fn to_edwards_point(&self) -> EdwardsPoint {
        return self.to_usable_public_key().decompress().expect("Failed To Decompress ED448 Key")
    }
    pub fn verify() {

    }
}

impl Ed448SecretKey {
    /// ED448 Secret Key to bytes from hexadecimal
    pub fn to_bytes(&self) -> Vec<u8> {
        return subtle_encoding::hex::decode_upper(&self.0).expect("Failed To Convert To Bytes")
    }
    /// ED448 Secret Key from bytes encoded in hexadecimal
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode_upper(bytes))

    }
    pub fn to_scalar_usable_type(&self) -> Scalar {
        let bytes = self.to_bytes();

        let sk_bytes: [u8;56] = bytes.try_into().expect("Failed To Convert To Array");

        let scalar = Scalar::from_bytes(&sk_bytes);

        return scalar
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) {
        let sk = self.to_scalar_usable_type();
    }
}