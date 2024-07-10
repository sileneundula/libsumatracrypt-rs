// Ed448-Goldilocks

use ed448_goldilocks_plus::{EdwardsPoint, CompressedEdwardsY, Scalar, elliptic_curve::hash2curve::ExpandMsgXof, sha3::Shake256};
use new_rand::rngs::OsRng;

pub struct SumatraEd448;

pub struct Ed448PublicKey(String);
pub struct Ed448SecretKey(String);

impl SumatraEd448 {
    pub fn new() -> (Ed448SecretKey,Ed448PublicKey) {
        let secret_key = Scalar::random(&mut OsRng);
        let public_key = EdwardsPoint::GENERATOR * &secret_key;
        let compressed_public_key = public_key.compress();
        assert_eq!(compressed_public_key.to_bytes().len(), 57);

        let compressed_pk_hex = hex::encode_upper(public_key.);
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
        return EdwardsPoint::from_bytes(bytes)
    }
}