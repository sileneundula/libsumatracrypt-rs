use pqc_kyber::*;
use rand::rngs::OsRng;
use new_rand::*;
use hex::*;

pub struct SumatraKyber1024;

pub struct Kyber1024PublicKey(String);
pub struct Kyber1024SecretKey(String);

pub struct Kyber1024CipherText(String);

pub struct Kyber1024SharedSecret(String);

impl SumatraKyber1024 {
    pub fn new() -> (Kyber1024SecretKey,Kyber1024PublicKey) {
        let keypair = pqc_kyber::keypair(&mut thread_rng()).expect("Failed To Generate Kyber1024");
        let pk = hex::encode_upper(keypair.public);
        let sk = hex::encode_upper(keypair.secret);

        return (Kyber1024SecretKey(sk),Kyber1024PublicKey(pk))
    }
}

impl Kyber1024PublicKey {
    pub fn new<T: AsRef<str>>(pk: T) -> Self {
        return Self(pk.as_ref().to_string())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let pk_bytes = hex::decode(&self.0).expect("Failed To Decode From Hex");
        return pk_bytes
    }
    pub fn encapsulate(&self) -> (Kyber1024CipherText,Kyber1024SharedSecret) {
        let (ciphertext, shared_secret_alice) = encapsulate(&Self::to_bytes(&self), &mut thread_rng()).expect("Failed To Encapsulate Kyber");
        let ss = hex::encode_upper(shared_secret_alice);
        let ctx = hex::encode_upper(ciphertext);

        return (Kyber1024CipherText(ctx),Kyber1024SharedSecret(ss))
    }
}

impl Kyber1024SecretKey {
    pub fn new<T: AsRef<str>>(sk: T) -> Self {
        return Self(sk.as_ref().to_string())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let sk_bytes = hex::decode(&self.0).expect("Failed To Decode Kyber Secret Key From Hex");
        return sk_bytes
    }
}

