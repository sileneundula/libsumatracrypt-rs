use rand::rngs::OsRng;
use safe_pqc_kyber::*;

pub struct SumatraSafeKyber1024;

pub struct SafeKyber1024PublicKey(String);
pub struct SafeKyber1024SecretKey(String);

pub struct SafeKyber1024CipherText(String);

pub struct SafeKyber1024SharedSecret(String);

impl SumatraSafeKyber1024 {
    pub fn new() -> (SafeKyber1024SecretKey,SafeKyber1024SecretKey) {
        let keypair = safe_pqc_kyber::Keypair::generate(OsRng());
        let public = hex::encode_upper(keypair.public);
        let secret = hex::encode_upper(keypair.secret);

        return (SafeKyber1024SecretKey(secret), SafeKyber1024PublicKey(public))
    }
}

impl SafeKyber1024PublicKey {
    pub fn encapsulate(&self) {
        let pk_bytes = Self::from_hex(self);
        let (ciphertext, shared_secret_alice) = encapsulate(&bytes, &mut rng)?;
    }
    pub fn from_hex(&self) -> Vec<u8> {
        let pk = hex::decode(self.0).expect("Failed To Decode Kyber1024");
        return pk
    }
}