use pqcrypto_traits::sign::*;
use pqcrypto_falcon::falcon512;
use pqcrypto_falcon::falcon1024;
use hex::*;

pub struct SumatraFalcon512;
pub struct SumatraFalcon1024;

pub struct Falcon512PublicKey(String);
pub struct Falcon512SecretKey(String);
pub struct Falcon512Signature(String);

pub struct Falcon1024PublicKey(String);

pub struct Falcon1024SecretKey(String);

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