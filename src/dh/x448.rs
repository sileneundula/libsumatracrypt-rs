use rand::rngs::OsRng;
use x448::*;
use hex::*;

// Add Double-Ratchet

pub struct SumatraX448;

pub struct X448SecretKey(String);

pub struct X448PublicKey(String);

pub struct X448SharedSecret(String);

impl SumatraX448 {
    pub fn generation() -> (X448SecretKey,X448PublicKey) {
        let secret = Secret::new(&mut OsRng);
        let publickey = PublicKey::from(&secret);

        let secret_hex = hex::encode_upper(secret.as_bytes());
        let pk_hex = hex::encode_upper(publickey.as_bytes());

        return (X448SecretKey(secret_hex),X448PublicKey(pk_hex))
    }
    /// Used for ephermal keys that are only used once.
    pub fn to_shared_secret(sk: X448SecretKey, pk: X448PublicKey) -> X448SharedSecret {
        let secret = sk.to_secret_type();
        let public = pk.to_public_key_type();

        let shared_secret: SharedSecret = secret.to_diffie_hellman(&public).expect("Failed To To Get Shared Secret");

        return X448SharedSecret(hex::encode_upper(shared_secret.as_bytes()))
    }
    /// Used to copy key and keep key
    pub fn as_shared_secret(sk: X448SecretKey, pk: X448PublicKey) -> X448SharedSecret {
        let secret = sk.to_secret_type();
        let public = pk.to_public_key_type();

        let shared_secret: SharedSecret = secret.as_diffie_hellman(&public).expect("Failed To Get Shared Secret");

        return X448SharedSecret(hex::encode_upper(shared_secret.as_bytes()))
    }
}

impl X448SecretKey {
    pub fn new<T: AsRef<str>>(secretkeyhex: T) -> Self {
        if secretkeyhex.as_ref().len() == 112 {
            return Self(secretkeyhex.as_ref().to_string())
        }
        else {
            panic!("Secret Key is Not Long Enough")
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        return hex::decode(self.0).expect("Failed To Decode From Hex")
    }
    pub fn secret_hex(&self) -> &str {
        return &self.0
    }
    pub fn to_secret_type(&self) -> x448::Secret {
        let bytes = self.to_bytes();

        return x448::Secret::from_bytes(&bytes).expect("Failed To Get Secret From Bytes For X448")
    }
    pub fn to_public_key_type(&self) -> x448::PublicKey {
        return PublicKey::from_bytes(self.to_secret_type().as_bytes()).expect("Failed To Get Public Key From Secret For X448")
    }
    pub fn public_key(&self) -> X448PublicKey {
        let pk_hex = hex::encode_upper(self.to_public_key_type().as_bytes());

        return X448PublicKey(pk_hex)
    }
}

impl X448PublicKey {
    pub fn new<T: AsRef<str>>(pk_hex: T) -> Self {
        return Self(pk_hex.as_ref().to_string())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        return hex::decode(self.0).expect("Failed To Decode Public Key From Hex For X448")
    }
    pub fn public_key_hex(&self) -> &str {
        return &self.0
    }
    pub fn to_public_key_type(&self) -> x448::PublicKey {
        let bytes = self.to_bytes();

        return x448::PublicKey::from_bytes(&bytes).expect("Failed To Get Public Key (X448) From Bytes")
    }
}

impl X448SharedSecret {
    pub fn to_bytes_from_hex(&self) -> Vec<u8> {
        return hex::decode(self.0).expect("Failed To Decode To Bytes")
    }
    pub fn to_shared_secret_type(&self) -> SharedSecret {
        SharedSecret::from_bytes(&self.to_bytes_from_hex()).expect("Failed To Get Shared Secret From Bytes For X448")
    }
}