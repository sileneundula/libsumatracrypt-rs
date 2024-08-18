use ecies_ed25519::*;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rsa::oaep::*;
use rsa::pkcs8::*;

use ecies_ed25519::{PublicKey,SecretKey};
use bs58::*;
use hex::*;
use schnorrkel::derive;
use sha2::Sha256;
use zeroize::*;
use base32::*;

use serde::{Serialize,Deserialize};

use new_rand::*;

use crate::signatures::ed25519::ED25519PublicKey;

// Security Warning: Do not show what operating system is used for RSA

pub struct SumatraRSA4096;

#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SumatraRSAPublicKey(String);

#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SumatraRSASecretKey(String);

pub struct SumatraEncryptECIES;

#[derive(Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ECIESPublicKey(String);

#[derive(Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ECIESSecretKey(String);

#[derive(Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ECIESCipherText(String);

#[derive(Clone, Zeroize, ZeroizeOnDrop,Serialize,Deserialize)]
pub struct ECIESDecodedMessage(Vec<u8>);

impl SumatraEncryptECIES {
    pub fn generate() -> (ECIESSecretKey,ECIESPublicKey)  {
        // CSPRNG from thread_rand()
        let mut csprng = rand::thread_rng();
        
        // Secret Key and Public Key
        let (sk,pk) = ecies_ed25519::generate_keypair(&mut csprng);

        let secretkey = hex::encode_upper(sk.as_bytes());
        let publickey = hex::encode_upper(pk.as_bytes());

        return (ECIESSecretKey(secretkey),ECIESPublicKey(publickey))
    }
    /// Encrypt: Accepts an input the public key (in hexadecimal format) and the message as a string or as bytes
    pub fn encrypt<B: AsRef<[u8]>>(pk: ECIESPublicKey, message: B) -> ECIESCipherText {
        // CSPRNG from thread_rand()
        let mut csprng = rand::thread_rng();

        // Conversion
        let pk_bytes = hex::decode(pk.0.as_bytes()).expect("Failed To Decode Public Key From Hex");
        let publickey = ecies_ed25519::PublicKey::from_bytes(&pk_bytes).expect("Failed To Get Public Key From Bytes");
        
        let encrypted = ecies_ed25519::encrypt(&publickey, message.as_ref(), &mut csprng).expect("Failed To Encrypt");
        let ciphertext = bs58::encode(encrypted).into_string();

        return ECIESCipherText(ciphertext)

    }
    pub fn decrypt(sk: ECIESSecretKey, ciphertext: ECIESCipherText) -> ECIESDecodedMessage {
        let sk_bytes = hex::decode(sk.0.as_bytes()).expect("Failed To Decoded Secret Key From Hex");
        let secretkey = ecies_ed25519::SecretKey::from_bytes(&sk_bytes).expect("Failed To Get Secret Key From Bytes");

        let decoded_ciphertext = bs58::decode(&ciphertext.0).into_vec().expect("Failed To Decode Ciphertext From Bs58");
        let decrypted = ecies_ed25519::decrypt(&secretkey, &decoded_ciphertext.as_ref()).expect("Failed To Decrypt Message From Encryption Key");

        return ECIESDecodedMessage(decrypted)
    }
}

impl ECIESDecodedMessage {
    pub fn to_utf8_string(&self) -> String {
        return String::from_utf8(self.0.to_vec()).expect("Failed To Decode From String")
    }
    pub fn to_vec(&self) -> Vec<u8> {
        return self.0.to_vec()
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.0
    }
}

impl ECIESPublicKey {
    pub fn new<T: AsRef<str>>(pk_hex: T) -> Self {
        return Self::from_hex(pk_hex.as_ref())
    }
    pub fn from_hex<T: AsRef<str>>(pk: T) -> Self {
        return Self(pk.as_ref().to_string())
    }
    pub fn from_bytes<T: AsRef<[u8]>>(pk_bytes: T) -> Self {
        return Self(hex::encode_upper(pk_bytes.as_ref()))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.0).expect("Failed To Decode From Hex");
    }
    pub fn public_key(&self) -> &str {
        return &self.0
    }
    pub fn to_dalek_pk(&self) -> ecies_ed25519::PublicKey {
        let bytes = self.to_bytes();

        return ecies_ed25519::PublicKey::from_bytes(&bytes).expect("Failed To Construct Public Key From Bytes For ECIES")
    }
    pub fn to_base32(&self) -> String {
        let pk_bytes = self.to_bytes();
        return base32::encode(base32::Alphabet::Rfc4648 { padding: false },&pk_bytes);
    }
    pub fn from_base32<T: AsRef<str>>(pk_bs32: T) -> Self {
        let pk_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, pk_bs32.as_ref()).expect("Failed To Decode Base32");
        return Self::from_bytes(&pk_bytes)
    }
}

impl ECIESSecretKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.0).expect("Failed To Decode From Hex To Secret Key")
    }
}


impl SumatraRSA4096 {
    pub fn generate() -> (SumatraRSASecretKey,SumatraRSAPublicKey) {
        let mut rng = new_rand::thread_rng();
        let bits = 4096;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);


        let sk_pem = priv_key.to_pkcs8_pem(LineEnding::LF).expect("Failed To Encode RSA Secret Key From PKCS8");
        let pk_pem = pub_key.to_public_key_pem(LineEnding::LF).expect("Failed To Encode RSA Pub from PKCS8");
        //rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&self, line_ending)

        return (SumatraRSASecretKey(sk_pem.to_string()),SumatraRSAPublicKey(pk_pem))
    }
    pub fn encrypt<T: AsRef<[u8]>>(pk: SumatraRSAPublicKey, data: T) -> String {
        let mut rng = new_rand::thread_rng();

        let padding = Oaep::new::<Sha256>();

        let encrypted = pk.decode_from_pem().encrypt(&mut rng, padding, data.as_ref()).expect("Failed To Encode Using RSA");

        return bs58::encode(encrypted).into_string();
    }
    pub fn decrypt<T: AsRef<str>>(sk: SumatraRSASecretKey,encrypted: T) -> Vec<u8> {
        let padding = Oaep::new::<Sha256>();


        let decrypted_bytes = bs58::decode(encrypted.as_ref()).into_vec().expect("Failed To Decode RSA Encrypted Data From Base58");

        let dec_data = sk.decode_from_pem().decrypt(padding, &decrypted_bytes).expect("failed to decrypt");

        return dec_data
    }
}

impl SumatraRSAPublicKey {
    pub fn public_key(&self) {
        &self.0;
    }
    pub fn decode_from_pem(&self) -> RsaPublicKey {
        return RsaPublicKey::from_public_key_pem(&self.0).expect("Failed To Convert Public Key");
    }
}

impl SumatraRSASecretKey {
    pub fn decode_from_pem(&self) -> RsaPrivateKey {
        return RsaPrivateKey::from_pkcs8_pem(&self.0).expect("Failed To Decoded Secret Key")
    }
}