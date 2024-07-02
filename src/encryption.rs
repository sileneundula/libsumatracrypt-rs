use ecies_ed25519::*;

use ecies_ed25519::{PublicKey,SecretKey};
use bs58::*;
use hex::*;
use schnorrkel::derive;
use zeroize::*;

pub struct SumatraEncrypt;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ECIESPublicKey(String);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ECIESSecretKey(String);

impl SumatraEncrypt {
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
    pub fn encrypt<T: AsRef<str>, B: AsRef<[u8]>>(pk: T, message: B) {
        // CSPRNG from thread_rand()
        let mut csprng = rand::thread_rng();

        // Conversion
        let pk_bytes = hex::decode(pk.as_ref().as_bytes()).expect("Failed To Decode Public Key From Hex");
        let publickey = ecies_ed25519::PublicKey::from_bytes(&pk_bytes).expect("Failed To Get Public Key From Bytes");
        
        let encrypted = ecies_ed25519::encrypt(&publickey, message.as_ref(), &mut csprng).expect("Failed To Encrypt");
        let ciphertext = bs58::encode(encrypted).into_string();

    }
    pub fn decrypt<T: AsRef<str>, B: AsRef<[u8]>>(sk: T, ciphertext: B) {
        let sk_bytes = hex::decode(sk.as_ref().as_bytes()).expect("Failed To Decoded Secret Key From Hex");
        let secretkey = ecies_ed25519::SecretKey::from_bytes(&sk_bytes).expect("Failed To Get Secret Key From Bytes");

        let decoded_ciphertext = bs58::decode(ciphertext).into_vec().expect("Failed To Decode Ciphertext From Bs58");
        let decrypted = ecies_ed25519::decrypt(&secretkey, &decoded_ciphertext.as_ref());
    }
}