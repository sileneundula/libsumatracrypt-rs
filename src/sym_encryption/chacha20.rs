use chacha20poly1305::*;
use new_rand::*;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};
pub struct ChaCha20Encrypt;
pub struct ChaCha20Decrypt;


pub struct EncryptionKey(String);
pub struct CipherText(String);

impl ChaCha20Encrypt {
    pub fn new<T: AsRef<[u8]>>(key: T) {
        let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let gen_key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    }
}