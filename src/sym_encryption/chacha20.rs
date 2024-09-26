use chacha20poly1305::*;
use new_rand::*;

pub struct ChaCha20Encrypt;

impl ChaCha20Encrypt {
    pub fn new<T: AsRef<[u8]>>(key: T) {
        let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(thread_rng());
        let cipher = XChaCha20Poly1305::new(key.as_ref());
    }
}