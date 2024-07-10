use libsumatracrypt_rs::encryption::{ECIESPublicKey,ECIESSecretKey,SumatraEncryptECIES,ECIESDecodedMessage};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecies_generation() {
        let (sk,ek) = SumatraEncryptECIES::generate();
    }

    #[test]
    fn ecies_encrypt_and_verify() {
        let (sk,ek) = SumatraEncryptECIES::generate();

        let msg = "This is a message to be encrypted";

        let ct = SumatraEncryptECIES::encrypt(ek, msg);

        let decrypted = SumatraEncryptECIES::decrypt(sk, ct);

        println!("msg: {}",decrypted.to_utf8_string());
    }

}