use libsumatracrypt_rs::encryption::{ECIESPublicKey,ECIESSecretKey,SumatraEncryptECIES};

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

        let message = String::from_utf8(decrypted).expect("Failed To Convert Message");

        println!("msg: {}",message);
    }

}