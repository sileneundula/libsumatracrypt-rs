use libsumatracrypt_rs::encryption::{SumatraRSA4096,SumatraRSAPublicKey,SumatraRSASecretKey};

mod tests {
    use super::*;

    #[test]
    fn generation() {
        let (sk,pk) = SumatraRSA4096::generate();
    }

    #[test]
    fn generation_and_encryption() {
        let (sk,pk) = SumatraRSA4096::generate();

        let msg = "This is a message to be encrypted by RSA4096-OAEP in Sumatracrypt";

        let ct = SumatraRSA4096::encrypt(pk, msg);

        let decrypted = SumatraRSA4096::decrypt(sk, ct);

        let msg_decrypted = String::from_utf8(decrypted).expect("Failed To Unwrap String From UTF-8 For RSA In Test");

        assert_eq!(msg,msg_decrypted.as_str())


    }
}