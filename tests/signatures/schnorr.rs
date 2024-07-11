use libsumatracrypt_rs::signatures::schnorr::{CTX_DEFAULT,SchnorrPublicKey,SchnorrSecretKey,SchnorrSignature};

mod tests {
    use super::*;

    #[test]
    fn generate() {
        let (pk,sk) = SchnorrPublicKey::generate();
    }

    #[test]
    fn generate_and_sign() {
        let (pk, sk) = SchnorrPublicKey::generate();
        let msg = "This message is being signed by sumatra using default context";
        
        let signature = sk.sign_with_context(CTX_DEFAULT,msg.as_bytes());
    }

    #[test]
    fn generate_sign_and_verify() {
        let (pk,sk) = SchnorrPublicKey::generate();
        let msg = "This message is being signed by sumatra using default context";

        let signature = sk.sign_with_context(CTX_DEFAULT,msg.as_bytes());

        let verification = pk.verify_with_context(CTX_DEFAULT,msg.as_bytes(),signature);

        assert!(verification);
    }

    #[test]
    fn generate_simple_sign_and_verify() {
        let (pk,sk) = SchnorrPublicKey::generate();
        let msg = "This message is being signed by sumatra using default context";

        let signature = sk.sign(msg.as_bytes());

        let verification = pk.verify(msg.as_bytes(),signature);

        assert!(verification);
    }
}