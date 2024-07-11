use libsumatracrypt_rs::signatures::ed25519::*;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn ed25519_generate_keypair() {
        let sk = SumatraED25519::new();
    }

#[test]
    fn ed25519_signing_test() {
        let sk = SumatraED25519::new();
        let signature = sk.sign("This message is being signed.");
    }

    #[test]
    fn ed25519_sign_and_verify() {
        let sk = SumatraED25519::new();
        let vk = sk.to_public_key();
        let message = "This is a message promoting sumatra";

        let signature = sk.sign(message);

        let is_valid_signature = vk.verify(message, signature);

        assert!(is_valid_signature);
    }

    #[test]
    fn ed25519_sign_and_verify_invald_msg() {
        let sk = SumatraED25519::new();
        let vk = sk.to_public_key();
        let message = "This is a message promoting sumatra";
        let message_invalid = "This message is invalid for the given signature";

        let signature = sk.sign(message);

        let is_valid_signature = vk.verify(message_invalid, signature);

        assert_eq!(is_valid_signature,false);
    }

}