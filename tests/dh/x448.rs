use libsumatracrypt_rs::dh::x448::{SumatraX448,X448PublicKey,X448SharedSecret,X448SecretKey};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alice_and_bob_x448() {
        // Alice: Generates Ephermal Keypair
        let (alice_sk,alice_pk) = SumatraX448::generation();
        
        // Bob: Generates Keypair
        let (bob_sk,bob_pk) = SumatraX448::generation();

        // Alice: Generates Shared Secret
        let alice_ss = SumatraX448::to_shared_secret(alice_sk, bob_pk);
        
        // Bob: Generates Shared Secret
        let bob_ss = SumatraX448::as_shared_secret(bob_sk,alice_pk);

        assert_eq!(alice_ss.to_bytes_from_hex(),bob_ss.to_bytes_from_hex());
    }
}