use libsumatracrypt_rs::signatures::ed25519::*;

#[test]
fn ed25519_generate_keypair() {
    let sk = SumatraED25519::new();
}

#[test]
fn ed25519_signing_test() {
    let sk = SumatraED25519::new();
    let signature = sk.sign("This message is being signed.");
}