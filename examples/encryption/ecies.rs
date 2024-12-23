use libsumatracrypt_rs::encryption::{ECIESCipherText,ECIESPublicKey,ECIESSecretKey,SumatraEncryptECIES};

fn main() {
    // Alice ECIES Keys
    let (vk,pk) = SumatraEncryptECIES::generate();
    
    // Bob ECIES Keys
    let (vk2,pk2) = SumatraEncryptECIES::generate();
    
    // Encrypted Message To Bob Using His Public Key And Including A Message (Accepts Bytes or Strings)
    let ct = SumatraEncryptECIES::encrypt(pk2, "This is a secret message using ECIES");

    // Decrypted Message
    let decrypted_message = SumatraEncryptECIES::decrypt(vk2, ct);

    // The Message Decrypted As A UTF8 String
    let message = decrypted_message.to_utf8_string();

    println!("Message: {}",message)
}