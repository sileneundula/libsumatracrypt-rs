use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

/// Argon2id KDF
pub struct SumatraPasswordKDF;

/// Key Deriviation (outputs 32 bytes of randomness derived from password and salt)
pub struct SumatraKeyDeriviation;

pub struct Argon2Key(String,String);

impl SumatraKeyDeriviation {
    pub fn new<T: AsRef<[u8]>>(pass: T, salt: T) -> [u8;32] {

        let mut output_key_material = [0u8; 32]; // Can be any desired size
        Argon2::default().hash_password_into(pass.as_ref(), salt.as_ref(), &mut output_key_material).expect("Failed");

        return output_key_material
    }
    pub fn new_with_csprng_salt<T: AsRef<[u8]>>(pass: T) -> [u8;32] {
        let salt = SaltString::generate(&mut OsRng);

        let mut output_key_material = [0u8; 32]; // Can be any desired size
        Argon2::default().hash_password_into(pass.as_ref(), salt.to_string().as_bytes(), &mut output_key_material).expect("Failed");

        return output_key_material
    }
}


impl SumatraPasswordKDF {
    pub fn new_with_rng_salt<T: AsRef<[u8]>>(pass: T) -> String {
        // Salt
        let salt = SaltString::generate(&mut OsRng);
        // Configure Argon2id
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(pass.as_ref(), &salt).expect("Failed").to_string();
        let parsed_hash = PasswordHash::new(&password_hash).expect("Failed");
        assert!(Argon2::default().verify_password(pass.as_ref(), &parsed_hash).is_ok());
        return password_hash
    }
}