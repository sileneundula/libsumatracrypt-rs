use getrandom::*;

pub struct SumatraCSPRNG;

impl SumatraCSPRNG {
    pub fn get_128_bytes_from_os() -> [u8;128] {
        let mut bytes: [u8;128] = [0u8;128];
        getrandom::getrandom(&mut bytes).expect("Failed To Get Randomness");
        return bytes
    }
    pub fn get_64_bytes_from_os() -> [u8;64] {
        let mut bytes: [u8;64] = [0u8;64];
        getrandom::getrandom(&mut bytes).expect("Failed To Get Randomness");
        return bytes
    }
    pub fn get_33_bytes_from_os() -> [u8;33] {
        let mut bytes: [u8;33] = [0u8;33];
        getrandom::getrandom(&mut bytes).expect("Failed To Get Bytes From CSPRNG 33");
        return bytes
    }
    pub fn new_32() -> [u8;32] {
        let mut bytes: [u8;32] = [0u8;32];
        getrandom::getrandom(&mut bytes).expect("Failed To Get Bytes From CSPRNG 33");
        return bytes
    }
}