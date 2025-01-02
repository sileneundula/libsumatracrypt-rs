/// # BIP39
/// 
/// BIP39 is used to create mnemonics.

use bip39::Mnemonic;
use bip39::Language;
use bip39::serde::{Serialize,Deserialize};
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;
use crate::csprng::SumatraCSPRNG;

#[derive(Clone,Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct MnemonicPhrase(Mnemonic);

impl MnemonicPhrase {
    pub fn new(lang: Language) -> Self {
        let csprng = SumatraCSPRNG::new_32();
        let mnemonic = Mnemonic::from_entropy_in(lang, &csprng).expect("Failed To Get Rnadomness");
        return Self(mnemonic)
    }
    pub fn new_english() -> Self {
        return MnemonicPhrase::new(Language::English)
    }
    pub fn revert_to_entropy(&self) -> Vec<u8> {
        return self.0.to_entropy()
    }
    pub fn to_seed(&self, pass: &str) -> [u8;64] {
        let seed = self.0.to_seed(pass);
        return seed
    }
    pub fn to_seed_32(&self, pass: &str) -> [u8;32] {
        let seed = self.0.to_seed(pass);
        let output: [u8; 32] = seed[..32].try_into().unwrap();
        return output
    }
    pub fn to_string(&self) -> String {
        let s = self.0.to_string();
        return s
    }
    pub fn print(&self) {
        let mnemonic = self.to_string();
        println!("MnemonicPhrase: {}",mnemonic);
    }
    pub fn from_string<T: AsRef<str>>(mnemonic: T) -> Self {
        Self(Mnemonic::parse(mnemonic.as_ref()).expect("Failed To Get Mnemonic"))
    }
}

#[test]
fn as_str() {
    let b = MnemonicPhrase::new_english();
    b.print();
    let seed = b.to_seed("Test123");
    println!("{:?}",seed);

}