/// # SumatraCryptErrors (Error Management)
/// 
/// This module provides error handling for sumatracrypt.

use thiserror::Error;


#[derive(Error, Debug)]
pub enum SumatraCryptErrors {
    #[error("Invalid Signature on {:?}", ctx)]
    InvalidSignature {
        ctx: SumatraCryptContext,
    },

    #[error("Invalid Signing on {:?}", ctx)]
    InvalidSigning {
        ctx: SumatraCryptContext,
    },
    
    // # Encoding/Decoding
    #[error("Invalid Encoding {:?}", ctx)]
    EncodingError {
        ctx: SumatraCryptContext,
    },
    #[error("Invalid Encoding {:?}", ctx)]
    DecodingError {
        ctx: SumatraCryptContext,
    },

    #[error("Verification Failed For {:?}", ctx)]
    VerificationFailed {
        ctx: SumatraCryptContext,
    }
}

#[derive(Debug)]
pub enum SumatraCryptContext {
    // # Signatures
    Signature_ED25519,
    Signature_ED448,
    Signature_Schnorr,
    Signature_BLS,

    PQSignature_FALCON512,
    PQSignature_FALCON1024,
    PQSignature_Dilithium3,
}

#[derive(Debug)]
pub enum SumatraCryptType {
    PublicKey,
    SecretKey,
    Signature,
    CipherText,
    Digest,
    Message,
}

#[derive(Debug)]
pub enum SumatraCryptEncoding {
    Hexadecimal,
    Base32,
    Base58,
    Base65,
}