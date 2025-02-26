#[allow(dead_code)]
use thiserror::Error;

pub mod open;
pub mod resilient;

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("Failed to initialize decryptor: {0}")]
    InitError(openssl::error::ErrorStack),

    #[error("Decryption failed: {0}")]
    DecryptionError(openssl::error::ErrorStack),
}

pub trait Decryptor {
    fn decrypt(&mut self, ciphertext: &mut [u8]) -> Result<(), DecryptError>;
}
