use crate::decryption::{DecryptError, Decryptor};
use openssl::symm::{Cipher, Crypter, Mode};

const WORK_BUF_SZ: usize = 2048;

pub struct AesGcmDecryptor {
    decryptor: Crypter,
    work_buf: [u8; WORK_BUF_SZ],
}

impl AesGcmDecryptor {
    pub fn new(key: [u8; 32], iv: [u8; 16]) -> Result<Self, DecryptError> {
        let decryptor = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, &key, Some(&iv))
            .map_err(DecryptError::InitError)?;
        Ok(AesGcmDecryptor {
            decryptor,
            work_buf: [0; WORK_BUF_SZ],
        })
    }
}

impl Decryptor for AesGcmDecryptor {
    fn decrypt(&mut self, ciphertext: &mut [u8]) -> Result<(), DecryptError> {
        match self.decryptor.update(ciphertext, &mut self.work_buf) {
            Ok(s) => {
                ciphertext.copy_from_slice(&self.work_buf[..s]);
                Ok(())
            }
            Err(e) => Err(DecryptError::DecryptionError(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{engine::general_purpose, Engine};
    #[test]
    fn test_openssl_decryptor() {
        let plaintext = "super secret message to encrypt";
        let mut ciphertext = general_purpose::STANDARD
            .decode("wsDHBX9rmTv7OmuLycMEA3pjfeDo5aeTTFJICVaQ7h7AxTnItKi2TKSWt+NG22Y=")
            .unwrap();
        let iv: [u8; 16] = *b"oneinitialvector";
        let key: [u8; 32] = *b"encrypt data securely for safety";

        let mut decryptor = AesGcmDecryptor::new(key, iv).expect("failed to create decrytpro ");

        let _ = decryptor
            .decrypt(&mut ciphertext)
            .expect("failed to decrypt");

        let decrypted_str = String::from_utf8_lossy(&ciphertext[..plaintext.len()]);

        assert_eq!(decrypted_str, plaintext)
    }
}
