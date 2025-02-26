use aes::{
    cipher::{
        generic_array::{typenum::U16, GenericArray},
        BlockEncrypt, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek,
    },
    Aes256, Block,
};

use crate::decryption::{DecryptError, Decryptor};
use ctr::Ctr32BE;
use ghash::{universal_hash::UniversalHash, GHash};

pub struct ResilientDecryptor {
    cipher: Ctr32BE<Aes256>,
    counter: u32,
}

const NONCE_BITS: u64 = 16_u64 * 8;

impl ResilientDecryptor {
    pub fn new(key: [u8; 32], iv: [u8; 16]) -> Result<Self, DecryptError> {
        let key = GenericArray::from(key);
        let cipher = aes::Aes256::new(&key);

        // initialize cipher
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);
        let ghash = GHash::new(GenericArray::from_slice(&ghash_key));
        let first_block = Self::gen_first_block(&iv, &ghash);
        let mut cipher = Ctr32BE::<Aes256>::new(&key, &first_block);

        // tag mask handling
        let mut tag_mask = Block::default();
        cipher.apply_keystream(&mut tag_mask);

        Ok(Self {
            cipher: cipher,
            counter: 16,
        })
    }

    // NOTE: that this will be different if the iv is 12 bytes
    fn gen_first_block(iv: &[u8], ghash: &GHash) -> GenericArray<u8, U16> {
        let mut ghash = ghash.clone();
        ghash.update_padded(iv);
        let mut block = Block::default();
        block[8..].copy_from_slice(&NONCE_BITS.to_be_bytes());
        ghash.update(&[block]);
        ghash.finalize()
    }

    pub fn forward(&mut self, num_bytes: u32) {
        self.cipher.seek(self.counter + num_bytes);
        self.counter += num_bytes;
    }
}

impl Decryptor for ResilientDecryptor {
    fn decrypt(&mut self, ciphertext: &mut [u8]) -> Result<(), DecryptError> {
        self.cipher.apply_keystream(ciphertext);
        self.counter += ciphertext.len() as u32;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine};

    const IV: [u8; 16] = *b"oneinitialvector";
    const KEY: [u8; 32] = *b"encrypt data securely for safety";

    const PLAINTEXT: &str = "super secret message to encrypt";

    #[test]
    fn test_resilient_decryptor() {
        let mut ciphertext = general_purpose::STANDARD
            .decode("wsDHBX9rmTv7OmuLycMEA3pjfeDo5aeTTFJICVaQ7h7AxTnItKi2TKSWt+NG22Y=")
            .unwrap();

        let mut decryptor = ResilientDecryptor::new(KEY, IV).unwrap();

        let _ = decryptor
            .decrypt(&mut ciphertext)
            .expect("failed to decrypt");

        let decrypted_str = String::from_utf8_lossy(&ciphertext)
            .into_owned()
            .chars()
            .take(PLAINTEXT.len())
            .collect::<String>();

        assert_eq!(decrypted_str, PLAINTEXT)
    }

    #[test]
    fn test_resilient_decryptor_seeking() {
        let ciphertext = general_purpose::STANDARD
            .decode("wsDHBX9rmTv7OmuLycMEA3pjfeDo5aeTTFJICVaQ7h7AxTnItKi2TKSWt+NG22Y=")
            .unwrap();

        let mut decryptor = ResilientDecryptor::new(KEY, IV).unwrap();

        let fst_part_till = 12;
        let snd_part_from = 22;
        let mut fst_part = ciphertext[..fst_part_till].to_vec();
        let mut snd_part = ciphertext[snd_part_from..].to_vec();

        let _ = decryptor
            .decrypt(&mut fst_part)
            .expect("failed to decrypt first part");

        let fst_decrypted_str = String::from_utf8_lossy(&fst_part[..fst_part_till]);

        decryptor.forward((snd_part_from - fst_part_till).try_into().unwrap());

        let _ = decryptor
            .decrypt(&mut snd_part)
            .expect("failed to decrypt second part");

        let snd_decrypted_str =
            String::from_utf8_lossy(&snd_part[..(PLAINTEXT.len() - snd_part_from)]);

        assert_eq!(fst_decrypted_str, &PLAINTEXT[..fst_part_till]);
        assert_eq!(
            snd_decrypted_str,
            &PLAINTEXT[snd_part_from..PLAINTEXT.len()]
        );
    }
}
