use base64::{engine::general_purpose, Engine};
use pretty_hex::*;
// use sdbx::decryption::{open::AesGcmDecryptor, Decryptor};
use sdbx::decryption::{resilient::ResilientDecryptor, Decryptor};

fn main() {
    // test data generated from - https://www.devglan.com/online-tools/aes-encryption-decryption
    let mut ciphertext = general_purpose::STANDARD
        .decode("wsDHBX9rmTv7OmuLycMEA3pjfeDo5aeTTFJICVaQ7h7AxTnItKi2TKSWt+NG22Y=")
        .unwrap();
    let iv: [u8; 16] = *b"oneinitialvector";
    let secret: [u8; 32] = *b"encrypt data securely for safety";

    println!("Encrypted data:");
    println!("{}", pretty_hex(&ciphertext.as_slice()));

    // let mut decryptor = AesGcmDecryptor::new(secret, iv).expect("failed to create decryptor ");
    // let _ = decryptor
    //     .decrypt(&mut ciphertext)
    //     .expect("failed to decrypt");

    // println!("Decrypted data:");
    // println!("{}", pretty_hex(&ciphertext.as_slice()));

    let mut fst_part = ciphertext[..12].to_vec();
    let mut decryptor = ResilientDecryptor::new(secret, iv).expect("failed to create decryptor");

    let _ = decryptor
        .decrypt(&mut fst_part)
        .expect("failed to decrypt first part");

    println!("First part decrypted:");
    println!("{}", pretty_hex(&fst_part.as_slice()));

    decryptor.forward(8);

    let mut snd_part = ciphertext[20..].to_vec();
    let _ = decryptor
        .decrypt(&mut snd_part)
        .expect("failed to decrypt first part");

    println!("Second part decrypted:");
    println!("{}", pretty_hex(&snd_part.as_slice()));
}
