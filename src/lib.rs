//! The only goal of this library is to provide the easiest way to encrypt and decrypt a message to
//! a computer, its a very very minimal and provides no choices for the user to increase
//! performance or security.
//!
//! It is a minimal wrapper for the crate aes_siv and anyone wanting anything more advanced than
//! what this library provides should look in that crate where ALL the heavy lifting is performed.
//!
//! Encryption and decryption example:
//!
//! ``` rust
//! use std::str;
//! fn main() {
//!     let payload = "Hello world!".as_bytes();
//!     let password = b"hello wooooooooo";
//!
//!     let encrypted = simplestcrypt::encrypt_and_serialize(&password[..], &payload).unwrap();
//!     let plain = simplestcrypt::deserialize_and_decrypt(&password[..], &encrypted).unwrap();
//!
//!     println!("{:?}", str::from_utf8(&plain));
//! }
//! ```

use aes_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_siv::Aes128SivAead;

use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Contains the Nonce used in the encryption process
#[derive(Deserialize, Serialize)]
pub struct Encrypted {
    nonce: [u8; 16],
    ciphertext: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum EncryptError {
    PasswordSize,
    EncryptionFail,
    SerializeFail,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum DecryptError {
    PasswordSize,
    DecryptFail,
    DeserializeFail,
}

/// Encrypts the given bytes using a random nonce using Aes128SivAed
/// Password cannot be longer than 32 bytes
pub fn encrypt(password: &[u8], bytes: &[u8]) -> Result<Encrypted, EncryptError> {
    let mut key: [u8; 32] = [0; 32];

    if password.len() > key.len() {
        return Err(EncryptError::PasswordSize);
    };

    for (i, k) in password.iter().enumerate() {
        if i >= key.len() {
            break;
        } else {
            key[i] = *k;
        }
    }
    let key = GenericArray::from_slice(&key);

    let mut rng = rand::thread_rng();
    let mut nonce: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut nonce);
    let noncearray = GenericArray::from_slice(&nonce);

    let cipher = Aes128SivAead::new(key);

    let ciphertext = cipher
        .encrypt(noncearray, bytes)
        .map_err(|_e| EncryptError::EncryptionFail)?;

    Ok(Encrypted { nonce, ciphertext })
}

/// Encrypts the given bytes using a random nonce using Aes128SivAed, and then serializes the
/// encryption along with the nonce using bincode. The resulting vector is then bincode serialized
/// Encrypted structure
///
/// Password cannot be longer than 32 bytes
pub fn encrypt_and_serialize(password: &[u8], bytes: &[u8]) -> Result<Vec<u8>, EncryptError> {
    let encrypted = encrypt(password, bytes)?;

    bincode::serialize(&encrypted).map_err(|_e| EncryptError::SerializeFail)
}

/// Decrypts an Encrypted structure using Aes128SivAead and returns a decrypted vector using the
/// given password
///
/// Password cannot be longer than 32 bytes
pub fn decrypt(password: &[u8], encrypted: &Encrypted) -> Result<Vec<u8>, DecryptError> {
    let mut key: [u8; 32] = [0; 32];

    if password.len() > key.len() {
        return Err(DecryptError::PasswordSize);
    };

    for (i, k) in password.iter().enumerate() {
        if i >= key.len() {
            break;
        } else {
            key[i] = *k;
        }
    }
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128SivAead::new(key);
    let noncearray = GenericArray::from_slice(&encrypted.nonce);

    let bytes = cipher
        .decrypt(noncearray, encrypted.ciphertext.as_ref())
        .map_err(|_e| DecryptError::DecryptFail)?;

    Ok(bytes)
}

/// Assumes that the given bytes is a Bincode serialized Encrypted structure, and first
/// deserializes it and then tries to decrypt it using the given password bytes
///
/// Password cannot be longer than 32 bytes
pub fn deserialize_and_decrypt(
    password: &[u8],
    serialized: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let deser: Encrypted =
        bincode::deserialize(&serialized).map_err(|_e| DecryptError::DeserializeFail)?;

    let plain = decrypt(&password[..], &deser).map_err(|_e| DecryptError::DecryptFail)?;

    Ok(plain)
}
