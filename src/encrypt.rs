use std::collections::HashMap;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit, KeySizeUser, Nonce,
};

use crate::error::EncryptError;

pub type EncryptResult<T> = Result<T, EncryptError>;
pub type EncryptFn = dyn Fn(&[u8], &[u8], HashMap<String, &[u8]>) -> EncryptResult<Vec<u8>>;
pub type DecryptFn = dyn Fn(&[u8], &[u8], HashMap<String, &[u8]>) -> EncryptResult<Vec<u8>>;

pub struct CipherRegistry {
    enciphers: HashMap<String, Box<EncryptFn>>,
    deciphers: HashMap<String, Box<EncryptFn>>,
}

impl CipherRegistry {
    pub fn new() -> Self {
        Self {
            enciphers: HashMap::new(),
            deciphers: HashMap::new(),
        }
    }

    pub fn register_encipher(&mut self, name: &str, encrypt_fn: Box<EncryptFn>) {
        self.enciphers.insert(name.to_owned(), encrypt_fn);
    }

    pub fn register_decipher(&mut self, name: &str, decrypt_fn: Box<DecryptFn>) {
        self.deciphers.insert(name.to_owned(), decrypt_fn);
    }
}

impl Default for CipherRegistry {
    fn default() -> Self {
        let mut registry = CipherRegistry::new();
        registry.register_encipher("aes-gcm", Box::new(aes_encrypt));
        registry.register_encipher("aes-gcm", Box::new(aes_decrypt));
        registry
    }
}

fn aes_encrypt(
    data: &[u8],
    key: &[u8],
    mut extras: HashMap<String, &[u8]>,
) -> EncryptResult<Vec<u8>> {
    let key = GenericArray::<u8, <Aes256Gcm as KeySizeUser>::KeySize>::from_slice(key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = extras
        .remove("nonce")
        .ok_or(EncryptError::MissingRequiredExtra("nonce".to_owned()))?;
    let encrypted = cipher.encrypt(Nonce::from_slice(nonce), data);
    encrypted.map_err(|_| EncryptError::EncryptionError)
}

fn aes_decrypt(
    data: &[u8],
    key: &[u8],
    mut extras: HashMap<String, &[u8]>,
) -> EncryptResult<Vec<u8>> {
    let key = GenericArray::<u8, <Aes256Gcm as KeySizeUser>::KeySize>::from_slice(key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = extras
        .remove("nonce")
        .ok_or(EncryptError::MissingRequiredExtra("nonce".to_owned()))?;
    let encrypted = cipher.decrypt(Nonce::from_slice(nonce), data);
    encrypted.map_err(|_| EncryptError::EncryptionError)
}
