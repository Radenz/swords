use std::collections::HashMap;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit, KeySizeUser, Nonce,
};

use crate::error::CipherError;

pub type CipherResult<T> = Result<T, CipherError>;
pub type EncryptFn = dyn Fn(&[u8], &[u8], HashMap<String, &[u8]>) -> CipherResult<Vec<u8>>;
pub type DecryptFn = dyn Fn(&[u8], &[u8], HashMap<String, &[u8]>) -> CipherResult<Vec<u8>>;

pub struct CipherRegistry {
    encrypt_functions: HashMap<String, Box<EncryptFn>>,
    decrypt_functions: HashMap<String, Box<EncryptFn>>,
}

impl CipherRegistry {
    pub fn new() -> Self {
        Self {
            encrypt_functions: HashMap::new(),
            decrypt_functions: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, encrypt_fn: Box<EncryptFn>, decrypt_fn: Box<DecryptFn>) {
        self.encrypt_functions.insert(name.to_owned(), encrypt_fn);
        self.decrypt_functions.insert(name.to_owned(), decrypt_fn);
    }

    pub fn get_encryptor(&self, name: &str) -> &Box<EncryptFn> {
        self.encrypt_functions.get(name).unwrap()
    }

    pub fn get_decryptor(&self, name: &str) -> &Box<DecryptFn> {
        self.decrypt_functions.get(name).unwrap()
    }
}

impl Default for CipherRegistry {
    fn default() -> Self {
        let mut registry = CipherRegistry::new();
        registry.register("aes-gcm", Box::new(aes_encrypt), Box::new(aes_decrypt));
        registry
    }
}

fn aes_encrypt(
    data: &[u8],
    key: &[u8],
    mut extras: HashMap<String, &[u8]>,
) -> CipherResult<Vec<u8>> {
    let key = GenericArray::<u8, <Aes256Gcm as KeySizeUser>::KeySize>::from_slice(key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = extras
        .remove("nonce")
        .ok_or(CipherError::MissingRequiredExtra("nonce".to_owned()))?;
    let encrypted = cipher.encrypt(Nonce::from_slice(nonce), data);
    encrypted.map_err(|_| CipherError::EncryptionError)
}

fn aes_decrypt(
    data: &[u8],
    key: &[u8],
    mut extras: HashMap<String, &[u8]>,
) -> CipherResult<Vec<u8>> {
    let key = GenericArray::<u8, <Aes256Gcm as KeySizeUser>::KeySize>::from_slice(key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = extras
        .remove("nonce")
        .ok_or(CipherError::MissingRequiredExtra("nonce".to_owned()))?;
    let encrypted = cipher.decrypt(Nonce::from_slice(nonce), data);
    encrypted.map_err(|_| CipherError::EncryptionError)
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher::{aes_encrypt, CipherRegistry},
        error::CipherError,
    };
    use aes_gcm::{Aes256Gcm, KeySizeUser};
    use std::collections::HashMap;

    use super::aes_decrypt;

    #[test]
    fn aes_encrypt_ok() {
        let key: &mut [u8] = &mut [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let data = b"Example dummy data";
        let nonce: &[u8] = b"dummy nonce ";
        let mut extras = HashMap::new();
        extras.insert("nonce".to_owned(), nonce);
        let result = aes_encrypt(data, key, extras);
        assert!(result.is_ok());
    }

    #[test]
    fn aes_encrypt_missing_nonce() {
        let key: &mut [u8] = &mut [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let data = b"Example dummy data";
        let nonce: &[u8] = b"dummy nonce ";
        let mut extras = HashMap::new();
        let result = aes_encrypt(data, key, extras);
        assert_eq!(
            result,
            Err(CipherError::MissingRequiredExtra("nonce".to_owned()))
        );
    }

    #[test]
    fn aes_decrypt_ok() {
        let key: &mut [u8] = &mut [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let data = b"Example dummy data";
        let nonce: &[u8] = b"dummy nonce ";
        let mut extras = HashMap::new();
        extras.insert("nonce".to_owned(), nonce);
        let result = aes_encrypt(data, key, extras.clone());
        let encrypted = result.unwrap();
        let result = aes_decrypt(&encrypted, key, extras);
        assert!(result.is_ok());
        let decrypted = result.unwrap();
        assert_eq!(&decrypted, data);
    }

    #[test]
    fn aes_decrypt_missing_nonce() {
        let key: &mut [u8] = &mut [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let data = b"Example dummy data";
        let nonce: &[u8] = b"dummy nonce ";
        let mut extras = HashMap::new();
        extras.insert("nonce".to_owned(), nonce);
        let result = aes_encrypt(data, key, extras.clone());
        let encrypted = result.unwrap();
        extras.remove("nonce");
        let result = aes_decrypt(&encrypted, key, extras);
        assert_eq!(
            result,
            Err(CipherError::MissingRequiredExtra("nonce".to_owned()))
        );
    }

    #[test]
    fn registry_encrypt_ok() {
        let key: &mut [u8] = &mut [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let data = b"Example dummy data";
        let nonce: &[u8] = b"dummy nonce ";
        let mut extras = HashMap::new();
        extras.insert("nonce".to_owned(), nonce);
        let registry = CipherRegistry::default();
        let encrypt = registry.get_encryptor("aes-gcm");
        let result = encrypt(data, key, extras);
        assert!(result.is_ok());
    }

    #[test]
    fn registry_decrypt_ok() {
        let key: &mut [u8] = &mut [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let data = b"Example dummy data";
        let nonce: &[u8] = b"dummy nonce ";
        let mut extras = HashMap::new();
        extras.insert("nonce".to_owned(), nonce);
        let result = aes_encrypt(data, key, extras.clone());
        let encrypted = result.unwrap();
        let registry = CipherRegistry::default();
        let decrypt = registry.get_decryptor("aes-gcm");
        let result = decrypt(&encrypted, key, extras);
        assert!(result.is_ok());
        let decrypted = result.unwrap();
        assert_eq!(&decrypted, data);
    }
}
