use self::{collection::Collection, value::Value};
use crate::{
    cipher::CipherRegistry,
    error::ParseError,
    hash::{HashFunction, HashFunctionRegistry},
};
use std::collections::HashMap;

pub mod collection;
pub mod record;
pub mod value;

pub const VERSION_BYTES_LENGTH: usize = 4;

pub type Entries = HashMap<String, Value>;

pub struct Swd {
    header: Header,
    root: Collection,
    cipher_registry: CipherRegistry,
    hash_function_registry: HashFunctionRegistry,
}

pub const REQUIRED_HEADER_FIELDS: [&str; 6] = ["v", "mkhf", "khf", "mks", "ks", "mkh"];

pub struct Header {
    version: u32,
    master_key_hash_fn: String,
    key_hash_fn: String,
    master_key_hash: Vec<u8>,
    master_key_salt: Vec<u8>,
    key_salt: Vec<u8>,
    key: Option<Vec<u8>>,
    extras: Entries,
}

impl Swd {
    pub fn new(
        header: Header,
        root_label: String,
        cipher_registry: CipherRegistry,
        hash_function_registry: HashFunctionRegistry,
    ) -> Self {
        Self {
            header,
            root: Collection::new(root_label),
            cipher_registry,
            hash_function_registry,
        }
    }

    pub fn from_root(
        header: Header,
        root: Collection,
        cipher_registry: CipherRegistry,
        hash_function_registry: HashFunctionRegistry,
    ) -> Self {
        Self {
            header,
            root,
            cipher_registry,
            hash_function_registry,
        }
    }

    pub fn access(&mut self, master_key: &[u8]) -> bool {
        let valid = self.validate_master_key(master_key);
        if !valid {
            return false;
        }
        self.populate_key(master_key);
        true
    }

    fn validate_master_key(&self, master_key: &[u8]) -> bool {
        let hash = self.get_master_key_hash_fn();
        let mut master_key = master_key.to_vec();
        master_key.extend_from_slice(self.header.master_key_salt());
        let master_key_hash = hash(&master_key);
        let stored_master_key_hash = self.header.master_key_hash();
        &master_key_hash == stored_master_key_hash
    }

    fn populate_key(&mut self, master_key: &[u8]) {
        let hash = self.get_key_hash_fn();
        let mut master_key = master_key.to_vec();
        master_key.extend_from_slice(self.header.key_salt());
        let key = hash(&master_key);
        self.header.set_key(key);
    }

    fn get_master_key_hash_fn(&self) -> &Box<HashFunction> {
        let master_key_hash_fn = self.header.master_key_hash_fn();
        let hash_fn = self.hash_function_registry.get_function(master_key_hash_fn);
        hash_fn
    }

    fn get_key_hash_fn(&self) -> &Box<HashFunction> {
        let key_hash_fn = self.header.key_hash_fn();
        let hash_fn = self.hash_function_registry.get_function(key_hash_fn);
        hash_fn
    }
}

impl Header {
    pub fn new(
        version: u32,
        master_key_hash_function_name: String,
        key_hash_function_name: String,
        master_key_hash: &[u8],
        master_key_salt: &[u8],
        key_salt: &[u8],
        extras: Entries,
    ) -> Self {
        Self {
            version,
            master_key_hash_fn: master_key_hash_function_name,
            key_hash_fn: key_hash_function_name,
            master_key_hash: master_key_hash.to_vec(),
            master_key_salt: master_key_salt.to_vec(),
            key_salt: key_salt.to_vec(),
            key: None,
            extras,
        }
    }

    pub fn master_key_hash_fn(&self) -> &String {
        &self.master_key_hash_fn
    }

    pub fn master_key_hash(&self) -> &Vec<u8> {
        &self.master_key_hash
    }

    pub fn master_key_salt(&self) -> &Vec<u8> {
        &self.master_key_salt
    }

    pub fn key_hash_fn(&self) -> &String {
        &self.key_hash_fn
    }

    pub fn key_salt(&self) -> &Vec<u8> {
        &self.key_salt
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.key = Some(key);
    }

    pub fn get_key(&self) -> Option<&Vec<u8>> {
        self.key.as_ref()
    }
}

impl TryFrom<Entries> for Header {
    type Error = ParseError;
    fn try_from(mut raw_header: Entries) -> Result<Self, Self::Error> {
        for &required_field in REQUIRED_HEADER_FIELDS.iter() {
            if !raw_header.contains_key(required_field) {
                return Err(ParseError::MissingRequiredField(required_field.to_owned()));
            }

            if raw_header.get(required_field).unwrap().is_secret() {
                return Err(ParseError::ForbiddenSecretField(required_field.to_owned()));
            }
        }

        let version_bytes = raw_header.remove("mkhf").unwrap().take();
        if version_bytes.len() != VERSION_BYTES_LENGTH {
            return Err(ParseError::InvalidVersionNumber);
        }
        let version = u32::from_be_bytes((version_bytes[0..4]).try_into().unwrap());
        let master_key_hash_fn = raw_header.remove("mkhf").unwrap().parse_string()?;
        let key_hash_fn = raw_header.remove("khf").unwrap().parse_string()?;
        let master_key_salt = raw_header.remove("mks").unwrap().take();
        let key_salt = raw_header.remove("ks").unwrap().take();
        let master_key_hash = raw_header.remove("mkh").unwrap().take();

        Ok(Self::new(
            0,
            master_key_hash_fn,
            key_hash_fn,
            &master_key_hash,
            &master_key_salt,
            &key_salt,
            raw_header,
        ))
    }
}
