use self::{collection::Collection, value::Value};
use crate::{
    cipher::CipherRegistry,
    error::ParseError,
    hash::{HashFunction, HashFunctionRegistry},
    util::MAGIC_NUMBER,
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

    pub fn unlock(&mut self, master_key: &[u8]) -> bool {
        let valid = self.validate_master_key(master_key);
        if !valid {
            return false;
        }
        self.populate_key(master_key);
        true
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn add_extra(&mut self, key: &str, value: &[u8], is_secret: bool) {
        self.header
            .extras
            .insert(key.to_owned(), Value::new(value, is_secret));
    }

    pub fn get_extra(&self, key: &str) -> Option<&Value> {
        self.header.extras.get(key)
    }

    pub fn get_root(&self) -> &Collection {
        &self.root
    }

    pub fn get_root_mut(&mut self) -> &mut Collection {
        &mut self.root
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&MAGIC_NUMBER);
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.root.to_bytes());
        bytes
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

pub struct Header {
    version: u32,
    master_key_hash_fn: String,
    key_hash_fn: String,
    master_key_hash: Vec<u8>,
    key_cipher: String,
    master_key_salt: Vec<u8>,
    key_salt: Vec<u8>,
    key: Option<Vec<u8>>,
    extras: Entries,
}

pub const REQUIRED_HEADER_FIELDS: [&str; 7] = ["v", "mkhf", "khf", "mks", "ks", "mkh", "kc"];

impl Header {
    pub fn new(
        version: u32,
        master_key_hash_function_name: String,
        key_hash_function_name: String,
        key_cipher: String,
        master_key_hash: &[u8],
        master_key_salt: &[u8],
        key_salt: &[u8],
        extras: Entries,
    ) -> Self {
        Self {
            version,
            master_key_hash_fn: master_key_hash_function_name,
            key_hash_fn: key_hash_function_name,
            key_cipher,
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&Value::str_to_bytes("v", false));
        bytes.extend_from_slice(&self.version_bytes());
        bytes.extend_from_slice(&Value::str_to_bytes("mkhf", false));
        bytes.extend_from_slice(&Value::str_to_bytes(&self.master_key_hash_fn(), false));
        bytes.extend_from_slice(&Value::str_to_bytes("khf", false));
        bytes.extend_from_slice(&Value::str_to_bytes(&self.key_hash_fn(), false));
        bytes.extend_from_slice(&Value::str_to_bytes("mks", false));
        bytes.extend_from_slice(self.master_key_salt());
        bytes.extend_from_slice(&Value::str_to_bytes("ks", false));
        bytes.extend_from_slice(self.key_salt());
        bytes.extend_from_slice(&Value::str_to_bytes("mkh", false));
        bytes.extend_from_slice(self.master_key_hash());

        for (key, value) in self.extras.iter() {
            bytes.extend_from_slice(&Value::str_to_bytes(key, false));
            bytes.extend_from_slice(&value.to_bytes());
        }

        bytes
    }

    fn version_bytes(&self) -> [u8; 4] {
        self.version.to_be_bytes()
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
        let key_cipher = raw_header.remove("kc").unwrap().parse_string()?;
        let master_key_salt = raw_header.remove("mks").unwrap().take();
        let key_salt = raw_header.remove("ks").unwrap().take();
        let master_key_hash = raw_header.remove("mkh").unwrap().take();

        Ok(Self::new(
            0,
            master_key_hash_fn,
            key_hash_fn,
            key_cipher,
            &master_key_hash,
            &master_key_salt,
            &key_salt,
            raw_header,
        ))
    }
}
