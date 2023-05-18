use self::{collection::Collection, value::Value};
use crate::{error::ParseError, hash::HashFunction};
use std::collections::HashMap;

pub mod collection;
pub mod record;
pub mod value;

pub const VERSION_BYTES_LENGTH: usize = 4;

pub type Entries = HashMap<String, Value>;

pub struct Swd {
    header: Header,
    root: Collection,
}

pub const REQUIRED_HEADER_FIELDS: [&str; 4] = ["v", "mkhf", "khf", "salt"];

pub struct Header {
    version: u32,
    master_key_hash_function_name: String,
    master_key_hash_function: Option<HashFunction>,
    salt: String,
    key_hash_function_name: String,
    key_hash_function: Option<HashFunction>,
    extras: Entries,
}

impl Swd {
    pub fn new(header: Header, root_label: String) -> Self {
        Self {
            header,
            root: Collection::new(root_label),
        }
    }

    pub fn from_root(header: Header, root: Collection) -> Self {
        Self { header, root }
    }
}

impl Header {
    pub fn new(
        version: u32,
        master_key_hash_function_name: String,
        key_hash_function_name: String,
        salt: String,
        extras: Entries,
    ) -> Self {
        Self {
            version,
            master_key_hash_function_name,
            key_hash_function_name,
            salt,
            extras,
            master_key_hash_function: None,
            key_hash_function: None,
        }
    }

    pub fn set_version(&mut self, version: u32) {
        self.version = version;
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
        let master_key_hash_function_name = raw_header.remove("mkhf").unwrap().parse_string()?;
        let key_hash_function_name = raw_header.remove("khf").unwrap().parse_string()?;
        let salt = raw_header.remove("salt").unwrap().parse_string()?;

        Ok(Self::new(
            0,
            master_key_hash_function_name,
            key_hash_function_name,
            salt,
            raw_header,
        ))
    }
}
