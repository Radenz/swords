use std::collections::HashMap;

use crate::error::ParseError;

use super::{value::Value, Entries};

pub const RECORD_STARTER_BYTE: u8 = 0x02;
pub const REQUIRED_RECORD_FIELDS: [&str; 1] = ["label"];
pub const REQUIRED_RECORD_SECRET_FIELDS: [&str; 1] = ["secret"];

/// Record structure
///
/// [STARTER_BYTE]
/// [KEY] [VALUE]
/// ...
/// [KEY] [VALUE]
#[derive(Debug)]
pub struct Record {
    label: String,
    secret: Box<[u8]>,
    revealed_secret: Option<String>,
    extras: Entries,
}

impl Record {
    pub fn new(label: String, secret: Box<[u8]>) -> Self {
        Self {
            label,
            secret,
            extras: HashMap::new(),
            revealed_secret: None,
        }
    }

    pub fn label(&self) -> &String {
        &self.label
    }

    pub fn secret(&self) -> &Box<[u8]> {
        &self.secret
    }

    pub fn revealed_secret(&self) -> Option<&String> {
        self.revealed_secret.as_ref()
    }

    pub fn reveal(&mut self, encrypt_fn: impl FnOnce(&[u8], &[u8]) -> bool) {
        unimplemented!()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&Self::label_bytes());
        bytes.extend_from_slice(&Value::str_to_bytes(&self.label, false));
        bytes.extend_from_slice(&Self::secret_bytes());
        bytes.extend_from_slice(&Value::new(&self.secret, true).to_bytes());

        for (key, value) in self.extras.iter() {
            bytes.extend_from_slice(&Value::str_to_bytes(key, false));
            bytes.extend_from_slice(&value.to_bytes());
        }

        bytes
    }

    fn label_bytes() -> Vec<u8> {
        Value::new(b"label", false).to_bytes()
    }

    fn secret_bytes() -> Vec<u8> {
        Value::new(b"secret", false).to_bytes()
    }
}

impl TryFrom<Entries> for Record {
    type Error = ParseError;
    fn try_from(mut raw_record: Entries) -> Result<Self, Self::Error> {
        for &required_field in REQUIRED_RECORD_FIELDS.iter() {
            if !raw_record.contains_key(required_field) {
                return Err(ParseError::MissingRequiredField(required_field.to_owned()));
            }

            if raw_record.get(required_field).unwrap().is_secret() {
                return Err(ParseError::ForbiddenSecretField(required_field.to_owned()));
            }
        }

        for &required_field in REQUIRED_RECORD_SECRET_FIELDS.iter() {
            if !raw_record.contains_key(required_field) {
                return Err(ParseError::MissingRequiredField(required_field.to_owned()));
            }

            if !raw_record.get(required_field).unwrap().is_secret() {
                return Err(ParseError::ForbiddenNonSecretField(
                    required_field.to_owned(),
                ));
            }
        }

        let label = raw_record.remove("label").unwrap().parse_string()?;
        let secret = raw_record.remove("secret").unwrap().take();

        Ok(Self {
            label,
            secret,
            extras: raw_record,
            revealed_secret: None,
        })
    }
}
