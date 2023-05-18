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
