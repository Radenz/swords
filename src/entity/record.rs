use std::collections::HashMap;

use crate::error::ParseError;

use super::{value::Value, Entries};

pub const RECORD_STARTER_BYTE: u8 = 0x02;
pub const REQUIRED_RECORD_FIELDS: [&str; 2] = ["label", "secret"];

/// Record structure
/// [STARTER_BYTE]
/// [KEY] [VALUE]
/// ...
/// [KEY] [VALUE]
pub struct Record {
    label: String,
    secret: String,
    revealed_secret: Option<String>,
    extras: Entries,
}

impl Record {
    pub fn new(label: String, secret: String) -> Self {
        Self {
            label,
            secret,
            extras: HashMap::new(),
            revealed_secret: None,
        }
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

        let label = raw_record.remove("label").unwrap().parse_string()?;
        let secret = raw_record.remove("secret").unwrap().parse_string()?;

        Ok(Self {
            label,
            secret,
            extras: raw_record,
            revealed_secret: None,
        })
    }
}
