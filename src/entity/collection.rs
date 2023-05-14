use std::collections::HashMap;

use crate::error::ParseError;

use super::{record::Record, value::Value, Entries};

pub const COLLECTION_STARTER_BYTE: u8 = 0x03;
pub const COLLECTION_ENDER_BYTE: u8 = 0x04;

pub const REQUIRED_COLLECTION_FIELDS: [&str; 1] = ["label"];

/// Collection structure
/// ```
/// [STARTER_BYTE]
/// [LENGTH]
/// [METADATA]:
///     [KEY] [VALUE]
///     [KEY] [VALUE]
///     ...
/// [CHILD_COLLECTION]
/// ...
/// [CHILD_COLLECTION]
/// [RECORD]
/// ...
/// [RECORD]
/// ```
///
/// Length consist of 4 byte ordered in big endian ordering
/// Length is required to determine where does the collection end
pub struct Collection {
    label: String,
    children: Vec<Collection>,
    records: Vec<Record>,
    extras: Entries,
}

impl Collection {
    pub fn new(label: String) -> Self {
        unimplemented!()
    }
}

impl TryFrom<(Vec<Collection>, Vec<Record>, Entries)> for Collection {
    type Error = ParseError;
    fn try_from(
        raw_collection: (Vec<Collection>, Vec<Record>, Entries),
    ) -> Result<Self, Self::Error> {
        let (children, records, mut extras) = raw_collection;

        for &required_field in REQUIRED_COLLECTION_FIELDS.iter() {
            if !extras.contains_key(required_field) {
                return Err(ParseError::MissingRequiredField(required_field.to_owned()));
            }

            if extras.get(required_field).unwrap().is_secret() {
                return Err(ParseError::ForbiddenSecretField(required_field.to_owned()));
            }
        }

        let label = extras.remove("label").unwrap().take();

        Ok(Self {
            label,
            children,
            records,
            extras,
        })
    }
}
