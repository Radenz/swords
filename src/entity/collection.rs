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
#[derive(Debug)]
pub struct Collection {
    label: String,
    children: Vec<Collection>,
    records: Vec<Record>,
    extras: Entries,
}

impl Collection {
    pub fn new(label: String) -> Self {
        Self {
            label,
            children: vec![],
            records: vec![],
            extras: HashMap::new(),
        }
    }

    pub fn label(&self) -> &String {
        &self.label
    }

    pub fn children(&self) -> &Vec<Collection> {
        &self.children
    }

    pub fn records(&self) -> &Vec<Record> {
        &self.records
    }

    pub fn get_record(&self, index: usize) -> Option<&Record> {
        self.records.get(index)
    }

    pub fn get_record_mut(&mut self, index: usize) -> Option<&mut Record> {
        self.records.get_mut(index)
    }

    pub fn get_child(&self, index: usize) -> Option<&Collection> {
        self.children.get(index)
    }

    pub fn get_child_mut(&mut self, index: usize) -> Option<&mut Collection> {
        self.children.get_mut(index)
    }

    pub fn set_label(&mut self, label: &str) {
        self.label = label.to_owned();
    }

    pub fn add_extra(&mut self, key: &str, value: &[u8], is_secret: bool) {
        self.extras
            .insert(key.to_owned(), Value::new(value, is_secret));
    }

    pub fn get_extra(&self, key: &str) -> Option<&Value> {
        self.extras.get(key)
    }

    pub fn add_record(&mut self, record: Record) {
        self.records.push(record);
    }

    pub fn add_child(&mut self, child: Collection) {
        self.children.push(child);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.push(COLLECTION_STARTER_BYTE);

        for (key, value) in self.extras.iter() {
            bytes.extend_from_slice(&Value::str_to_bytes(key, false));
            bytes.extend_from_slice(&value.to_bytes());
        }

        for collection in self.children.iter() {
            bytes.extend_from_slice(&collection.to_bytes());
        }

        for record in self.records.iter() {
            bytes.extend_from_slice(&record.to_bytes());
        }

        bytes.push(COLLECTION_ENDER_BYTE);
        bytes
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

        let label = extras.remove("label").unwrap().parse_string()?;

        Ok(Self {
            label,
            children,
            records,
            extras,
        })
    }
}
