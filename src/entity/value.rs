use std::str::Utf8Error;

use crate::{error::ParseError, io::parser::ParseResult};

#[derive(Debug)]
pub struct Value {
    value: Box<[u8]>,
    revealed_value: Option<String>,
    is_secret: bool,
}

pub const VALUE_STARTER_BYTE: u8 = 0x00;
pub const KEY_STARTER_BYTE: u8 = 0x00;
pub const SECRET_VALUE_STARTER_BYTE: u8 = 0x01;
pub const VALUE_LENGTH_BYTES_LENGTH: usize = 2;

impl Value {
    pub fn new(value: &[u8], is_secret: bool) -> Self {
        Self {
            value: value.into(),
            is_secret,
            revealed_value: None,
        }
    }

    pub fn parse_string(self) -> ParseResult<String> {
        self.try_into()
            .map_err(|err| ParseError::EncodingError(err))
    }

    pub fn is_secret(&self) -> bool {
        self.is_secret
    }

    pub fn take(self) -> Box<[u8]> {
        self.value
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let length = self.value.len();
        let size = length + VALUE_LENGTH_BYTES_LENGTH;
        let mut bytes: Vec<u8> = Vec::with_capacity(size);
        let length_bytes = &(length as u16).to_be_bytes();
        bytes.extend_from_slice(length_bytes);
        bytes.extend_from_slice(&self.value);
        bytes
    }
}

impl TryFrom<Value> for String {
    type Error = Utf8Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(std::str::from_utf8(&value.value)?.to_owned())
    }
}
