use std::{collections::HashMap, os::raw};

use crate::{
    entity::{
        collection::{Collection, COLLECTION_ENDER_BYTE, COLLECTION_STARTER_BYTE},
        record::{Record, RECORD_STARTER_BYTE},
        value::{Value, SECRET_VALUE_STARTER_BYTE, VALUE_STARTER_BYTE},
        Entries, Header, Swd, VERSION_BYTES_LENGTH,
    },
    error::ParseError,
    util::MAGIC_NUMBER,
};

pub type ParseResult<T> = Result<T, ParseError>;

struct Parser<'a> {
    remaining_input: &'a [u8],
}

impl<'a> Parser<'a> {
    pub fn new() -> Self {
        Self {
            remaining_input: &[],
        }
    }

    pub fn parse(&mut self, input: &'a [u8]) -> ParseResult<Swd> {
        self.remaining_input = input;
        self.ensure_magic_number()?;
        let header = self.parse_header()?;
        let collection = self.parse_collection()?;

        Ok(Swd::from_root(header, collection))
    }

    fn inject_input(&mut self, input: &'a [u8]) {
        self.remaining_input = input;
    }

    fn parse_header(&mut self) -> ParseResult<Header> {
        let version = self.parse_version()?;
        let mut raw_header: Entries = HashMap::new();

        self.ensure_remaining_input()?;

        let mut starter_byte = self.peek_starter_byte()?;
        while starter_byte == VALUE_STARTER_BYTE {
            let (key, value) = self.parse_key_value()?;
            raw_header.insert(key, value);

            starter_byte = self.peek_starter_byte()?;
        }

        let mut header: Header = raw_header.try_into()?;
        header.set_version(version);

        Ok(header)
    }

    fn parse_record(&mut self) -> ParseResult<Record> {
        let mut starter_byte = self.ensure_starter_byte(RECORD_STARTER_BYTE)?;
        let mut raw_record = HashMap::new();

        starter_byte = self.peek_starter_byte()?;
        while starter_byte == VALUE_STARTER_BYTE {
            let (key, value) = self.parse_key_value()?;
            raw_record.insert(key, value);

            starter_byte = self.peek_starter_byte()?;
        }

        let record: Record = raw_record.try_into()?;

        Ok(record)
    }

    fn parse_collection(&mut self) -> ParseResult<Collection> {
        let mut starter_byte = self.ensure_starter_byte(COLLECTION_STARTER_BYTE)?;
        let mut extras: Entries = HashMap::new();
        let mut records: Vec<Record> = vec![];
        let mut children: Vec<Collection> = vec![];

        starter_byte = self.peek_starter_byte()?;
        while starter_byte != COLLECTION_ENDER_BYTE {
            match starter_byte {
                VALUE_STARTER_BYTE => {
                    let (key, value) = self.parse_key_value()?;
                    extras.insert(key, value);
                }
                COLLECTION_STARTER_BYTE => {
                    let collection = self.parse_collection()?;
                    children.push(collection);
                }
                RECORD_STARTER_BYTE => {
                    let record = self.parse_record()?;
                    records.push(record);
                }
                _ => return Err(ParseError::UnexpectedStarterByte),
            }
            starter_byte = self.peek_starter_byte()?;
        }

        let raw_collection = (children, records, extras);
        let collection: Collection = raw_collection.try_into()?;

        Ok(collection)
    }

    fn parse_key_value(&mut self) -> ParseResult<(String, Value)> {
        let key = self.parse_value(false)?;
        let starter_byte = self.peek_starter_byte()?;
        let is_secret_value = starter_byte == SECRET_VALUE_STARTER_BYTE;
        let value = self.parse_value(is_secret_value)?;

        Ok((key.take(), value))
    }

    fn parse_value(&mut self, is_secret: bool) -> ParseResult<Value> {
        let starter_byte = if is_secret {
            SECRET_VALUE_STARTER_BYTE
        } else {
            VALUE_STARTER_BYTE
        };
        self.ensure_starter_byte(starter_byte)?;
        self.ensure_remaining_length_or(2, ParseError::UnexpectedEndOfFile)?;

        let (length_bytes, remaining_input) = self.remaining_input.split_at(2);
        self.remaining_input = remaining_input;
        let length: usize = u16::from_be_bytes(length_bytes.try_into().unwrap()) as usize;

        self.ensure_remaining_length(length, |remain, need| {
            ParseError::UnexpectedEndOfValue(remain, need)
        })?;

        let (value_bytes, remaining_input) = self.remaining_input.split_at(length);
        self.remaining_input = remaining_input;
        let value = std::str::from_utf8(value_bytes)
            .map_err(|err| ParseError::EncodingError(err))?
            .to_owned();

        Ok(Value::new(value, is_secret))
    }

    fn parse_version(&mut self) -> ParseResult<u32> {
        self.ensure_remaining_length_or(VERSION_BYTES_LENGTH, ParseError::UnexpectedEndOfFile)?;

        let (version_bytes, remaining_input) = self.remaining_input.split_at(VERSION_BYTES_LENGTH);
        self.remaining_input = remaining_input;
        let version = u32::from_be_bytes(version_bytes.try_into().unwrap());

        Ok(version)
    }

    fn ensure_magic_number(&mut self) -> ParseResult<()> {
        let magic_number =
            self.take_bytes_or(MAGIC_NUMBER.len(), ParseError::UnexpectedEndOfFile)?;
        if !Parser::check_magic_number(magic_number) {
            return Err(ParseError::InvalidMagicNumber);
        }
        Ok(())
    }

    fn ensure_starter_byte(&mut self, starter_byte: u8) -> ParseResult<u8> {
        self.ensure_remaining_input()?;
        if self.remaining_input[0] != starter_byte {
            return Err(ParseError::UnexpectedStarterByte);
        }
        self.remaining_input = &self.remaining_input[1..];
        Ok(starter_byte)
    }

    fn ensure_starter_byte_in(&mut self, starter_bytes: &[u8]) -> ParseResult<u8> {
        self.ensure_remaining_input()?;
        for &starter_byte in starter_bytes {
            if self.remaining_input[0] == starter_byte {
                self.remaining_input = &self.remaining_input[1..];
                return Ok(starter_byte);
            }
        }

        Err(ParseError::UnexpectedStarterByte)
    }

    fn peek_starter_byte(&mut self) -> ParseResult<u8> {
        self.ensure_remaining_input()?;
        Ok(self.remaining_input[0])
    }

    fn take_bytes(
        &mut self,
        length: usize,
        err_fn: impl FnOnce(usize, usize) -> ParseError,
    ) -> ParseResult<&[u8]> {
        self.ensure_remaining_length(MAGIC_NUMBER.len(), err_fn)?;
        let (bytes, remaining_input) = self.remaining_input.split_at(length);
        self.remaining_input = remaining_input;
        Ok(bytes)
    }

    fn take_bytes_or(&mut self, length: usize, err: ParseError) -> ParseResult<&[u8]> {
        self.take_bytes(length, |_, _| err)
    }

    fn check_magic_number(magic_number: &[u8]) -> bool {
        for i in 0..MAGIC_NUMBER.len() {
            if magic_number[i] != MAGIC_NUMBER[i] {
                return false;
            }
        }

        true
    }

    fn ensure_remaining_input(&self) -> ParseResult<()> {
        if self.remaining_input.len() == 0 {
            return Err(ParseError::UnexpectedEndOfFile);
        }

        Ok(())
    }

    fn ensure_remaining_length(
        &self,
        length: usize,
        err_fn: impl FnOnce(usize, usize) -> ParseError,
    ) -> ParseResult<()> {
        if self.remaining_input.len() < length {
            return Err(err_fn(self.remaining_input.len(), length));
        }

        Ok(())
    }

    fn ensure_remaining_length_or(&self, length: usize, err: ParseError) -> ParseResult<()> {
        self.ensure_remaining_length(length, |_, _| err)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        entity::value::{SECRET_VALUE_STARTER_BYTE, VALUE_STARTER_BYTE},
        error::ParseError,
        util::MAGIC_NUMBER,
    };

    use super::Parser;

    #[test]
    fn ensure_magic_number_success() {
        let mut parser = Parser::new();
        parser.inject_input(&MAGIC_NUMBER);
        assert!(parser.ensure_magic_number().is_ok())
    }

    #[test]
    fn ensure_magic_number_invalid() {
        let mut parser = Parser::new();
        parser.inject_input(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let result = parser.ensure_magic_number();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::InvalidMagicNumber)
    }

    #[test]
    fn ensure_magic_number_eof() {
        let mut parser = Parser::new();
        parser.inject_input(&MAGIC_NUMBER[0..4]);
        let result = parser.ensure_magic_number();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEndOfFile)
    }

    #[test]
    fn parse_version() {
        let mut parser = Parser::new();
        parser.inject_input(&[0, 0, 0, 1]);
        let result = parser.parse_version();
        assert!(result.is_ok());
        let version = result.unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn parse_value_success() {
        let mut parser = Parser::new();
        parser.inject_input(&[VALUE_STARTER_BYTE, 0, 5, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
        let result = parser.parse_value(false);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert!(!value.is_secret());
        assert_eq!(&value.take(), "hello");
    }

    #[test]
    fn parse_value_success_secret() {
        let mut parser = Parser::new();
        parser.inject_input(&[
            SECRET_VALUE_STARTER_BYTE,
            0,
            5,
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
        ]);
        let result = parser.parse_value(true);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert!(value.is_secret());
        assert_eq!(&value.take(), "hello");
    }

    #[test]
    fn parse_value_wrong_starter() {
        let mut parser = Parser::new();
        parser.inject_input(&[SECRET_VALUE_STARTER_BYTE]);
        let result = parser.parse_value(false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedStarterByte);
    }

    #[test]
    fn parse_value_wrong_starter_secret() {
        let mut parser = Parser::new();
        parser.inject_input(&[VALUE_STARTER_BYTE]);
        let result = parser.parse_value(true);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedStarterByte);
    }

    #[test]
    fn parse_value_invalid_starter() {
        let mut parser = Parser::new();
        parser.inject_input(&[0xff, 0, 0, 0]);
        let result = parser.parse_value(false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedStarterByte);
    }

    #[test]
    fn parse_value_empty() {
        let mut parser = Parser::new();
        parser.inject_input(&[]);
        let result = parser.parse_value(false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEndOfFile);
    }

    #[test]
    fn parse_value_eof_len() {
        let mut parser = Parser::new();
        parser.inject_input(&[VALUE_STARTER_BYTE, 0]);
        let result = parser.parse_value(false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEndOfFile);
    }

    #[test]
    fn parse_value_eof() {
        let mut parser = Parser::new();
        parser.inject_input(&[VALUE_STARTER_BYTE, 0, 3, 0, 0]);
        let result = parser.parse_value(false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEndOfValue(2, 3));
    }

    #[test]
    fn parse_key_value_success() {
        let mut parser = Parser::new();
        parser.inject_input(&[
            VALUE_STARTER_BYTE,
            0,
            3,
            0x6d,
            0x73,
            0x67,
            VALUE_STARTER_BYTE,
            0,
            5,
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
        ]);
        let result = parser.parse_key_value();
        assert!(result.is_ok());
        let (key, value) = result.unwrap();
        assert!(!value.is_secret());
        assert_eq!(&key, "msg");
        assert_eq!(&value.take(), "hello");
    }

    #[test]
    fn parse_key_value_success_secret() {
        let mut parser = Parser::new();
        parser.inject_input(&[
            VALUE_STARTER_BYTE,
            0,
            3,
            0x6d,
            0x73,
            0x67,
            SECRET_VALUE_STARTER_BYTE,
            0,
            5,
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
        ]);
        let result = parser.parse_key_value();
        assert!(result.is_ok());
        let (key, value) = result.unwrap();
        assert!(value.is_secret());
        assert_eq!(&key, "msg");
        assert_eq!(&value.take(), "hello");
    }

    #[test]
    fn parse_key_value_empty() {
        let mut parser = Parser::new();
        parser.inject_input(&[]);
        let result = parser.parse_key_value();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEndOfFile)
    }

    #[test]
    fn parse_key_value_secret_key() {
        let mut parser = Parser::new();
        parser.inject_input(&[
            SECRET_VALUE_STARTER_BYTE,
            0,
            3,
            0x6d,
            0x73,
            0x67,
            VALUE_STARTER_BYTE,
            0,
            5,
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
        ]);
        let result = parser.parse_key_value();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedStarterByte)
    }

    #[test]
    fn parse_key_value_unexpected_starter_byte() {
        let mut parser = Parser::new();
        parser.inject_input(&[
            0xff,
            0,
            3,
            0x6d,
            0x73,
            0x67,
            VALUE_STARTER_BYTE,
            0,
            5,
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
        ]);
        let result = parser.parse_key_value();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedStarterByte)
    }

    #[test]
    fn parse_key_value_eof_key() {
        let mut parser = Parser::new();
        parser.inject_input(&[VALUE_STARTER_BYTE, 0, 3, 0x6d]);
        let result = parser.parse_key_value();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEndOfValue(1, 3))
    }

    #[test]
    fn parse_key_value_eof_value() {
        let mut parser = Parser::new();
        parser.inject_input(&[
            VALUE_STARTER_BYTE,
            0,
            3,
            0x6d,
            0x73,
            0x67,
            VALUE_STARTER_BYTE,
            0,
            5,
            0x68,
            0x65,
            0x6c,
        ]);
        let result = parser.parse_key_value();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEndOfValue(3, 5))
    }

    #[test]
    fn parse_record_success() {
        todo!("Impl")
    }

    #[test]
    fn parse_record_missing_label() {
        todo!("Impl")
    }

    #[test]
    fn parse_record_missing_secret() {
        todo!("Impl")
    }

    #[test]
    fn parse_record_unexpected_eof() {
        todo!("Impl")
    }

    #[test]
    fn parse_collection() {
        todo!("Impl")
    }
}
