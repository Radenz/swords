use std::str::Utf8Error;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    InvalidMagicNumber,
    InvalidVersionNumber,
    UnexpectedStarterByte,
    UnexpectedEndOfFile,
    MissingRequiredField(String),
    ForbiddenSecretField(String),
    UnexpectedEndOfValue(usize, usize),
    EncodingError(Utf8Error),
}
