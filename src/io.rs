use std::{
    fs::File,
    io::{self, Read},
};

pub mod parser;

pub type IOResult<T> = io::Result<T>;

pub fn read_file(file_path: &str) -> IOResult<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}
