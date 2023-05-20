#![allow(unused)]

use std::{
    collections::HashMap,
    fs::File,
    io::{stdout, Write},
    path::Path,
};

use clap::{Args, Parser, Subcommand};
use crossterm::{
    cursor::MoveTo,
    execute,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{Clear, ClearType},
};
use inquire::{Password, PasswordDisplayMode, Select};
use rand::RngCore;
use swords::{
    cipher::CipherRegistry,
    entity::{Header, Swd},
    hash::HashFunctionRegistry,
};

// FIXME: derive version from Cargo.toml
// TODO: find a way to fit MAJOR.MINOR.PATCH format
// into u32
const VERSION: u32 = 1;

fn main() {
    let Cli { command } = Cli::parse();

    match command {
        Commands::New(args) => new(args),
        Commands::Open(args) => open(args),
    }
}

fn new(args: NewArgs) {
    let NewArgs { mut file_path } = args;
    let name = file_path.clone();
    file_path.push_str(".swd");
    if file_exists(&file_path) {
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("File already exist"),
            ResetColor
        );
        return;
    }

    execute!(stdout(), Clear(ClearType::All), MoveTo(0, 0));

    let master_key = loop {
        let result = Password::new("Master key:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .prompt();
        match result {
            Ok(password) if password.len() > 8 => break password,
            _ => continue,
        }
    };

    let cipher_registry = CipherRegistry::default();
    let hash_registry = HashFunctionRegistry::default();

    let master_key_hash_function = loop {
        let result =
            Select::new("Choose master key hash function", hash_registry.get_names()).prompt();
        match result {
            Ok(hasher) => break hasher,
            _ => continue,
        }
    };

    let key_hash_function = loop {
        let result = Select::new("Choose key hash function", hash_registry.get_names()).prompt();
        match result {
            Ok(hasher) => break hasher,
            _ => continue,
        }
    };

    let key_cipher = loop {
        let result = Select::new("Choose key cipher", cipher_registry.get_names()).prompt();
        match result {
            Ok(cipher) => break cipher,
            _ => continue,
        }
    };

    let mut rng = rand::thread_rng();
    let mut master_key_salt = [0; 16];
    let mut key_salt = [0; 16];
    rng.fill_bytes(&mut master_key_salt);
    rng.fill_bytes(&mut key_salt);

    let mut salted_master_key = master_key.as_bytes().to_vec();
    salted_master_key.extend_from_slice(&master_key_salt);
    let hash = hash_registry.get_function(&master_key_hash_function);
    let master_key_hash = hash(&salted_master_key);

    let header = Header::new(
        VERSION,
        master_key_hash_function.to_owned(),
        key_hash_function.to_owned(),
        key_cipher.to_owned(),
        &master_key_hash,
        &master_key_salt,
        &key_salt,
        HashMap::new(),
    );

    let swd = Swd::new(header, name, cipher_registry, hash_registry);

    let mut file = File::create(file_path.clone()).expect("error creating file");
    file.write_all(&swd.to_bytes());

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!("{} was created", file_path)),
        ResetColor
    );
}

fn open(args: OpenArgs) {
    let OpenArgs { mut file_path } = args;
    file_path.push_str(".swd");
    if !file_exists(&file_path) {
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("File does not exist"),
            ResetColor
        );
        return;
    }

    unimplemented!()
}

fn file_exists(path: &str) -> bool {
    let path = Path::new(path);
    path.exists() && path.is_file()
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    New(NewArgs),
    Open(OpenArgs),
}

#[derive(Args)]
struct NewArgs {
    file_path: String,
}

#[derive(Args)]
struct OpenArgs {
    file_path: String,
}
