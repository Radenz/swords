#![allow(unused)]

use std::{
    collections::HashMap,
    fs::{read, File},
    io::{stdout, Write},
    ops::Index,
    path::Path,
    thread,
    time::Duration,
};

use arboard::Clipboard;
use clap::{Args, Parser as CliParser, Subcommand};
use crossterm::{
    cursor::{MoveTo, RestorePosition, SavePosition},
    event::{self, Event, KeyEventKind},
    execute,
    style::{
        Attribute, Color, Print, ResetColor, SetAttribute, SetBackgroundColor, SetForegroundColor,
    },
    terminal::{Clear, ClearType},
};
use inquire::{Password, PasswordDisplayMode, Select, Text};
use rand::RngCore;
use swords::{
    cipher::{Cipher, CipherRegistry},
    entity::{collection::Collection, record::Record, Header, Swd},
    hash::HashFunctionRegistry,
    io::parser::Parser,
};

// FIXME: derive version from Cargo.toml
// TODO: find a way to fit MAJOR.MINOR.PATCH format
// into u32
const VERSION: u32 = 1;

fn main() {
    // let Cli { command } = Cli::parse();
    let command = Commands::Open(OpenArgs {
        file_path: "passwords".to_owned(),
    });

    match command {
        Commands::New(args) => new(args),
        Commands::Open(args) => {
            let result = open(args);
            if let Some(swd) = result {
                interact(swd);
            }
        }
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

// FIXME: return Result instead
fn open(args: OpenArgs) -> Option<Swd> {
    let OpenArgs { mut file_path } = args;
    if !file_path.ends_with(".swd") {
        file_path.push_str(".swd");
    }

    if !file_exists(&file_path) {
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("File does not exist"),
            ResetColor
        );
        return None;
    }

    let result = read(file_path);
    if let Err(err) = result {
        println!("{}", err);
        return None;
    }
    let mut parser = Parser::new();
    let result = parser.parse(&result.unwrap());
    if let Err(parse_error) = result {
        println!("{:?}", parse_error);
        return None;
    }

    Some(result.unwrap())
}

const ROOT_MENU: [&str; 5] = [
    "Collections",
    "Records",
    "New Collection",
    "New Record",
    "Exit",
];

const COLLECTION_MENU: [&str; 5] = [
    "Collections",
    "Records",
    "New Collection",
    "New Record",
    "Back",
];

const RECORD_MENU: [&str; 2] = ["Copy Secret to Clipboard", "Back"];

struct CliState<'a> {
    path: Vec<String>,
    cipher: Cipher<'a>,
    key: Vec<u8>,
}

fn interact(mut swd: Swd) {
    authenticate(&mut swd);

    let cipher_name = swd.header().key_cipher();
    let cipher_registry = CipherRegistry::default();
    let encrypt = cipher_registry.get_encryptor(cipher_name);
    let decrypt = cipher_registry.get_decryptor(cipher_name);

    let key = swd.header().get_key().unwrap().clone();

    let mut state = CliState {
        path: vec![],
        key,
        cipher: (encrypt, decrypt),
    };

    loop {
        execute!(stdout(), Clear(ClearType::All), MoveTo(0, 0));

        let menu = Select::new(swd.get_root().label(), ROOT_MENU.to_vec())
            .prompt()
            .expect("there was an error while selecting");

        match menu {
            "Collections" => show_collections(swd.get_root_mut(), &mut state),
            "Records" => show_records(swd.get_root_mut(), &mut state),
            "New Collections" => add_new_collection(swd.get_root_mut(), &mut state),
            "New Record" => add_new_record(swd.get_root_mut(), &mut state),
            "Exit" => {
                todo!("save")
            }
            _ => unreachable!(),
        }
    }
}

fn interact_collection(collection: &mut Collection, state: &mut CliState) {
    state.path.push(collection.label().to_owned());

    loop {
        execute!(stdout(), Clear(ClearType::All), MoveTo(0, 0));

        let menu = Select::new(collection.label(), COLLECTION_MENU.to_vec())
            .prompt()
            .expect("there was an error while selecting");

        match menu {
            "Collections" => show_collections(collection, state),
            "Records" => show_records(collection, state),
            "New Collections" => add_new_collection(collection, state),
            "New Record" => add_new_record(collection, state),
            "Back" => {
                state.path.pop();
                return;
            }
            _ => unreachable!(),
        }
    }
}

fn show_collections(collection: &mut Collection, state: &mut CliState) {
    loop {
        execute!(stdout(), Clear(ClearType::All), MoveTo(0, 0));

        let mut children: Vec<String> = collection
            .children()
            .iter()
            .enumerate()
            .map(|(index, child)| format!("[{}] {}", index + 1, child.label()))
            .collect();
        children.push("[<] Back".to_owned());

        let choice = Select::new("Collections", children.clone())
            .prompt()
            .expect("there was an error while selecting");

        if &choice == "[<] Back" {
            return;
        }

        let index = children
            .iter()
            .position(|child| *child == choice)
            .expect("BUG: this should never panic");

        let child = collection.get_child_mut(index).unwrap();

        interact_collection(child, state);
    }
}

fn show_records(collection: &mut Collection, state: &mut CliState) {
    loop {
        execute!(stdout(), Clear(ClearType::All), MoveTo(0, 0));

        let mut records: Vec<String> = collection
            .records()
            .iter()
            .enumerate()
            .map(|(index, child)| format!("[{}] {}", index + 1, child.label()))
            .collect();
        records.push("[<] Back".to_owned());

        let choice = Select::new("Records", records.clone())
            .prompt()
            .expect("there was an error while selecting");

        if &choice == "[<] Back" {
            return;
        }

        let index = records
            .iter()
            .position(|child| *child == choice)
            .expect("BUG: this should never panic");

        let record = collection.get_record_mut(index).unwrap();

        interact_record(record, state);
    }
}

fn interact_record(record: &mut Record, state: &mut CliState) {
    let path = state.path.join("/") + record.label();
    loop {
        execute!(stdout(), Clear(ClearType::All), MoveTo(0, 0));

        let menu = Select::new(&format!("/{}", path), RECORD_MENU.to_vec())
            .prompt()
            .expect("there was an error while selecting");

        match menu {
            "Copy Secret to Clipboard" => {
                let mut clipboard = Clipboard::new().unwrap();
                let decrypt_fn = state.cipher.1;
                record.reveal(decrypt_fn, &state.key);
                let secret = record.revealed_secret().unwrap();
                clipboard.set_text(secret);

                execute!(
                    stdout(),
                    SetAttribute(Attribute::Bold),
                    SetForegroundColor(Color::Green),
                    Print("Secret has been copied to clipboard!\n"),
                    SetAttribute(Attribute::Reset),
                    ResetColor,
                    Print("Press any key to continue..."),
                );

                pause();
                state.path.pop();
                return;
            }
            "Back" => {
                state.path.pop();
                return;
            }
            _ => unreachable!(),
        }
    }
}

fn authenticate(swd: &mut Swd) -> String {
    execute!(stdout(), Clear(ClearType::All), MoveTo(0, 0));

    loop {
        let master_key = Password::new("Master key:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt()
            .expect("there was an error on password input");

        let unlocked = swd.unlock(master_key.as_bytes());
        if unlocked {
            return master_key;
        }

        execute!(
            stdout(),
            SetAttribute(Attribute::Bold),
            SetForegroundColor(Color::Red),
            Print("Wrong master key!\n"),
            SetAttribute(Attribute::Reset),
            ResetColor,
        );
    }
}

fn add_new_record(collection: &mut Collection, state: &mut CliState) {
    execute!(
        stdout(),
        Clear(ClearType::All),
        SetAttribute(Attribute::Bold),
        SetForegroundColor(Color::Cyan),
        Print(format!(
            "Creating a new record on {}\n",
            state.path.join("/")
        )),
        SetAttribute(Attribute::Reset)
    );

    let label = Text::new("Label:")
        .with_help_message("Leave blank to cancel")
        .prompt()
        .expect("there was an error");

    if label.len() == 0 {
        return;
    }

    let secret = Password::new("Secret:")
        .with_help_message("Secret to store in the record")
        .with_display_mode(PasswordDisplayMode::Masked)
        .prompt()
        .expect("there was an error");

    execute!(
        stdout(),
        SetForegroundColor(Color::Yellow),
        SavePosition,
        Print("Creating record..."),
        SetAttribute(Attribute::Reset),
        ResetColor,
    );

    let encrypt = state.cipher.0;

    // FIXME: refactor this so that it is not hardcoded
    let mut rng = rand::thread_rng();
    let mut nonce = [0; 12];
    rng.fill_bytes(&mut nonce);
    let mut extras = HashMap::new();
    extras.insert("nonce".to_owned(), &nonce[..]);

    let encrypted_secret =
        encrypt(secret.as_bytes(), &state.key, extras).expect("error while encrypting secret");
    let mut record = Record::new(label, encrypted_secret.into_boxed_slice());
    record.add_extra("nonce", &nonce, false);
    collection.add_record(record);

    execute!(
        stdout(),
        Clear(ClearType::CurrentLine),
        RestorePosition,
        SetAttribute(Attribute::Bold),
        SetForegroundColor(Color::Green),
        Print("Record created!\n"),
        SetAttribute(Attribute::Reset),
        ResetColor,
        Print("Press any key to continue..."),
    );

    pause();
}

fn add_new_collection(collection: &mut Collection, state: &mut CliState) {
    execute!(
        stdout(),
        Clear(ClearType::All),
        SetAttribute(Attribute::Bold),
        SetForegroundColor(Color::Cyan),
        Print(format!(
            "Creating a new collection on {}\n",
            state.path.join("/")
        )),
        SetAttribute(Attribute::Reset)
    );

    let label = Text::new("Label:")
        .with_help_message("Leave blank to cancel")
        .prompt()
        .expect("there was an error");

    if label.len() == 0 {
        return;
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Yellow),
        SavePosition,
        Print("Creating collection..."),
        SetAttribute(Attribute::Reset),
        ResetColor,
    );

    let child = Collection::new(label);
    collection.add_child(child);

    execute!(
        stdout(),
        Clear(ClearType::CurrentLine),
        RestorePosition,
        SetAttribute(Attribute::Bold),
        SetForegroundColor(Color::Green),
        Print("Collection created!\n"),
        SetAttribute(Attribute::Reset),
        ResetColor,
        Print("Press any key to continue..."),
    );

    pause();
}

fn pause() {
    loop {
        if let Ok(Event::Key(event)) = event::read() {
            if event.kind == KeyEventKind::Press {
                break;
            }
        }
    }
}

fn file_exists(path: &str) -> bool {
    let path = Path::new(path);
    path.exists() && path.is_file()
}

#[derive(CliParser)]
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
