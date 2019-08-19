pub mod crypt;
pub mod data;
pub mod bash;

//use crypt::{encrypt, decrypt}

use std::time::{SystemTime, UNIX_EPOCH};
use std::str;
use std::path::PathBuf;
use std::process;
use colored::*;
use rustyline::error::ReadlineError;
use rustyline::{Editor};
use std::ffi::OsString;
use serde::{Serialize, Deserialize};
use serde_json::json;

use rustc_serialize::base64::{self, ToBase64, FromBase64};
use rustc_serialize::hex::{ToHex,FromHex};
use crate::data::get_path;

use std::env;

#[derive(Serialize, Deserialize)]
struct Manifest {
    alg: String,
    bits: u16,
    created_at: u32,
    enc_text: String,
    hash: String,
    iv: String
}

fn sign_in(meta: &PathBuf) {
    let mut der;
    let master_key;
    let data = data::read_file(meta);
    let manifest: Manifest = serde_json::from_str(&data).unwrap();
    loop {
        let mut pwd = rpassword::read_password_from_tty(Some("Your password: ")).unwrap();
        if pwd.is_empty() {
            println!("Please, type a valid password.");
            continue;
        }
        der = crypt::derive_password(&mut pwd, &"");
        let hash = crypt::sha_256(&der);
        if hash == manifest.hash {
            master_key = String::from(decrypt(&der, &manifest.iv, &manifest.enc_text).to_str().unwrap());
            break;
        } else {
            println!("Account not found. Try again, please.");
        }
    }
    println!("Welcome back! {}", "Type help or ? for help.".green());
    shell(&master_key);
}

fn sign_up(meta: &PathBuf) {
    let mut pwd;
    loop {
        pwd = rpassword::read_password_from_tty(Some("Choose a strong password: ")).unwrap();
        if pwd.is_empty() {
            println!("Please, type a valid password.");
            continue;
        }
        let pwd2 = rpassword::read_password_from_tty(Some("Retype it, please: ")).unwrap();
        if pwd == pwd2 {
            break;
        } else {
            println!("The two passwords don't match. Try again, please.");
        }
    }
    let der = crypt::derive_password(&mut pwd, &"");
    let hash = crypt::sha_256(&der);
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let master_key = crypt::random_key();

    let encrypted_master_key = encrypt(&der, &master_key);
    let manifest = json!({
        "hash": hash,
        "created_at": since_the_epoch.as_secs(),
        "iv": encrypted_master_key[0],
        "enc_text": encrypted_master_key[1],
        "alg": "Blowfish",
        "bits": 448
    });
    data::save_file(&meta, &manifest.to_string()).expect("It didn't save.");
    println!("Welcome! {}", "Type help for help.".green());
    shell(&master_key);
}

fn shell(master_key: &str) {
    let mut rl = Editor::<()>::new();

//    let root = Path::new("/");
//    assert!(env::set_current_dir(&root).is_ok());
//    println!("Successfully changed working directory to {}!", root.display());


//    let history = files::get_path(&"history");
//    if rl.load_history(&history).is_err() {
//        println!("No previous history.");
//    }

    let mut prompt = "> ";
    let mut current_path = get_path(&"/root");
    env::set_current_dir(&current_path).is_ok();
    let mut virtual_path = "/";

    loop {
        let readline = rl.readline(&prompt);
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                let words: Vec<&str> = line.split(' ').collect();
                match words[0] {

                    "quit" =>  {
                        process::exit(0x0100);
                    },

                    "ls" =>  {
                        bash::ls(&words);
                    },

                    "pwd" =>  {
                        bash::pwd(&words);
                    },

                    _ => println!("Line: {}", line)
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
//    let history = rl.history();
//    rl.save_history(&history).unwrap();
}

fn encrypt(key: &str, plain_text: &str) -> [String; 2] {
    let iv_str = crypt::random_string(16);
    let key= crypt::key_448_bit(&key, &iv_str);
    let mut enc = crypt::encrypt(&key, &plain_text.as_bytes());
    [iv_str, enc]
}

fn decrypt(key: &str, iv_str: &str, hex_text: &str) -> OsString {
    let key = crypt::key_448_bit(&key, &iv_str);
    crypt::decrypt(&key, &hex_text)
}

fn main() {
    println!("\n\n{}", "Secrez v0.0.1".bold());
    data::ensure_dir(&"/root").expect("It didn't ensure the directory exists.");
    let meta = data::get_path("/manifest.json");
    if meta.exists() {
        sign_in(&meta);
    } else {
        sign_up(&meta);
    }
}


//// TEST
//
//let der = crypt::derive_password(&"cinesina", &"");
//let mut hash = crypt::sha256(&der);
//hash = crypt::hex_to_base64(hash);
//let rand_str = crypt::random_str(64);
//let mut master_key = crypt::sha256(&rand_str);
//println!("Master key {}", master_key);
//master_key = crypt::hex_to_base64(master_key);
//println!("Master key {}", master_key);
//let hex_enc_text = crypt::base64_to_hex(String::from(&master_key));
//println!("Master key {}", hex_enc_text);