use rand::Rng;
use std::fs;
use std::fs::*;
use std::io::prelude::*;
use crypto::bcrypt_pbkdf::bcrypt_pbkdf;
use std::path::{Path, PathBuf};
use std::process;
use colored::*;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use aes_soft::Aes256;
use hex_literal::hex;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn encrypt_and_save(filename: &Path, plaintext: &str) -> [u8; 32] {
    let key = hex!("000102030405060708090a0b0c0d0e0f");
    let mut rng = rand::thread_rng();
    let mut iv = [16; 0];
    for i in 1..16 {
        iv[i] = rng.gen::<u8>();
    }
    let plaintext = plaintext.as_bytes();
    let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
    let mut buffer = [0u8; 32];
    let pos = plaintext.len();
    buffer[..pos].copy_from_slice(plaintext);
    let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();

//    println!("ciphertext {}", buffer[0]);

    buffer

//    assert_eq!(ciphertext, hex!("1b7a4c403124ae2fb52bedc534d82fa8"));
//
//// re-create cipher mode instance and decrypt the message
//    let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
//    let mut buf = ciphertext.to_vec();
//    let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();
//
//    assert_eq!(decrypted_ciphertext, plaintext);
}


fn get_path(p: &str) -> PathBuf {
    let homedir = dirs::home_dir().unwrap();
    homedir.join(".secrez".to_owned() + p)
}

fn ensure_dir(d: &str) -> std::io::Result<()> {
    fs::create_dir(get_path(d))?;
    Ok(())
}

fn save_file(filename: &Path, text: &str) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(text.as_bytes()).expect("I can't save");
    Ok(())
}

fn read_file(filename: &Path) -> String {
    let mut file = File::open(filename).expect("File does not exist.");
    let mut contents = String::new();
    file.read_to_string(&mut contents);
    contents
}

fn list_files(path: PathBuf) -> Vec<PathBuf> {
    let mut res = vec![];
    for entry in path.read_dir().expect("read_dir call failed") {
        if let Ok(entry) = entry {
            res.push(entry.path());
        }
    }
    res
}

fn derive_password(password: &str, salt: &str) -> String {
    let mut out = [0u8; 32];
    bcrypt_pbkdf(password.as_bytes(), salt.as_bytes(), 33, &mut out);
    let mut password_hash = String::with_capacity(out.len() * 2);
    for c in out.iter() {
        password_hash.push_str(&format!("{:02x}", c));
    }
    password_hash
}

fn main() {
    println!("\n\n{}", "Secrez v0.0.1".bold());
    ensure_dir(&"");
    let meta = get_path("/meta");

    let key = hex!("000102030405060708090a0b0c0d0e0f");
    encrypt_and_save(&meta, &"Dove si va al mare");//, &key);


    let list = list_files(get_path(&""));
    if list.len() == 0 {
        signup(&meta);
    } else {
        login(&meta);
    }
}

fn login(meta: &PathBuf) {
    let mut der;
    let hash = read_file(meta);
    loop {
        let mut pwd = rpassword::read_password_from_tty(Some("Password: ")).unwrap();
        der = derive_password(&mut pwd, "salt");

        if der == hash {
            break;
        } else {
            println!("Account not found. Try again, please.");
        }
    }
    println!("Welcome back! {}", "Type help or ? for help.".cyan());
    shell(&der);
}

fn signup(meta: &PathBuf) {
    let mut der;
    let mut pwd;
    loop {
        pwd = rpassword::read_password_from_tty(Some("Choose a strong password: ")).unwrap();
        let pwd2 = rpassword::read_password_from_tty(Some("Retype it, please: ")).unwrap();
        if pwd == pwd2 {
            break;
        } else {
            println!("The two passwords don't match. Try again, please.");
        }
    }
    der = derive_password(&mut pwd, "salt");
    save_file(&meta, &der);
    println!("Welcome! {}", "Type help for help.".cyan());
    shell(&der);
}

fn shell(der: &str) {
    let mut rl = Editor::<()>::new();

// TODO load encrypted history, instead
//
//    if rl.load_history("history.txt").is_err() {
//        println!("No previous history.");
//    }

    let mut prompt = "> ";
    let quit = String::from("quit");

    loop {
        let readline = rl.readline(&prompt);
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                if line == quit {
                    process::exit(0x0100);
                }
                println!("Line: {}", line);
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
//    rl.save_history("history.txt").unwrap();
}
