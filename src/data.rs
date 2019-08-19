use std::fs;
use std::fs::*;
use std::str;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

pub fn get_path(p: &str) -> PathBuf {
    let homedir = dirs::home_dir().unwrap();
    homedir.join(".secrez".to_owned() + p)
}

pub fn ensure_dir(d: &str) -> std::io::Result<()> {
    let dir = get_path(d);
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

pub fn save_file(filename: &Path, text: &str) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(text.as_bytes()).expect("I can't save");
    Ok(())
}

pub fn read_file(filename: &Path) -> String {
    let mut file = File::open(filename).expect("File does not exist.");
    let mut contents = String::new();
    file.read_to_string(&mut contents);
    contents
}

pub fn list_files(path: PathBuf) -> Vec<PathBuf> {
    let mut res = vec![];
    for entry in path.read_dir().expect("read_dir call failed") {
        if let Ok(entry) = entry {
            res.push(entry.path());
        }
    }
    res
}
