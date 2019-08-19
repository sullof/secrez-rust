use std::fs;
use std::fs::*;
use std::str;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;

//pub struct Command {
//
//}
//
//impl Command {
//
//    pub fn run() {
//
//    }
//
//}


pub fn ls(words: &Vec<&str>) {
    let mut param = "-";
    if !words[1].is_empty() {
        param = words[1];
    }
    let output = Command::new("ls")
        .arg(param)
        .output()
        .expect("failed to execute process");

    println!("{:?}", String::from_utf8_lossy(&output.stdout));
}

pub fn pwd(words: &Vec<&str>) {
    let output = Command::new("pwd")
        .output()
        .expect("failed to execute process");

    println!("{:?}", String::from_utf8_lossy(&output.stdout));
}