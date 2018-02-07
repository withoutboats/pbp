#![feature(fs_read_write)]

extern crate pbp;
extern crate git2;

use std::env;
use std::fs;
use std::path::PathBuf;

use pbp::{PgpKey, PgpSig};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let props = root.join("examples").join("props");

    let sig: String = fs::read_string(props.join("sig.txt")).unwrap();
    let key: String = fs::read_string(props.join("key.txt")).unwrap();
    let data: String = fs::read_string(props.join("data.txt")).unwrap();

    let sig = PgpSig::from_ascii_armor(&sig).unwrap();
    let key = PgpKey::from_ascii_armor(&key).unwrap();

    if sig.verify_dalek(data.as_bytes(), &key.to_dalek().unwrap()) {
        println!("Verified signature.");
    } else {
        println!("Could not verify signature.");
    }
}
