extern crate rand;
extern crate sha2;
extern crate ed25519_dalek as dalek;
extern crate pbp;

use rand::OsRng;
use sha2::{Sha256, Sha512};
use dalek::Keypair;
use pbp::PgpKey;

fn main() {
    let mut cspring = OsRng::new().unwrap();
    let keypair = Keypair::generate::<Sha512>(&mut cspring);

    let key = PgpKey::from_dalek::<Sha256, Sha512>(&keypair, "withoutboats");
    println!("{}", key);
}
