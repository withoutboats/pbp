//! This library implements a conversion from an ed25519 public key to a valid
//! OpenPGP public key.
//!
//! This library is intended to be used for transmiting ed25519 public keys
//! through mediums which are designed to accept OpenPGP keys but not other
//! kinds of data.
// #![deny(missing_docs)]

extern crate base64;
extern crate byteorder;
extern crate digest;
extern crate sha1;
extern crate sha2;

#[cfg(feature = "dalek")]
extern crate ed25519_dalek as dalek;

mod ascii_armor;
mod packet;

mod key;
mod sig;

pub use key::PgpKey;
pub use sig::{PgpSig, SubPacket, SigType};

/// An OpenPGP public key fingerprint.
pub type Fingerprint = [u8; 20];
pub type Signature = [u8; 64];
