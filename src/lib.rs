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
extern crate typenum;

#[macro_use] extern crate failure;
#[macro_use] extern crate bitflags;

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
/// An ed25519 signature.
pub type Signature = [u8; 64];

bitflags! {
    pub struct KeyFlags: u8 {
        const NONE              = 0x00;
        const CERTIFY           = 0x01;
        const SIGN              = 0x02;
        const ENCRYPT_COMS      = 0x04;
        const ENCRYPT_STORAGE   = 0x08;
        const AUTHENTICATION    = 0x20;
    }
}

/// An error returned while attempting to parse a PGP signature or public key.
#[derive(Fail, Debug)]
pub enum PgpError {
    /// Invalid ASCII armor format
    #[fail(display = "Invalid ASCII armor format")]
    InvalidAsciiArmor,
    /// Packet header incorrectly formatted
    #[fail(display = "Packet header incorrectly formatted")]
    InvalidPacketHeader,
    /// Unsupported packet length format
    #[fail(display = "Unsupported packet length format")]
    UnsupportedPacketLength,
    /// Unsupported form of signature packet
    #[fail(display = "Unsupported form of signature packet")]
    UnsupportedSignaturePacket,
    /// First hashed subpacket of signature must be the key fingerprint
    #[fail(display = "First hashed subpacket of signature must be the key fingerprint")]
    MissingFingerprintSubpacket,
    /// Unsupported form of public key packet
    #[fail(display = "Unsupported form of public key packet")]
    UnsupportedPublicKeyPacket,
}
