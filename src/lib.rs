//! This library is designed to integrate non-PGP generated and verified keys
//! and signatures with channels that expect PGP data. It specifically only
//! supports the ed25519 signature scheme.
//!
//! Sometimes you want to be able to sign data, and the only reasonable channel
//! to transmit signatures and public keys available to you expects them to be
//! PGP formatted. If you don't want to use a heavyweight dependency like gpg,
//! this library supports only the minimal necessary components of the PGP
//! format to transmit your keys and signatures.
#![deny(missing_docs, missing_debug_implementations)]

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
    /// The key flags assigned to this key.
    pub struct KeyFlags: u8 {
        /// No key flags.
        const NONE              = 0x00;
        /// The Certify flag.
        const CERTIFY           = 0x01;
        /// The Sign flag.
        const SIGN              = 0x02;
        /// The Encrypt Communication flag.
        const ENCRYPT_COMS      = 0x04;
        /// The Encrypt Storage flag.
        const ENCRYPT_STORAGE   = 0x08;
        /// The Authentication flag.
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

// Helper for writing base64 data
struct Base64<'a>(&'a [u8]);

impl<'a> std::fmt::Debug for Base64<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&base64::encode(self.0))
    }
}

