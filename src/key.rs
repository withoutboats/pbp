use std::fmt::{self, Display, Debug};
use std::ops::Range;
use std::str::FromStr;
use std::u16;

use byteorder::{ByteOrder, BigEndian};
use digest::Digest;
use sha1::Sha1;
use typenum::U32;

#[cfg(feature = "dalek")] use ed25519_dalek as dalek;
#[cfg(feature = "dalek")] use typenum::U64;

use crate::ascii_armor::{ascii_armor, remove_ascii_armor};
use crate::Base64;
use crate::packet::*;

use crate::{Fingerprint, Signature, KeyFlags};
use crate::{PgpSig, SubPacket, SigType};
use crate::PgpError;

// curve identifier (curve25519)
const CURVE: &[u8] = &[
    0x09, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0xda, 0x47,
    0x0f, 0x01
];

/// An OpenPGP formatted ed25519 public key.
///
/// This allows you to transmit an ed25519 key as a PGP key. Though gpg
/// and other implementations will probably be willing to import this
/// public key, it is not designed for use within the PGP ecosystem, but
/// rather to transfer public key data through mediums in which an OpenPGP
/// formatted key is expected.
///
/// This type implements Display by ASCII armoring the public key data.
#[derive(Eq, PartialEq, Hash)]
pub struct PgpKey {
    data: Vec<u8>,
}

impl PgpKey {
    /// Construct a PgpKey from an ed25519 public key.
    ///
    /// This will construct a valid OpenPGP Public Key datagram with the
    /// following packets:
    ///
    /// - A public key packet (formatted according to the "EdDSA for OpenPGP"
    ///   extension draft)
    /// - A user id (whatever string you pass as the user id argument)
    /// - A self-signature, with key usage flags all set to null
    ///
    /// The sign function must be a valid function for signing data with the
    /// private key paired with the public key. You are required to provide
    /// this so that you don't have to trust this library with direct access
    /// to the private key.
    ///
    /// # Warnings
    ///
    /// This will panic if your key is not 32 bits of data. It will not
    /// otherwise verify that your key is a valid ed25519 key.
    pub fn new<Sha256, F>(
        key: &[u8],
        flags: KeyFlags,
        user_id: &str,
        unix_time: u32,
        sign: F,
    ) -> PgpKey where
        Sha256: Digest<OutputSize = U32>,
        F: Fn(&[u8]) -> Signature,
    {
        assert!(key.len() == 32);

        let mut data = Vec::with_capacity(user_id.len() + 180);

        let key_packet_range = write_public_key_packet(&mut data, key, unix_time);
        let fingerprint = fingerprint(&data[key_packet_range.clone()]);
        write_user_id_packet(&mut data, user_id);

        let sig_data = {
            let mut data = Vec::from(&data[key_packet_range]);
            data.extend(&[0xb4]);
            data.extend(&bigendian_u32(user_id.len() as u32));
            data.extend(user_id.as_bytes());
            data
        };

        let signature_packet = PgpSig::new::<Sha256, _>(
            &sig_data,
            fingerprint,
            SigType::PositiveCertification,
            unix_time,
            &[
                SubPacket { tag: 27, data: &[flags.bits()] },
                SubPacket { tag: 23, data: &[0x80] },
            ],
            sign,
        );
        
        data.extend(signature_packet.as_bytes());

        PgpKey { data }
    }

    /// Construct a PgpKey struct from an OpenPGP public key.
    ///
    /// This does minimal verification of the data received. it ensures that
    /// the initial portion of the data is an OpenPGP public key packet,
    /// formatted to contain an ed25519 public key. It does not ensure that
    /// the actual public key is a valid ed25519 key, and no verification is
    /// done on the remainder of the data.
    ///
    /// As a result, a key constructed this way many not successfully import
    /// into an OpenPGP implementation like gpg.
    pub fn from_bytes(bytes: &[u8]) -> Result<PgpKey, PgpError> {
        let (packet_data, end) = find_public_key_packet(bytes)?;

        // Validate that this is a version 4 curve25519 EdDSA key.
        if !is_ed25519_valid(packet_data) {
            return Err(PgpError::UnsupportedPublicKeyPacket);
        }
        
        // convert public key packet to the old style header,
        // two byte length. All methods on PgpKey assume the
        // public key is in that format (e.g. the fingerprint
        // method).
        let data = if bytes[0] != 0x99 { 
            let mut packet = prepare_packet(6, |packet| packet.extend(packet_data));
            packet.extend(&bytes[end..]);
            packet
        } else { bytes.to_owned() };

        Ok(PgpKey { data })
    }

    /// Construct a PgpKey from an ASCII armored string.
    pub fn from_ascii_armor(string: &str) -> Result<PgpKey, PgpError> {
        let data = remove_ascii_armor(string, "BEGIN PGP PUBLIC KEY BLOCK", "END PGP PUBLIC KEY BLOCK")?;
        PgpKey::from_bytes(&data)
    }

    /// The ed25519 public key data contained in this key.
    ///
    /// This slice will be thirty-two bytes long.
    pub fn key_data(&self) -> &[u8] {
        &self.data[22..54]
    }

    /// All of the bytes in this key (including PGP metadata).
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..]
    }

    /// The OpenPGP fingerprint of this public key.
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint(&self.data[0..54])
    }

    #[cfg(feature = "dalek")]
    /// Create a PgpKey from a dalek Keypair and a user_id string.
    pub fn from_dalek<Sha256, Sha512>(keypair: &dalek::Keypair, flags: KeyFlags, unix_time: u32, user_id: &str) -> PgpKey
    where
        Sha256: Digest<OutputSize = U32>,
        Sha512: Digest<OutputSize = U64>,
    {
        PgpKey::new::<Sha256, _>(keypair.public.as_bytes(), flags, user_id, unix_time, |data| {
            keypair.sign::<Sha512>(data).to_bytes()
        })
    }

    #[cfg(feature = "dalek")]
    /// Convert this key into a dalek PublicKey.
    ///
    /// This will validate that the key data is a correct ed25519 public key.
    pub fn to_dalek(&self) -> Result<dalek::PublicKey, dalek::SignatureError> {
        dalek::PublicKey::from_bytes(self.key_data())
    }
}

impl Debug for PgpKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PgpKey").field("key", &Base64(&self.data[..])).finish()
    }
}

impl Display for PgpKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        ascii_armor(
            "BEGIN PGP PUBLIC KEY BLOCK",
            "END PGP PUBLIC KEY BLOCK",
            &self.data[..],
            f,
        )
    }
}

impl FromStr for PgpKey {
    type Err = PgpError;
    fn from_str(s: &str) -> Result<PgpKey, PgpError> {
        PgpKey::from_ascii_armor(s)
    }
}

fn write_public_key_packet(data: &mut Vec<u8>, key: &[u8], unix_time: u32) -> Range<usize> {
    write_packet(data, 6, |packet| {
        packet.push(4); // packet version #4
        packet.extend(&bigendian_u32(unix_time));
        packet.push(22); // algorithm id #22 (edDSA)

        packet.extend(CURVE);

        let mut key_data = Vec::with_capacity(33);
        key_data.push(0x40);
        key_data.extend(key);
        write_mpi(packet, &key_data);
    })
}

fn write_user_id_packet(data: &mut Vec<u8>, user_id: &str) -> Range<usize> {
    write_packet(data, 13, |packet| packet.extend(user_id.as_bytes()))
}

// Mainly this function parses the possible packet headers.
// If the data begins with a valid old public key packet using
// anything but the indeterminate length header format, it
// will return the data of that public key packet.
fn find_public_key_packet(data: &[u8]) -> Result<(&[u8], usize), PgpError> {
    let (init, len) = match data.first() {
        Some(&0x98)  => {
            if data.len() < 2 { return Err(PgpError::InvalidPacketHeader) }
            let len = data[1] as usize;
            (2, len)
        }
        Some(&0x99)  => {
            if data.len() < 3 { return Err(PgpError::InvalidPacketHeader) }
            let len = BigEndian::read_u16(&data[1..3]) as usize;
            (3, len)
        }
        Some(&0x9a)  => {
            if data.len() < 5 { return Err(PgpError::InvalidPacketHeader) }
            let len = BigEndian::read_u32(&data[1..5]) as usize;
            if len > u16::MAX as usize { return Err(PgpError::UnsupportedPacketLength) }
            (5, len)
        }
        _           => return Err(PgpError::UnsupportedPacketLength)
    };
    let end = init + len;
    if data.len() < end { return Err(PgpError::InvalidPacketHeader) }
    Ok((&data[init..end], end))
}

fn fingerprint(key_packet: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(key_packet);
    hasher.digest().bytes()
}

fn is_ed25519_valid(packet: &[u8]) -> bool {
    packet.len() == 51
        && packet[0] == 0x04
        && packet[5] == 0x16
        && &packet[6..16] == CURVE
        && &packet[16..19] == &[0x01, 0x07, 0x40]
}
