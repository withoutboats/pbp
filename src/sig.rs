use std::fmt::{self, Display};
use std::u16;

use byteorder::{ByteOrder, BigEndian};
use digest::Digest;
use typenum::U32;
#[cfg(feature = "dalek")]
use typenum::U64;

use ascii_armor::{ascii_armor, remove_ascii_armor};
use packet::*;
use {Fingerprint, Signature};

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum SigType {
    BinaryDocument          = 0x00,
    TextDocument            = 0x01,
    Standalone              = 0x02,
    GenericCertification    = 0x10,
    PersonaCertification    = 0x11,
    CasualCertification     = 0x12,
    PositiveCertification   = 0x13,
    SubkeyBinding           = 0x18,
    PrimaryKeyBinding       = 0x19,
    DirectlyOnKey           = 0x1F,
    KeyRevocation           = 0x20,
    SubkeyRevocation        = 0x28,
    CertificationRevocation = 0x30,
    Timestamp               = 0x40,
    ThirdPartyConfirmation  = 0x50,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SubPacket<'a> {
    pub tag: u8,
    pub data: &'a [u8],
}

pub struct PgpSig {
    data: Vec<u8>,
}

impl PgpSig {
    pub fn new<Sha256, F>(
        data: &[u8],
        fingerprint: Fingerprint,
        sig_type: SigType,
        subpackets: &[SubPacket],
        sign: F
    ) -> PgpSig
        where
            Sha256: Digest<OutputSize = U32>,
            F: Fn(&[u8]) -> Signature,
    {
        let data = prepare_packet(2, |packet| {
            packet.push(4);                 // version number
            packet.push(sig_type as u8);    // signature class
            packet.push(22);                // signing algorithm (EdDSA)
            packet.push(8);                 // hash algorithm (SHA-256)

            write_subpackets(packet, |hashed_subpackets| {
                // fingerprint
                write_single_subpacket(hashed_subpackets, 33, |packet| {
                    packet.push(4);
                    packet.extend(&fingerprint);
                });

                // fake timestamp
                write_single_subpacket(hashed_subpackets, 2, |packet| packet.extend(&TIMESTAMP));

                for &SubPacket { tag, data } in subpackets {
                    write_single_subpacket(hashed_subpackets, tag, |packet| packet.extend(data));
                }
            });

            let hash = {
                let mut hasher = Sha256::default();

                hasher.process(data);

                hasher.process(&packet[3..]);

                hasher.process(&[0x04, 0xff]);
                hasher.process(&bigendian_u32((packet.len() - 3) as u32));

                hasher.fixed_result()
            };

            write_subpackets(packet, |unhashed_subpackets| {
                write_single_subpacket(unhashed_subpackets, 16, |packet| {
                    packet.extend(&fingerprint[12..]);
                });
            });

            packet.extend(&hash[0..2]);

            let signature = sign(&hash[..]);
            write_mpi(packet, &signature[00..32]);
            write_mpi(packet, &signature[32..64]);
        });

        PgpSig { data }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<PgpSig> {
        // TODO: convert to three byte header
        let (data, packet) = find_signature_packet(bytes)?;
        if !has_correct_structure(packet) { return None }
        if !has_correct_hashed_subpackets(packet) { return None }
        Some(PgpSig { data })
    }

    pub fn from_ascii_armor(string: &str) -> Option<PgpSig> {
        let data = remove_ascii_armor(string)?;
        PgpSig::from_bytes(&data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn hashed_section(&self) -> &[u8] {
        let subpackets_len = BigEndian::read_u16(&self.data[7..9]) as usize;
        &self.data[3..(subpackets_len + 9)]
    }

    pub fn signature(&self) -> Signature {
        let init = self.data.len() - 68;
        let sig_data = &self.data[init..];
        let mut sig = [0; 64];
        sig[00..32].clone_from_slice(&sig_data[02..34]);
        sig[32..64].clone_from_slice(&sig_data[36..68]);
        sig
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut fingerprint = [0; 20];
        fingerprint.clone_from_slice(&self.data[10..30]);
        fingerprint
    }

    pub fn sig_type(&self) -> SigType {
        match self.data[4] {
            0x00 => SigType::BinaryDocument,
            0x01 => SigType::TextDocument,
            0x02 => SigType::Standalone,
            0x10 => SigType::GenericCertification,
            0x11 => SigType::PersonaCertification,
            0x12 => SigType::CasualCertification,
            0x13 => SigType::PositiveCertification,
            0x18 => SigType::SubkeyBinding,
            0x19 => SigType::PrimaryKeyBinding,
            0x1F => SigType::DirectlyOnKey,
            0x20 => SigType::KeyRevocation,
            0x28 => SigType::SubkeyRevocation,
            0x30 => SigType::CertificationRevocation,
            0x40 => SigType::Timestamp,
            0x50 => SigType::ThirdPartyConfirmation,
            _    => panic!("Unrecognized signature type."),
        }
    }

    pub fn verify<Sha256, F>(&self, data: &[u8], verify: F) -> bool
        where
            Sha256: Digest<OutputSize = U32>,
            F: Fn(&[u8], Signature) -> bool,
    {
        let hash = {
            let mut hasher = Sha256::default();

            hasher.process(data);

            let hashed_section = self.hashed_section();
            hasher.process(hashed_section);

            hasher.process(&[0x04, 0xff]);
            hasher.process(&bigendian_u32(hashed_section.len() as u32));

            hasher.fixed_result()
        };

        verify(&hash[..], self.signature())
    }

    #[cfg(feature = "dalek")]
    pub fn from_dalek<Sha256, Sha512>(
        keypair: &::dalek::Keypair,
        data: &[u8],
        fingerprint: Fingerprint,
        sig_type: SigType
    ) -> PgpSig 
    where
        Sha256: Digest<OutputSize = U32>,
        Sha512: Digest<OutputSize = U64>,
    {
        PgpSig::new::<Sha256, _>(data, fingerprint, sig_type, &[], |data| {
            keypair.sign::<Sha512>(data).to_bytes()
        })
    }

    #[cfg(feature = "dalek")]
    pub fn to_dalek(&self) -> ::dalek::Signature {
        ::dalek::Signature::from_bytes(&self.signature()).unwrap()
    }

    #[cfg(feature = "dalek")]
    pub fn verify_dalek<Sha256, Sha512>(&self, data: &[u8], key: &::dalek::PublicKey) -> bool
    where
        Sha256: Digest<OutputSize = U32>,
        Sha512: Digest<OutputSize = U64>,
    {
        self.verify::<Sha256, _>(data, |data, signature| {
            let sig = ::dalek::Signature::from_bytes(&signature).unwrap();
            key.verify::<Sha512>(data, &sig)
        })
    }
}

impl Display for PgpSig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        ascii_armor(
            "BEGIN PGP SIGNATURE",
            "END PGP SIGNATURE",
            &self.data[..],
            f,
        )
    }
}

fn find_signature_packet(data: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let (init, len) = match data.first() {
        Some(&0x88)  => {
            if data.len() < 2 { return None }
            (2, data[1] as usize)
        }
        Some(&0x89)  => {
            if data.len() < 3 { return None }
            let len = BigEndian::read_u16(&data[1..3]);
            (3, len as usize)
        }
        Some(&0x8a)  => {
            if data.len() < 5 { return None }
            let len = BigEndian::read_u32(&data[1..5]);
            if len > u16::MAX as u32 { return None }
            (5, len as usize)
        }
        _            => return None,
    };

    if data.len() < init + len { return None }

    let packet = &data[init..][..len];

    if init == 3 {
        Some((data.to_owned(), packet))
    } else {
        let mut vec = Vec::with_capacity(3 + len);
        let len = bigendian_u16(len as u16);
        vec.push(0x89);
        vec.push(len[0]);
        vec.push(len[1]);
        vec.extend(packet.iter().cloned());
        Some((vec, packet))
    }
}

fn has_correct_structure(packet: &[u8]) -> bool {
    if packet.len() < 6 { return false }

    if !(packet[0] == 04 && packet[2] == 22 && packet[3] == 08) {
        return false
    }

    let hashed_len = BigEndian::read_u16(&packet[4..6]) as usize;
    if packet.len() < hashed_len + 8 { return false }
    let unhashed_len = BigEndian::read_u16(&packet[(hashed_len + 6)..][..2]) as usize;
    packet.len() == unhashed_len + hashed_len + 78
}

fn has_correct_hashed_subpackets(packet: &[u8]) -> bool {
    let hashed_len = BigEndian::read_u16(&packet[4..6]) as usize;
    if hashed_len < 23 { return false }

    // check that the first subpacket is a fingerprint subpacket
    packet[6] == 22 && packet[7] == 33 && packet[8] == 4
}
