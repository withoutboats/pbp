use std::fmt;

use base64;
use byteorder::{BigEndian, ByteOrder};

pub fn remove_ascii_armor(s: &str) -> Option<Vec<u8>> {
    let lines: Vec<&str> = s.lines().map(|s| s.trim()).collect();
    let first_line = lines.first()?;
    if !first_line.starts_with("-----") || !first_line.ends_with("-----") {
        return None
    }
    let last_line = lines.last()?;
    if !last_line.starts_with("-----") || !last_line.ends_with("-----") {
        return None
    }

    base64::decode(&lines[2..lines.len() - 2].concat()).ok()
    // TODO checksum?
}

pub fn ascii_armor(
    header: &'static str,
    footer: &'static str,
    data: &[u8], 
    f: &mut fmt::Formatter
) -> fmt::Result
{
    // Header Line
    f.write_str("-----")?;
    f.write_str(header)?;
    f.write_str("-----\n\n")?;

    // Base64'd data
    let b64_cfg = base64::Config::new(
        base64::CharacterSet::Standard,
        true,
        false,
        base64::LineWrap::Wrap(76, base64::LineEnding::LF),
    );
    f.write_str(&base64::encode_config(data, b64_cfg))?;
    f.write_str("\n=")?;

    // Checksum
    let cksum = checksum_crc24(data);
    let mut cksum_buf = [0; 4];
    BigEndian::write_u32(&mut cksum_buf, cksum);
    f.write_str(&base64::encode(&cksum_buf[1..4]))?;

    // Footer Line
    f.write_str("\n-----")?;
    f.write_str(footer)?;
    f.write_str("-----\n")?;

    Ok(())
}

// Translation of checksum function from RFC 4880, section 6.1.
fn checksum_crc24(data: &[u8]) -> u32 {
    const CRC24_INIT: u32 = 0x_00B7_04CE;
    const CRC24_POLY: u32 = 0x_0186_4CFB;

    let mut crc = CRC24_INIT;

    for &byte in data {
        crc ^= (byte as u32) << 16;

        for _ in 0..8 {

            crc <<= 1;

            if (crc & 0x_0100_0000) != 0 {
                crc ^= CRC24_POLY;
            }
        }
    }

    crc & 0x_00FF_FFFF
}
