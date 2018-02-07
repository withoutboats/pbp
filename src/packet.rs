use std::ops::Range;
use std::u16;

use byteorder::{ByteOrder, BigEndian};

pub(crate) type BigEndianU32  = [u8; 4];
pub(crate) type BigEndianU16  = [u8; 2];

pub(crate) const TIMESTAMP: [u8; 4] = [0, 0, 0, 1];

pub(crate) fn write_packet<F: Fn(&mut Vec<u8>)>(data: &mut Vec<u8>, tag: u8, write: F) -> Range<usize> {
    let init = data.len();
    let header_tag = (tag << 2) | 0b_1000_0001;
    data.extend(&[header_tag, 0, 0]);
    write(data);
    let len = data.len() - init - 3;
    assert!(len < u16::MAX as usize);
    BigEndian::write_u16(&mut data[(init+1)..(init+3)], len as u16);
    init..data.len()
}

pub(crate) fn prepare_packet<F: Fn(&mut Vec<u8>)>(tag: u8, write: F) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    write(&mut packet);
    packet[0] = (tag << 2) | 0b_1000_0001;
    let len = packet.len() - 3;
    BigEndian::write_u16(&mut packet[1..3], len as u16);
    packet
}

pub(crate) fn write_subpackets<F>(packet: &mut Vec<u8>, write_each_subpacket: F) where
    F: Fn(&mut Vec<u8>)
{
    packet.extend(&[0, 0]);
    let init = packet.len();
    write_each_subpacket(packet);
    let len = packet.len() - init;
    assert!(len < u16::MAX as usize);
    BigEndian::write_u16(&mut packet[(init - 2)..init], len as u16);
}

pub(crate) fn write_single_subpacket<F: Fn(&mut Vec<u8>)>(packet: &mut Vec<u8>, tag: u8, write: F) {
    packet.extend(&[0, tag]);
    let init = packet.len() - 1;
    write(packet);
    let len = packet.len() - init;
    assert!(len < 191);
    packet[init - 1] = len as u8;
}

pub(crate) fn write_mpi(data: &mut Vec<u8>, mpi: &[u8]) {
    assert!(mpi.len() < (u16::MAX / 8) as usize);
    assert!(mpi.len() > 0);
    let len = bigendian_u16((mpi.len() * 8 - (mpi[0].leading_zeros() as usize)) as u16);
    data.extend(&len);
    data.extend(mpi);
}

pub(crate) fn bigendian_u32(data: u32) -> BigEndianU32 {
    let mut out = BigEndianU32::default();
    BigEndian::write_u32(&mut out, data);
    out
}

pub(crate) fn bigendian_u16(data: u16) -> BigEndianU16 {
    let mut out = BigEndianU16::default();
    BigEndian::write_u16(&mut out, data);
    out
}
