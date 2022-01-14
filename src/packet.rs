
use pnet::packet::{ip::IpNextHeaderProtocols, tcp::TcpPacket, Packet};

use pnet::util;
use std::fmt::Debug;
use std::net::Ipv4Addr;

use crate::tcp::{SYN, ACK, FIN, CWR, ECE, RST, PSH, URG};
const TCP_HEADER_SIZE: usize = 20;

#[derive(Clone)]
pub struct TCPPacket {
    buffer: Vec<u8>,
}

impl TCPPacket {
    pub fn new(payload_len: usize) -> Self {
        TCPPacket {
            buffer: vec![0; TCP_HEADER_SIZE + payload_len],
        }
    }

    pub fn get_src(&self) -> u16 {
        u16::from_be_bytes(self.buffer[0..2].try_into().unwrap())
    }

    pub fn get_dst(&self) -> u16 {
        u16::from_be_bytes(self.buffer[2..4].try_into().unwrap())
    }

    pub fn get_seq(&self) -> u32 {
        u32::from_be_bytes(self.buffer[4..8].try_into().unwrap())
    }

    // next seq to be received
    pub fn get_ack(&self) -> u32 {
        u32::from_be_bytes(self.buffer[8..12].try_into().unwrap())
    }

    pub fn get_flag(&self) -> u8 {
        self.buffer[13]
    }

    pub fn get_window_size(&self) -> u16 {
        u16::from_be_bytes(self.buffer[14..16].try_into().unwrap())
    }

    pub fn get_checksum(&self) -> u16 {
        u16::from_be_bytes(self.buffer[16..18].try_into().unwrap())
    }

    pub fn set_src(&mut self, port: u16) {
        self.buffer[0..2].copy_from_slice(&port.to_be_bytes());
    }

    pub fn set_dst(&mut self, port: u16) {
        self.buffer[2..4].copy_from_slice(&port.to_be_bytes());
    }

    pub fn set_seq(&mut self, seq: u32) {
        self.buffer[4..8].copy_from_slice(&seq.to_be_bytes());
    }

    pub fn set_ack(&mut self, ack: u32) {
        self.buffer[8..12].copy_from_slice(&ack.to_be_bytes());
    }

    pub fn set_data_offset(&mut self, data_offset: u8) {
        self.buffer[12] = (self.buffer[12] & 0b1111) | (data_offset << 4);
    }

    pub fn set_flag(&mut self, flag: u8) {
        self.buffer[13] = flag;
    }

    pub fn set_window_size(&mut self, window_size: u16) {
        self.buffer[14..16].copy_from_slice( &window_size.to_be_bytes());
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        self.buffer[16..18].copy_from_slice(&checksum.to_be_bytes());
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        self.buffer[TCP_HEADER_SIZE..].copy_from_slice(&payload);
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_correct_checksum(&self, local_addr: Ipv4Addr, remote_addr: Ipv4Addr) -> bool {
        self.get_checksum() == util::ipv4_checksum(
            &self.packet(),
            8,
            &[],
            &local_addr,
            &remote_addr,
            IpNextHeaderProtocols::Tcp,
        )
    }
}

impl Debug for TCPPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, r"
        src: {}
        dst: {}
        seq: {}
        ack: {}
        flag: {}
        payload_len: {}",
            self.get_src(),
            self.get_dst(),
            self.get_seq(),
            self.get_ack(),
            flag_to_string(self.get_flag()),
            self.payload().len()
        )
    }
}

impl Packet for TCPPacket {
    fn packet(&self) -> &[u8] {
        &self.buffer
    }

    fn payload(&self) -> &[u8] {
        &self.buffer[TCP_HEADER_SIZE..]
    }
}

impl<'a> From<TcpPacket<'a>> for TCPPacket {
    fn from(packet: TcpPacket) -> Self {
        Self {
            buffer: packet.packet().to_vec(),
        }
    }
}

fn flag_to_string(flag: u8) -> String {
    let mut flags: Vec<&str> = vec![];
    if (flag & SYN) == SYN {
        flags.push("SYN");
    }
    if (flag & ACK) == ACK {
        flags.push("ACK");
    }
    if (flag & FIN) == FIN {
        flags.push("FIN");
    }
    if (flag & RST) == RST {
        flags.push("RST");
    }
    if (flag & CWR) == CWR {
        flags.push("CWR");
    }
    if (flag & ECE) == ECE {
        flags.push("ECE");
    }
    if (flag & PSH) == PSH {
        flags.push("PSH");
    }
    if (flag & URG) == URG {
        flags.push("URG");
    }

    flags.join(" ")
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn flag_to_string_works() {
        assert_eq!(flag_to_string(RST), "RST");
        assert_eq!(flag_to_string(ACK | SYN), "SYN ACK");
    }
}
