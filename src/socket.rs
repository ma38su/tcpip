use std::net::{Ipv4Addr, IpAddr};
use std::ops::Range;
use anyhow::{Result,Context};
use pnet::packet::{util, Packet};
use pnet::{transport::{TransportSender, TransportChannelType, TransportProtocol, self}, packet::ip::IpNextHeaderProtocols};
use crate::tcp::{TCPPacket, TcpStatus};

const SOCKET_BUFFER_SIZE: usize = 4380;
pub const PORT_RANGE: Range<u16> = 40000..60000;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct AddressPair(pub Ipv4Addr, pub u16, pub Ipv4Addr, pub u16);

impl AddressPair {
    pub fn new(
        local_addr: Ipv4Addr,
        local_port: u16,
        remote_addr: Ipv4Addr,
        remote_port: u16
    ) -> Self {
        AddressPair (local_addr, local_port, remote_addr, remote_port)
    }

    pub fn local_addr(&self) -> Ipv4Addr {
        self.0
    }

    pub fn local_port(&self) -> u16 {
        self.1
    }

    pub fn remote_addr(&self) -> Ipv4Addr {
        self.2
    }

    pub fn remote_port(&self) -> u16 {
        self.3
    }
}

#[derive(Debug, Clone)]
pub struct SendParam {
    pub unacked_seq: u32,
    pub next_seq: u32,
    pub initial_seq: u32,
    pub window_size: u16,
}

#[derive(Debug, Clone)]
pub struct RecvParam {
    pub next_seq: u32,
    pub initial_seq: u32,
    pub tail: u32,
    pub window_size: u16,
}

pub struct Socket {
    pub addrs: AddressPair,
    pub send_param: SendParam,
    pub recv_param: RecvParam,
    pub status: TcpStatus,
    pub sender: TransportSender,
}

impl Socket {
    pub fn new(addrs: AddressPair, status: TcpStatus) -> Result<Self> {
        let (sender, _) = transport::transport_channel(
            65535,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        )?;

        Ok(Self {
            addrs,
            send_param: SendParam {
                unacked_seq: 0,
                initial_seq: 0,
                next_seq: 0,
                window_size: SOCKET_BUFFER_SIZE as u16,
            },
            recv_param: RecvParam {
                initial_seq: 0,
                next_seq: 0,
                window_size: SOCKET_BUFFER_SIZE as u16,
                tail: 0,
            },
            status,
            sender,
        })
    }

    pub fn local_addr(&self) -> Ipv4Addr {
        self.addrs.local_addr()
    }

    pub fn local_port(&self) -> u16 {
        self.addrs.local_port()
    }

    pub fn remote_addr(&self) -> Ipv4Addr {
        self.addrs.remote_addr()
    }

    pub fn remote_port(&self) -> u16 {
        self.addrs.remote_port()
    }

    pub fn send_tcp_packet(&mut self, seq: u32, ack: u32, flag: u8, payload: &[u8]) -> Result<usize> {
        let mut tcp_packet = TCPPacket::new(payload.len());
        tcp_packet.set_src(self.local_port());
        tcp_packet.set_dst(self.remote_port());
        tcp_packet.set_seq(seq);
        tcp_packet.set_ack(ack);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flag(flag);
        tcp_packet.set_window_size(self.recv_param.window_size);
        tcp_packet.set_payload(payload);
        tcp_packet.set_checksum(util::ipv4_checksum(
            &tcp_packet.packet(),
            8,
            &[],
            &self.local_addr(),
            &self.remote_addr(),
            IpNextHeaderProtocols::Tcp,
        ));

        let sent_size = self.sender.send_to(
            tcp_packet.clone(),
            IpAddr::V4(self.remote_addr()),
        ).context(format!("failed to send: \n{:?}", tcp_packet))?;

        dbg!("sent", &self.status, &tcp_packet);
        Ok(sent_size)
    }
}