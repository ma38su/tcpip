
use std::fmt::{Debug, Display};
use std::{cmp, thread};
use std::process::Command;
use std::sync::{Mutex, Condvar, RwLock, Arc, RwLockWriteGuard};
use std::time::{Duration, SystemTime};
use std::{collections::HashMap};
use std::net::{Ipv4Addr, IpAddr};

use anyhow::{Result, Context};
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::transport::{TransportChannelType, self};
use rand::Rng;
use rand::prelude::ThreadRng;

use crate::packet::TCPPacket;
use crate::socket::{Socket, AddressPair, PORT_RANGE};

const UNDETERMINED_IP_ADDR: Ipv4Addr = Ipv4Addr::new(0,0,0,0);
const UNDETERMINED_PORT: u16 = 0;
const MAX_TRANSMISSION: u8 = 5;
const RETRANSMISSION_TIMEOUT: u64 = 3;
const MSS: usize = 1460;

pub const TCP_HEADER_SIZE: usize = 20;

pub const CWR: u8 = 1 << 7;
pub const ECE: u8 = 1 << 6;
pub const URG: u8 = 1 << 5;
pub const ACK: u8 = 1 << 4;
pub const PSH: u8 = 1 << 3;
pub const RST: u8 = 1 << 2;
pub const SYN: u8 = 1 << 1;
pub const FIN: u8 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TcpStatus {
    Listen,
    SynSent,
    SynRecv,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
}

#[derive(Debug, Clone, PartialEq)]
struct TCPEvent {
    addrs: AddressPair,
    kind: TCPEventKind,
}

impl TCPEvent {
    fn new(addrs: AddressPair, kind: TCPEventKind) -> Self {
        Self { addrs, kind }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TCPEventKind {
    ConnectionCompleted,
    Acked,
    DataArrived,
    ConnectionClosed,
}

impl Display for TcpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpStatus::Listen => write!(f, "LISTEN"),
            TcpStatus::SynSent => write!(f, "SYNSENT"),
            TcpStatus::SynRecv => write!(f, "SYNRECV"),
            TcpStatus::Established => write!(f, "ESTABLISHED"),
            TcpStatus::FinWait1 => write!(f, "FINWAIT1"),
            TcpStatus::FinWait2 => write!(f, "FINWAIT2"),
            TcpStatus::TimeWait => write!(f, "TIMEWAIT"),
            TcpStatus::CloseWait => write!(f, "CLOSEWAIT"),
            TcpStatus::LastAck => write!(f, "LASTACK"),
        }
    }
}

pub struct TCP {
    sockets: RwLock<HashMap<AddressPair, Socket>>,
    event_condvar: (Mutex<Option<TCPEvent>>, Condvar),
}

impl TCP {
    pub fn new() -> Arc<Self> {
        let sockets = RwLock::new(HashMap::new());

        let tcp = Arc::new(Self {
            sockets,
            event_condvar: (Mutex::new(None), Condvar::new()),
        });

        let cloned_tcp = tcp.clone();
        std::thread::spawn(move || {
            cloned_tcp.receive_handler().unwrap();
        });

        let cloned_tcp = tcp.clone();
        std::thread::spawn(move || {
            cloned_tcp.timer();
        });
        tcp
    }

    fn timer(&self) {
        dbg!("begin timer thread");
        loop {
            let retransmission_timeout = Duration::from_secs(RETRANSMISSION_TIMEOUT);
            let mut table = self.sockets.write().unwrap();
            for (addrs, socket) in table.iter_mut() {
                while let Some(mut item) = socket.retransmission_queue.pop_front() {
                    if socket.send_param.unacked_seq > item.packet.get_seq() {
                        dbg!("successfully acked", item.packet.get_seq());
                        socket.send_param.window_size += item.packet.payload().len() as u16;
                        self.publish_event(*addrs, TCPEventKind::Acked);
                        if (item.packet.get_flag() & FIN) != 0
                            && socket.status == TcpStatus::LastAck
                        {
                            self.publish_event(*addrs, TCPEventKind::ConnectionClosed);                           
                        }
                        continue;
                    }
                    if item.latest_transmission_time.elapsed().unwrap() < retransmission_timeout {
                        socket.retransmission_queue.push_front(item);
                        break;
                    }
                    if item.transmission_count < MAX_TRANSMISSION {
                        dbg!("retransmit", item.packet.clone());
                        socket
                            .sender
                            .send_to(item.packet.clone(), IpAddr::V4(socket.remote_addr()))
                            .context("failed to retransmit")
                            .unwrap();
                        item.transmission_count += 1;
                        item.latest_transmission_time = SystemTime::now();
                        socket.retransmission_queue.push_back(item);
                        break;
                    } else {
                        dbg!("reached MAX_TRANSMISSION");
                        if (item.packet.get_flag() & FIN) != 0
                            && (socket.status == TcpStatus::LastAck
                                || socket.status == TcpStatus::FinWait1
                                || socket.status == TcpStatus::FinWait2)
                        {
                            self.publish_event(*addrs, TCPEventKind::ConnectionClosed);
                        }
                    }
                }
            }
            drop(table);
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn connect(&self, addr: Ipv4Addr, port: u16) -> Result<AddressPair> {
        let mut rng = rand::thread_rng();
        let local_addr = self.select_source_addr(addr).unwrap();
        let local_port = self.select_unused_port(&mut rng).unwrap();

        let addrs = AddressPair::new(
            local_addr,
            local_port,
            addr,
            port,
        );

        let mut socket = Socket::new(
            addrs,
            TcpStatus::SynSent
        )?;

        let mut table = self.sockets.write().unwrap();

        socket.send_param.initial_seq = rng.gen_range(1..(1<<31));
        socket.send_tcp_packet(
            socket.send_param.initial_seq,
            0,
            SYN,
            &[],
        )?;

        socket.send_param.unacked_seq = socket.send_param.initial_seq;
        socket.send_param.next_seq = socket.send_param.initial_seq + 1;

        table.insert(addrs, socket);
        drop(table);

        self.wait_event(addrs, TCPEventKind::ConnectionCompleted);
        Ok(addrs)
    }

    pub fn listen(&self, local_addr: Ipv4Addr, local_port: u16) -> Result<AddressPair> {
        let addrs = AddressPair::new(
            local_addr,
            local_port,
            UNDETERMINED_IP_ADDR,
            UNDETERMINED_PORT,
        );
        let socket = Socket::new(
            addrs,
            TcpStatus::Listen,
        )?;
        let mut table = self.sockets.write().unwrap();
        table.insert(addrs, socket);
        Ok(addrs)
    }

    pub fn accept(&self, addrs: AddressPair) -> Result<AddressPair> {
        self.wait_event(addrs, TCPEventKind::ConnectionCompleted);

        let mut table = self.sockets.write().unwrap();
        Ok(table
            .get_mut(&addrs)
            .context(format!("no such socket: {:?}", addrs))?
            .connected_queue
            .pop_front()
            .context("no connected socket")?)
    }

    pub fn send(&self, addrs: AddressPair, buffer: &[u8]) -> Result<()> {
        let mut cursor = 0;
        while cursor < buffer.len() {
            let mut table = self.sockets.write().unwrap();
            let mut socket = table
                .get_mut(&addrs)
                .context(format!("no such socket: {:?}", addrs))?;
            let send_size = cmp::min(MSS, buffer.len() - cursor);
            socket.send_tcp_packet(
                socket.send_param.next_seq,
                socket.recv_param.next_seq,
                ACK,
                &buffer[cursor..cursor + send_size],
            )?;
            cursor += send_size;
            socket.send_param.next_seq += send_size as u32;
            socket.send_param.window_size -= send_size as u16;
            drop(table);
            thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    pub fn recv(&self, addrs: AddressPair, buffer: &mut [u8]) -> Result<usize> {
        let mut table = self.sockets.write().unwrap();
        let mut socket = table
            .get_mut(&addrs)
            .context(format!("no such socket: {:?}", addrs))?;
        let mut received_size = socket.recv_buffer.len() - socket.recv_param.window_size as usize;
        while received_size == 0 {
            match socket.status {
                TcpStatus::CloseWait | TcpStatus::LastAck | TcpStatus::TimeWait => break,
                _ => {},
            }
            drop(table);
            dbg!("waiting incoming data");
            self.wait_event(addrs, TCPEventKind::DataArrived);
            table = self.sockets.write().unwrap();
            socket = table
                .get_mut(&addrs)
                .context(format!("no such socket: {:?}", addrs))?;
            received_size = socket.recv_buffer.len() - socket.recv_param.window_size as usize;
        }
        let copy_size = cmp::min(buffer.len(), received_size);
        buffer[..copy_size].copy_from_slice(&socket.recv_buffer[..copy_size]);
        socket.recv_buffer.copy_within(copy_size.., 0);
        socket.recv_param.window_size += copy_size as u16;
        Ok(copy_size)
    }

    pub fn receive_handler(&self) -> Result<()> {
        dbg!("begin recv thread");
        let (_, mut receiver) = transport::transport_channel(
            65535,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        )
        .unwrap();
        
        let mut packet_iter = transport::ipv4_packet_iter(&mut receiver);
        loop {
            let (packet, remote_addr) = match packet_iter.next() {
                Ok((p, r)) => (p, r),
                Err(_) => continue,
            };
            let local_addr = packet.get_destination();
            let tcp_packet = match TcpPacket::new(packet.payload()) {
                Some(p) => p,
                None => continue,
            };
            
            let packet = TCPPacket::from(tcp_packet);
            let remote_addr = match remote_addr {
                IpAddr::V4(addr) => addr,
                _ => continue,
            };

            let mut table = self.sockets.write().unwrap();
            let mut addrs = AddressPair::new(
                local_addr,
                packet.get_dst(),
                remote_addr,
                packet.get_src(),
            );
            let socket= match table.get_mut(&addrs) {
                // client socket
                Some(socket) => socket,
                // server socket
                None => {
                    addrs = AddressPair::new(
                        local_addr,
                        packet.get_dst(),
                        UNDETERMINED_IP_ADDR,
                        UNDETERMINED_PORT,
                    );
                    match table.get_mut(&addrs) {
                        Some(socket) => socket,
                        None => continue,
                    }
                },
            };

            if !packet.is_correct_checksum(local_addr, remote_addr) {
                dbg!("invalid checksum");
                continue;
            }

            dbg!("recv", &socket.status, &packet);

            if let Err(error) = match socket.status {
                TcpStatus::Listen => self.listen_handler(table, addrs, &packet, remote_addr),
                TcpStatus::SynRecv => self.synrecv_handler(table, addrs, &packet),
                // connect called, SYN sent.
                TcpStatus::SynSent => self.synsent_handler(socket, &packet),
                TcpStatus::Established => self.established_handler(socket, &packet),
                TcpStatus::CloseWait | TcpStatus::LastAck => self.close_handler(socket, &packet),
                TcpStatus::FinWait1 | TcpStatus::FinWait2 => self.finwait_handler(socket, &packet),
                _ => {
                    dbg!("not implemented state");
                    Ok(())
                }
            } {
                dbg!(error);
            }
        }
    }

    fn delete_acked_segement_from_retransmisson_queue(&self, socket: &mut Socket) {
        dbg!("ack accept", socket.send_param.unacked_seq);
        while let Some(item) = socket.retransmission_queue.pop_front() {
            if socket.send_param.unacked_seq > item.packet.get_seq() {
                dbg!("successfully acked", item.packet.get_seq());
                self.publish_event(socket.addrs, TCPEventKind::Acked);
            } else {
                socket.retransmission_queue.push_front(item);
                break;
            }
        }
    }

    fn established_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("established handler");
        if socket.send_param.unacked_seq < packet.get_ack()
            && packet.get_ack() <= socket.send_param.next_seq
        {
            socket.send_param.unacked_seq = packet.get_ack();
            self.delete_acked_segement_from_retransmisson_queue(socket);    
        } else if socket.send_param.next_seq < packet.get_ack() {
            return Ok(())
        }
        if (packet.get_flag() & ACK) == 0 {
            return Ok(());
        }
        if !packet.payload().is_empty() {
            self.process_payload(socket, &packet)?;
        }
        if (packet.get_flag() & FIN) != 0 {
            socket.recv_param.next_seq = packet.get_seq() + 1;
            socket.send_tcp_packet(
                socket.send_param.next_seq,
                socket.recv_param.next_seq,
                ACK,
                &[],
            )?;
            socket.status = TcpStatus::CloseWait;
            self.publish_event(socket.addrs, TCPEventKind::DataArrived);
        }
        Ok(())
    }

    fn process_payload(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        let offset = socket.recv_buffer.len() - socket.recv_param.window_size as usize
            + (packet.get_seq() - socket.recv_param.next_seq) as usize;
        let copy_size = cmp::min(packet.payload().len(), socket.recv_buffer.len() - offset);
        socket.recv_buffer[offset..offset+copy_size]
            .copy_from_slice(&packet.payload()[..copy_size]);
        socket.recv_param.tail =
            cmp::max(socket.recv_param.tail, packet.get_seq() + copy_size as u32);

        if packet.get_seq() == socket.recv_param.next_seq {
            socket.recv_param.next_seq = socket.recv_param.tail;
            socket.recv_param.window_size -= (socket.recv_param.tail - packet.get_seq()) as u16;
        }

        if copy_size > 0 {
            socket.send_tcp_packet(
                socket.send_param.next_seq,
                socket.recv_param.next_seq,
                ACK,
                &[],
            )?;
        } else {
            dbg!("recv buffer overflow");
        }
        self.publish_event(socket.addrs, TCPEventKind::DataArrived);
        Ok(())
    }

    fn listen_handler(
        &self,
        mut table: RwLockWriteGuard<HashMap<AddressPair, Socket>>,
        listening_addrs: AddressPair,
        packet: &TCPPacket,
        remote_addr: Ipv4Addr,
    ) -> Result<()> {
        dbg!("listen handler");

        if (packet.get_flag() & ACK) == ACK {
            // TODO send RST
            return Ok(());
        }
        let listening_socket = table.get_mut(&listening_addrs).unwrap();
        if (packet.get_flag() & SYN) == SYN {
            let addrs = AddressPair::new(
                listening_socket.local_addr(),
                listening_socket.local_port(),
                remote_addr,
                packet.get_src(),
            );
            let mut socket = Socket::new(
                addrs,
                TcpStatus::SynRecv,
            )?;
            socket.recv_param.next_seq = packet.get_seq() + 1;
            socket.recv_param.initial_seq = packet.get_seq();
            socket.send_param.initial_seq = rand::thread_rng().gen_range(1..(1<<31));
            socket.send_param.window_size = packet.get_window_size();
            socket.send_tcp_packet(
                socket.send_param.initial_seq,
                socket.recv_param.next_seq,
                SYN | ACK,
                &[],
            )?;
            socket.send_param.next_seq = socket.send_param.initial_seq + 1;
            socket.send_param.unacked_seq = socket.send_param.initial_seq;
            socket.listening_socket = Some(listening_addrs);
            dbg!("status: listen ->", &socket.status);
            table.insert(addrs, socket);
        }
        Ok(())
    }

    fn synrecv_handler(
            &self,
            mut table: RwLockWriteGuard<HashMap<AddressPair, Socket>>,
            addrs: AddressPair,
            packet: &TCPPacket,
    ) -> Result<()> {
        dbg!("synrecv handler");

        let socket = table.get_mut(&addrs).unwrap();
        if (packet.get_flag() & ACK) == ACK 
            && socket.send_param.unacked_seq <= packet.get_ack()
            && packet.get_ack() <= socket.send_param.next_seq
        {
            socket.recv_param.next_seq = packet.get_seq();
            socket.send_param.unacked_seq = packet.get_ack();
            socket.status = TcpStatus::Established;
            dbg!("status: synrcvd ->", &socket.status);
            if let Some(id) = socket.listening_socket {
                let ls = table.get_mut(&id).unwrap();
                ls.connected_queue.push_back(addrs);
                self.publish_event(id, TCPEventKind::ConnectionCompleted);
            }
        }
        Ok(())
    }

    fn synsent_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("synsent handler");
        let expected_flag = ACK | SYN;
        if (packet.get_flag() & expected_flag) == expected_flag
                && socket.send_param.unacked_seq <= packet.get_ack()
                && packet.get_ack() <= socket.send_param.next_seq {

            socket.recv_param.next_seq = packet.get_seq() + 1;
            socket.recv_param.initial_seq = packet.get_seq();
            socket.send_param.unacked_seq = packet.get_ack();
            socket.send_param.window_size = packet.get_window_size();
            if socket.send_param.unacked_seq > socket.send_param.initial_seq {
                socket.status = TcpStatus::Established;
                socket.send_tcp_packet(
                    socket.send_param.next_seq,
                    socket.recv_param.next_seq,
                    ACK,
                    &[],
                )?;
                dbg!("status: synsent ->", &socket.status);
                self.publish_event(socket.addrs, TCPEventKind::ConnectionCompleted);
            } else {
                socket.status = TcpStatus::SynRecv;
                socket.send_tcp_packet(
                    socket.send_param.next_seq,
                    socket.recv_param.next_seq,
                    ACK,
                    &[],
                )?;
                dbg!("status: synsent ->", &socket.status);
            }
        }
        Ok(())
    }

    fn select_source_addr(&self, addr: Ipv4Addr) -> Result<Ipv4Addr> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("ip route get {} | grep src", addr))
            .output()?;
        let tmp = String::from_utf8(output.stdout).unwrap();
        let mut output = tmp.trim().split_ascii_whitespace();
        while let Some(s) = output.next() {
            if s == "src" {
                break;
            }
        }

        let ip = output.next().context("failed to get src ip")?;
        dbg!("source addr", ip);
        ip.parse().context("failed to parse source ip")
    }

    fn select_unused_port(&self, rng: &mut ThreadRng) -> Result<u16> {
        for _ in 0..(PORT_RANGE.end - PORT_RANGE.start) {
            let local_port = rng.gen_range(PORT_RANGE);
            let table = self.sockets.read().unwrap();
            if table.keys().all(|k| local_port != k.local_port()) {
                return Ok(local_port);
            }
        }
        anyhow::bail!("no available port found.");
    }

    fn publish_event(&self, addrs: AddressPair, kind: TCPEventKind) {
        let (lock, cvar) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = Some(TCPEvent::new(addrs, kind));
        cvar.notify_all();
    }

    fn wait_event(&self, addrs: AddressPair, kind: TCPEventKind) {
        let (lock, cvar) = &self.event_condvar;
        let mut event = lock.lock().unwrap();
        loop {
            if let Some(ref e) = *event {
                if e.addrs == addrs && e.kind == kind {
                    break;
                }
            }
            event = cvar.wait(event).unwrap();
        }
        dbg!(&event);
        *event = None;
    }

    pub fn close(&self, addrs: AddressPair) -> Result<()> {
        let mut table = self.sockets.write().unwrap();
        let socket = table
            .get_mut(&addrs)
            .context(format!("no such socket: {:?}", addrs))?;
        socket.send_tcp_packet(
            socket.send_param.next_seq,
            socket.recv_param.next_seq,
            FIN | ACK,
            &[],
        )?;
        socket.send_param.next_seq += 1;
        match socket.status {
            TcpStatus::Established => {
                socket.status = TcpStatus::FinWait1;
                drop(table);
                self.wait_event(addrs, TCPEventKind::ConnectionClosed);
                let mut table = self.sockets.write().unwrap();
                table.remove(&addrs);
                dbg!("closed & removed", addrs);
            },
            TcpStatus::CloseWait => {
                socket.status = TcpStatus::LastAck;
                drop(table);
                self.wait_event(addrs, TCPEventKind::ConnectionClosed);
                let mut table = self.sockets.write().unwrap();
                table.remove(&addrs);
                dbg!("closed & removed", addrs);
            },
            TcpStatus::Listen => {
                table.remove(&addrs);
            },
            _ => {},
        }
        Ok(())
    }

    fn close_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("close wait | lastack handler");
        socket.send_param.unacked_seq = packet.get_ack();
        Ok(())
    }

    fn finwait_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> Result<()> {
        dbg!("finwait handler");
        if socket.send_param.unacked_seq < packet.get_ack()
            && packet.get_ack() <= socket.send_param.next_seq
        {
            socket.send_param.unacked_seq = packet.get_ack();
            self.delete_acked_segement_from_retransmisson_queue(socket);
        } else if socket.send_param.next_seq < packet.get_ack() {
            return Ok(());
        }
        if !packet.payload().is_empty() {
            self.process_payload(socket, &packet)?;
        }

        if socket.status == TcpStatus::FinWait1
            && socket.send_param.next_seq == socket.send_param.unacked_seq
        {
            socket.status = TcpStatus::FinWait2;
            dbg!("status: finwait1 ->", &socket.status);
        }

        if (packet.get_flag() & FIN) != 0 {
            socket.recv_param.next_seq += 1;
            socket.send_tcp_packet(
                socket.send_param.next_seq,
                socket.recv_param.next_seq,
                ACK,
                &[],
            )?;
            self.publish_event(socket.addrs, TCPEventKind::ConnectionClosed);
        }
        Ok(())
    }
}