#![feature(iterator_try_collect)]
#![feature(iter_array_chunks)]
#![feature(array_into_iter_constructors)]
#![feature(array_methods)]
#![feature(never_type)]

const BLANK_SYN: [u8; 54] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 250, 240, 0, 0, 0, 0,
];
const MAX_PACKET_SIZE: usize = 65536 + 14;
const NETTY_SYN_NUMBER: u32 = 68;
const BATCH_SIZE: usize = 3;
const MEGABATCH_SIZE: u64 = 512; // 2**something for performance because bitshift division
const RECEIVE_TIMEOUT: u64 = 30;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use crate::{
    excludes::{ExcludedIps, Range}, minecraft::MinecraftSlp, scan_storage::{TestStore, Storage}, tcp::ServerPacketType,
};
use anyhow::Context;
use clap::Parser;
use crossbeam::{
    channel::{self, Receiver, Sender},
    sync::Parker,
};
use mac_address::MacAddress;
use rand::seq::SliceRandom;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    array::IntoIter,
    cmp,
    io::IoSlice,
    iter, mem,
    net::Ipv4Addr,
    thread,
    time::{Duration, Instant},
    sync::Arc,
};
use std::mem::MaybeUninit;

mod excludes;
mod excludes_parser;
mod mac_address;
mod minecraft;
mod scan_storage;
mod tcp;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// A program to scan the whole Internet
struct Args {
    /// MAC address of gateway (router)
    #[arg(short, long)]
    mac: MacAddress,
    /// Interface index
    #[arg(short, long)]
    interface: u32,
    /// Source port
    #[arg(short, long)]
    source_port: u16,
    /// Destination port
    #[arg(short, long)]
    dest_port: u16,
    /// Rate to scan at (in nanoseconds)
    #[arg(short, long)]
    rate: u64,
    /// Ip address to scan at, or 0.0.0.0 for scan everything excluding excludes
    #[arg(long)]
    scan_range: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let ip = args.scan_range.parse::<Ipv4Addr>()?;

    let mut socket = Socket::new(
        Domain::from(libc::AF_PACKET),
        Type::RAW,
        Some(Protocol::from(libc::ETH_P_IP)),
    )
    .context("Socket creation failed")?;

    let bind_addr = unsafe {
        let mut addr_array = [0; 8];
        addr_array[0..6].copy_from_slice(&args.mac.as_bytes());

        let mut storage = std::mem::zeroed::<libc::sockaddr_storage>();
        let addr_pointer = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_ll;
        (*addr_pointer).sll_family = libc::AF_PACKET as u16;
        (*addr_pointer).sll_protocol = (libc::ETH_P_IP as u16).to_be();
        (*addr_pointer).sll_ifindex = args.interface as i32;
        (*addr_pointer).sll_halen = 6;
        (*addr_pointer).sll_addr = addr_array;
        SockAddr::new(storage, mem::size_of::<libc::sockaddr_ll>() as u32)
    };

    socket.bind(&bind_addr).context("Socket binding failed")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(RECEIVE_TIMEOUT)))
        .context("Could not set socket timeout")?;

    let (source_mac, source_ip) = {
        let iface = default_net::get_interfaces()
            .iter()
            .find(|iface| iface.index == args.interface)
            .ok_or(anyhow::Error::msg(
                "Failed to find interface with given index",
            ))?
            .clone();
        (
            iface
                .mac_addr
                .ok_or(anyhow::Error::msg("Interface has no mac address"))?
                .octets(),
            iface
                .ipv4
                .get(0)
                .ok_or(anyhow::Error::msg("Interface has no ipv4 address"))?
                .addr
                .octets(),
        )
    };

    // Synthesize template packets
    let mut blank_syn = BLANK_SYN;
    blank_syn[0..6].copy_from_slice(&args.mac.as_bytes());
    blank_syn[6..12].copy_from_slice(&source_mac);
    blank_syn[26..30].copy_from_slice(&source_ip);
    blank_syn[34..36].copy_from_slice(&args.source_port.to_be_bytes());
    blank_syn[36..38].copy_from_slice(&args.dest_port.to_be_bytes());

    let mut blank_ack = blank_syn;
    // Set TCP flags to ACK
    blank_ack[47] = 16;
    // Set sequence number to 1
    blank_ack[38..42].copy_from_slice(&1u32.to_be_bytes());

    let mut syn = blank_syn;

    // Test ping - a little smoke test in prod?
    tcp::create_tcp_packet(&mut syn, [1, 1, 1, 1]);
    socket
        .send_to(&syn, &bind_addr)
        .context("Socket send failed")?;

    let mut recv_buffer = [0; MAX_PACKET_SIZE];
    /*
    loop {
        let read_bytes = socket
            .read(&mut recv_buffer)
            .context("Socket read failed")?;
        let packet = tcp::parse_server_packet(&recv_buffer[0..read_bytes], args.source_port);

        if let Some(packet) = packet {
            println!("type: {:?}", packet.packet_type);
            println!("ip: {:?}", packet.ip);
            println!("port: {:?}", packet.port);
            println!("seq: {:?}", packet.sequence_number);

            let payload = "GET / HTTP/1.1\nHost: 1.1.1.1\n\n";
            match packet.packet_type {
                ServerPacketType::SynAck => {
                    let mut data = blank_ack;
                    // Copy the sequence number from the SYN-ACK packet for the acknowledgement
                    data[42..46].copy_from_slice(&(packet.sequence_number + 1).to_be_bytes());

                    let mut ack = data;
                    tcp::create_tcp_packet(&mut ack, packet.ip);
                    socket
                        .send_to(&ack, &bind_addr)
                        .context("Socket send failed")?;

                    let mut data = data.to_vec();
                    data.extend(payload.as_bytes());
                    // Update length
                    data[16..18].copy_from_slice(&(40 + payload.len() as u16).to_be_bytes());
                    // Set TCP flags to ACK (16) and PSH (8)
                    data[47] = 16 | 8;
                    tcp::create_tcp_packet(&mut data, packet.ip);
                    socket
                        .send_to(&data, &bind_addr)
                        .context("Socket send failed")?;
                }
                ServerPacketType::Data(data) => {
                    let mut reset = blank_syn;
                    // Set TCP flags to RST and ACK
                    reset[47] = 4 | 16;
                    // Sequence number should be previous sequence number (1) + payload length
                    reset[38..42].copy_from_slice(&(1 + payload.len() as u32).to_be_bytes());
                    // Acknowledgement number should be server sequence number + server data length
                    reset[42..46].copy_from_slice(
                        &(packet.sequence_number + data.len() as u32).to_be_bytes(),
                    );
                    tcp::create_tcp_packet(&mut reset, packet.ip);
                    socket
                        .send_to(&reset, &bind_addr)
                        .context("Socket send failed")?;
                }
            }
        }
    }*/


    let (sender, receiver) = channel::unbounded();
    let parker = Parker::new();
    let parker_borrow = &parker;
    let socket_borrow = &socket;
    let receive = thread::spawn(move || receive_thread(socket_borrow, TestStore(Vec::new()), args.source_port, blank_syn, blank_ack, bind_addr, parker_borrow, receiver));

    transmit_thread(&socket, blank_syn, args.rate, &mut [(if ip == Ipv4Addr::from([0, 0, 0, 0]) { Range { start: 0, end: u32::MAX, } } else { ExcludedIps::Address(ip).to_range() })], bind_addr, &parker, sender);

    receive.join();

    Ok(())
}

// Magic threads that magically work

// Note: the scan_ranges will be changed in place to randomize it
fn transmit_thread(
    socket: &Socket,
    blank_syn: [u8; BLANK_SYN.len()],
    scan_rate_nanos: u64,
    scan_ranges: &mut [Range],
    bind_addr: SockAddr,
    parker: &Parker,
    sender: Sender<()>,
) {
    let mut rng = rand::thread_rng();
    scan_ranges.shuffle(&mut rng);

    let mut scan_iter = scan_ranges
        .iter()
        .flat_map(|range| range.into_iter())
        .array_chunks::<BATCH_SIZE>();
    let mut megabatch_counter = 0;
    let mut last_megabatch_instant = Instant::now();
    let expected_rate = Duration::from_nanos(MEGABATCH_SIZE * scan_rate_nanos);
    let mut throttle = Duration::from_nanos(scan_rate_nanos);

    for batch in scan_iter.by_ref() {
        if megabatch_counter == MEGABATCH_SIZE {
            let rate = last_megabatch_instant.elapsed();
            let rate_diff =
                (cmp::max(expected_rate, rate) - cmp::min(rate, rate)) / MEGABATCH_SIZE as u32;

            throttle = throttle.saturating_sub(rate_diff);

            megabatch_counter = 0;
            last_megabatch_instant = Instant::now();
        }

        let mut syn_buf = [blank_syn; BATCH_SIZE];
        syn_buf.iter_mut().zip(batch.iter()).for_each(|(syn, ip)| {
            tcp::create_tcp_packet(syn, ip.to_be_bytes());
        });

        parker.park();

        socket
            .send_to_vectored(&syn_buf.each_ref().map(|syn| IoSlice::new(syn)), &bind_addr)
            .ok();

        parker.unparker().unpark();

        thread::sleep(throttle);
        megabatch_counter += 1;
    }

    // Scan the remaining items
    let syn_buf = scan_iter
        .into_remainder()
        .unwrap_or(IntoIter::empty())
        .zip(iter::repeat(blank_syn))
        .map(|(ip, mut syn)| {
            tcp::create_tcp_packet(&mut syn, ip.to_be_bytes());
            syn
        })
        .collect::<Vec<[u8; BLANK_SYN.len()]>>();

    parker.park();

    socket
        .send_to_vectored(
            &syn_buf
                .iter()
                .map(|syn| IoSlice::new(syn))
                .collect::<Vec<IoSlice>>(),
            &bind_addr,
        )
        .ok();

    parker.unparker().unpark();

    // We're done, tell the receiver that
    sender.send(()).ok();
}

#[allow(clippy::too_many_arguments)]
fn receive_thread<T>(
    socket: &Socket,
    mut storage: impl Storage<StoreResult = T>,
    source_port: u16,
    blank_syn: [u8; BLANK_SYN.len()],
    blank_ack: [u8; BLANK_SYN.len()],
    bind_addr: SockAddr,
    parker: &Parker,
    receiver: Receiver<()>,
) -> T {
    // Change sequence number for our SYNs
    // Used to distinguish between transmit thread SYNs and the ones this thread sense
    let mut blank_syn = blank_syn;
    blank_syn[38..42].copy_from_slice(&NETTY_SYN_NUMBER.to_be_bytes());

    let mut timeout_counter = None;

    loop {
        // Check if transmit thread has finished
        if receiver.try_recv().is_ok() {
            timeout_counter = Some(Instant::now());
        }

        let mut recv_buffer = [0; MAX_PACKET_SIZE];
        // This is safe the API is just cringe
        let received = socket.recv_from(unsafe { &mut *(&mut recv_buffer as *mut [u8] as *mut [MaybeUninit<u8>]) });

        let read_bytes = if let Ok((read_bytes, _)) = received {
            read_bytes
        } else {
            continue;
        };

        if let Some(packet) = tcp::parse_server_packet(&recv_buffer[0..read_bytes], source_port) {
            match packet.packet_type {
                ServerPacketType::SynAck => {
                    let hostname = &Ipv4Addr::from(packet.ip).to_string();
                    let port = u16::from_be_bytes(packet.port);

                    // Check for the SYNs we sent that indicate we want a Netty (1.7+) SLP
                    let payload = if packet.sequence_number == NETTY_SYN_NUMBER + 1 {
                        minecraft::construct_netty_ping(hostname, port)
                    } else {
                        minecraft::construct_1_6_ping(hostname, port)
                    };

                    let mut data = blank_ack;
                    // Copy the sequence number from the SYN-ACK packet for the acknowledgement
                    data[42..46].copy_from_slice(&(packet.sequence_number + 1).to_be_bytes());

                    let mut ack = data;
                    tcp::create_tcp_packet(&mut ack, packet.ip);

                    if socket.send_to(&ack, &bind_addr).is_err() {
                        continue;
                    }

                    let mut data = data.to_vec();
                    data.extend(&payload);
                    // Update length
                    data[16..18].copy_from_slice(&(40 + payload.len() as u16).to_be_bytes());
                    // Set TCP flags to ACK (16) and PSH (8)
                    data[47] = 16 | 8;
                    tcp::create_tcp_packet(&mut data, packet.ip);

                    if socket.send_to(&data, &bind_addr).is_err() {
                        continue;
                    }
                }
                ServerPacketType::Data(mut data) => {
                    let minecraft_slp =
                        if let Some(legacy_response) = minecraft::process_server_1_6_ping(&data) {
                            if legacy_response
                                .protocol_version
                                .is_some_and(|protocol| protocol == minecraft::UPGRADE_PROTOCOL_VER)
                            {
                                let mut syn = blank_syn;
                                tcp::create_tcp_packet(&mut syn, packet.ip);

                                parker.park();
                                socket.send_to(&syn, &bind_addr).ok();
                                parker.unparker().unpark();
                            }

                            MinecraftSlp::Legacy(legacy_response)
                        } else if let Some(netty_response) =
                            minecraft::process_server_netty_ping(&mut data)
                        {
                            MinecraftSlp::Netty(netty_response)
                        } else {
                            continue;
                        };

                    storage.store(packet.ip, minecraft_slp);
                }
            }
        }

        if timeout_counter.is_some_and(|counter| counter.elapsed().as_secs() >= RECEIVE_TIMEOUT) {
            break;
        }
    }

    storage.finalize()
}
