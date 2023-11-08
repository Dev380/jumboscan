const ETH_IP_HEADERS_LEN: usize = 34;
const MIN_TCP_HEADER_LEN: usize = 20;
const SYN_ACK: u8 = 2 | 16;
const PSH_ACK: u8 = 8 | 16;

use internet_checksum::Checksum;

pub fn create_tcp_packet(blank_packet: &mut [u8], dest_ip: [u8; 4]) {
    blank_packet[30..34].copy_from_slice(&dest_ip);
    calculate_checksums(blank_packet);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerPacketType {
    SynAck,
    Data(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPacket {
    pub ip: [u8; 4],
    pub port: [u8; 2],
    pub sequence_number: u32,
    pub packet_type: ServerPacketType,
}

pub fn parse_server_packet(server_packet: &[u8], source_port: u16) -> Option<ServerPacket> {
    if server_packet.len() < ETH_IP_HEADERS_LEN + MIN_TCP_HEADER_LEN {
        return None;
    }

    let received_port = u16::from_be_bytes(
        server_packet[36..38]
            .try_into()
            .expect("36..38 should be [u8; 2]"),
    );
    if received_port != source_port {
        return None;
    }

    let flags = server_packet[47];
    let packet_type = match flags {
        SYN_ACK => Some(ServerPacketType::SynAck),
        PSH_ACK => {
            let mut data_offset = server_packet[46] as usize;
            data_offset >>= 4;

            if server_packet.len() < ETH_IP_HEADERS_LEN + data_offset {
                return None;
            }

            Some(ServerPacketType::Data(
                server_packet[ETH_IP_HEADERS_LEN + data_offset..].to_vec(),
            ))
        }
        _ => None,
    }?;

    let ip = server_packet[26..30]
        .try_into()
        .expect("26..30 should be [u8; 4]");
    let port = server_packet[34..36]
        .try_into()
        .expect("34..36 should be [u8; 2]");
    let sequence_number = u32::from_be_bytes(
        server_packet[38..42]
            .try_into()
            .expect("38..42 should be [u8; 4]"),
    );
    Some(ServerPacket {
        ip,
        port,
        sequence_number,
        packet_type,
    })
}

fn calculate_checksums(packet: &mut [u8]) {
    // IP header
    let ip_checksum = internet_checksum::checksum(&packet[14..34]);
    packet[24..26].copy_from_slice(&ip_checksum);

    // TCP
    let mut tcp_checksum = Checksum::new();
    // Pseudoheader = source IP + dest IP + byte of zeros + protocol number (6) + TCP length
    // We need to add these bytes first then add the actual TCP header + data
    tcp_checksum.add_bytes(&packet[26..30]);
    tcp_checksum.add_bytes(&packet[30..34]);
    tcp_checksum.add_bytes(&[0, 6]);
    tcp_checksum.add_bytes(&((packet[34..].len() as u16).to_be_bytes()));
    // Actual TCP stuff here
    tcp_checksum.add_bytes(&packet[34..]);
    packet[50..52].copy_from_slice(&tcp_checksum.checksum());
}
