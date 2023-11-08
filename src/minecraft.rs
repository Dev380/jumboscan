const MINECRAFT_1_6_PING: [u8; 26] = [
    0xfe, 0x01, 0xfa, 0x00, 0x0b, 0x00, 0x4d, 0x00, 0x43, 0x00, 0x7c, 0x00, 0x50, 0x00, 0x69, 0x00,
    0x6e, 0x00, 0x67, 0x00, 0x48, 0x00, 0x6f, 0x00, 0x73, 0x00,
];
const PROTOCOL_VER_1_6: u16 = 76;
const NETTY_STATUS_ID: u8 = 0;
const NETTY_PROTOCOL_VER: u8 = 0;
const STATUS_REQUEST_STATE: u8 = 1;
pub const UPGRADE_PROTOCOL_VER: i64 = 127;

use simd_json::prelude::*;

// https://wiki.vg/Server_List_Ping#1.6
/// Builds a 1.6 or earlier legacy server list ping packet
pub fn construct_1_6_ping(hostname: &str, port: u16) -> Vec<u8> {
    let encoded_string = hostname
        .encode_utf16()
        .flat_map(|unit: u16| unit.to_be_bytes())
        .collect::<Vec<u8>>();
    let mut ping_vec: Vec<u8> =
        Vec::with_capacity(MINECRAFT_1_6_PING.len() + encoded_string.len() + 7);

    // Header
    ping_vec[0..MINECRAFT_1_6_PING.len()].copy_from_slice(&MINECRAFT_1_6_PING);
    // Length of rest of message: 7 + len(hostname)
    ping_vec[MINECRAFT_1_6_PING.len()..MINECRAFT_1_6_PING.len() + 2]
        .copy_from_slice(&(encoded_string.len() as u16 + 7).to_be_bytes());
    // Protocol version
    ping_vec[MINECRAFT_1_6_PING.len() + 2..MINECRAFT_1_6_PING.len() + 4]
        .copy_from_slice(&PROTOCOL_VER_1_6.to_be_bytes());
    // Length of hostname
    ping_vec[MINECRAFT_1_6_PING.len() + 2..MINECRAFT_1_6_PING.len() + 4]
        .copy_from_slice(&(encoded_string.len() as u16).to_be_bytes());
    // Hostname
    let four_before_end = ping_vec.len() - 4;
    ping_vec[MINECRAFT_1_6_PING.len() + 4..four_before_end].copy_from_slice(&encoded_string);
    // Port
    ping_vec[four_before_end..].copy_from_slice(&(port as i32).to_be_bytes()); // Mojang is quirky and decides ports are C ints now

    ping_vec
}

// https://wiki.vg/Server_List_Ping#Current_.281.7.2B.29
/// Constructs a 1.7+ netty minecraft SLP packet
pub fn construct_netty_ping(hostname: &str, port: u16) -> Vec<u8> {
    let mut ping_vec: Vec<u8> = Vec::with_capacity(hostname.len() + 5);

    ping_vec[0] = NETTY_STATUS_ID;
    ping_vec[1] = NETTY_PROTOCOL_VER;
    ping_vec[2..hostname.len() + 2].copy_from_slice(hostname.as_bytes());

    let server_port_slice = ping_vec.len() - 3..ping_vec.len() - 1;
    ping_vec[server_port_slice].copy_from_slice(&port.to_be_bytes());

    let last_element = ping_vec.len();
    ping_vec[last_element] = STATUS_REQUEST_STATE;

    ping_vec
}

#[derive(Debug, Clone)]
pub enum MinecraftSlp {
    Legacy(LegacyPingResponse),
    Netty(NettyPingResponse),
}

#[derive(Debug, Clone)]
pub struct LegacyPingResponse {
    pub protocol_version: Option<i64>,
    pub server_version: Option<String>,
    pub motd: Option<String>,
    pub current_players: Option<i64>,
    pub max_players: Option<i64>,
}

/// Processes a server's 1.6 or earlier legacy ping response
pub fn process_server_1_6_ping(packet: &[u8]) -> Option<LegacyPingResponse> {
    // Check 0xFF packet ID
    if packet.first()? != &0xff {
        return None;
    }

    // Check §1\x00\x00 magic string
    if packet.get(3..9)? != [00, 167, 00, 31, 00, 00] {
        return None;
    }

    let null_delim_string = NullDelimitedString::new(bytemuck::pod_align_to(packet.get(9..)?).1);
    let info_string = null_delim_string.fields();

    Some(LegacyPingResponse {
        protocol_version: info_string
            .get(0)
            .map(|s| String::from_utf16(s))
            .and_then(Result::ok)
            .and_then(|s| s.parse().ok()),
        server_version: info_string.get(1).and_then(|s| String::from_utf16(s).ok()),
        motd: info_string.get(1).and_then(|s| String::from_utf16(s).ok()),
        current_players: info_string
            .get(3)
            .and_then(|s| String::from_utf16(s).ok())
            .and_then(|s| s.parse().ok()),
        max_players: info_string
            .get(4)
            .and_then(|s| String::from_utf16(s).ok())
            .and_then(|s| s.parse().ok()),
    })
}

#[derive(Debug, Clone)]
pub struct NettyPingResponse {
    version_name: Option<String>,
    protocol: Option<i64>,
    max_players: Option<i64>,
    online_players: Option<i64>,
    online_sample: Vec<Player>,
    motd: Option<String>,
    enforces_secure_chat: Option<bool>,
    previews_chat: Option<bool>,
    favicon: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Player {
    name: Option<String>,
    id: Option<String>,
}

/// Processes a 1.7+ netty SLP response
/// Needs mutability for simd_json performance
pub fn process_server_netty_ping(packet: &mut [u8]) -> Option<NettyPingResponse> {
    // Check packet ID
    if packet.first()? != &NETTY_STATUS_ID {
        return None;
    }

    // The next 1-2 bytes are a length field as a varint (so if the first bit of the first byte is set then it's two bytes)
    let string_start_index = if packet.get(1)? & 0b10000000 == 0 {
        2
    } else {
        3
    };
    let json_response = simd_json::to_borrowed_value(packet.get_mut(string_start_index..)?).ok()?;
    let json_response = json_response.as_object()?;

    let version_object = json_response.get("version");
    let version_object = version_object.as_object();

    let players_object = json_response.get("players");
    let players_object = players_object.as_object();

    Some(NettyPingResponse {
        version_name: version_object
            .and_then(|version| version.get("name"))
            .and_then(ValueAccess::as_str)
            .map(str::to_owned),
        protocol: version_object.and_then(|version| version.get("protocol")?.as_i64()),
        max_players: players_object.and_then(|players| players.get("max")?.as_i64()),
        online_players: players_object.and_then(|players| players.get("online")?.as_i64()),
        online_sample: players_object
            .and_then(|players| players.get("sample"))
            .and_then(ValueAccess::as_array)
            .map(|players_array| {
                players_array
                    .iter()
                    .map(|player| Player {
                        name: player
                            .get("name")
                            .and_then(ValueAccess::as_str)
                            .map(str::to_owned),
                        id: player
                            .get("id")
                            .and_then(ValueAccess::as_str)
                            .map(str::to_owned),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        motd: json_response
            .get("description")
            .and_then(ValueAccess::as_str)
            .map(str::to_owned),
        enforces_secure_chat: json_response
            .get("enforcesSecureChat")
            .and_then(ValueAccess::as_bool),
        previews_chat: json_response
            .get("previewsChat")
            .and_then(ValueAccess::as_bool),
        favicon: json_response
            .get("favicon")
            .and_then(ValueAccess::as_str)
            .map(str::to_owned),
    })
}

// 16 bit word string composed of fields separated by \x00\x00 that the legacy ping uses
struct NullDelimitedString<'a> {
    data: &'a [u16],
    counter: usize,
}

impl<'a> NullDelimitedString<'a> {
    fn new(data: &'a [u16]) -> Self {
        NullDelimitedString { data, counter: 0 }
    }

    // Convert into \x00\x00 separated fields
    fn fields(&self) -> Vec<&[u16]> {
        let mut fields = Vec::with_capacity(5); // 5 fields in a correctly formed legacy ping response

        self.data
            .split(|&c| c == 0x00)
            .for_each(|field| fields.push(field));

        fields
    }
}
