//! LCP / IPCP control packets and their configuration options (RFC 1661).

use bytes::{BufMut, Bytes, BytesMut};

pub const CONFIGURE_REQUEST: u8 = 1;
pub const CONFIGURE_ACK: u8 = 2;
pub const CONFIGURE_NAK: u8 = 3;
pub const CONFIGURE_REJECT: u8 = 4;
pub const TERMINATE_REQUEST: u8 = 5;
pub const TERMINATE_ACK: u8 = 6;
pub const CODE_REJECT: u8 = 7;
pub const PROTOCOL_REJECT: u8 = 8;
pub const ECHO_REQUEST: u8 = 9;
pub const ECHO_REPLY: u8 = 10;
pub const DISCARD_REQUEST: u8 = 11;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    pub code: u8,
    pub id: u8,
    pub data: Bytes,
}

impl ControlPacket {
    pub fn new(code: u8, id: u8, data: impl Into<Bytes>) -> Self {
        Self {
            code,
            id,
            data: data.into(),
        }
    }

    /// Parses a packet, dropping any padding after the length field.
    pub fn parse(payload: &Bytes) -> Option<Self> {
        if payload.len() < 4 {
            return None;
        }
        let len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if len < 4 || len > payload.len() {
            return None;
        }
        Some(Self {
            code: payload[0],
            id: payload[1],
            data: payload.slice(4..len),
        })
    }

    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(4 + self.data.len());
        out.put_u8(self.code);
        out.put_u8(self.id);
        out.put_u16((4 + self.data.len()) as u16);
        out.put_slice(&self.data);
        out.freeze()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigOption {
    pub kind: u8,
    pub data: Bytes,
}

impl ConfigOption {
    pub fn new(kind: u8, data: impl Into<Bytes>) -> Self {
        Self {
            kind,
            data: data.into(),
        }
    }

    pub fn u16(&self) -> Option<u16> {
        (self.data.len() == 2).then(|| u16::from_be_bytes([self.data[0], self.data[1]]))
    }

    pub fn u32(&self) -> Option<u32> {
        let d = &self.data;
        (d.len() == 4).then(|| u32::from_be_bytes([d[0], d[1], d[2], d[3]]))
    }
}

/// Parses a Configure-* option list. `None` if it is malformed.
pub fn parse_options(data: &Bytes) -> Option<Vec<ConfigOption>> {
    let mut options = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let kind = data[i];
        let len = *data.get(i + 1)? as usize;
        if len < 2 || i + len > data.len() {
            return None;
        }
        options.push(ConfigOption {
            kind,
            data: data.slice(i + 2..i + len),
        });
        i += len;
    }
    Some(options)
}

pub fn encode_options(options: &[ConfigOption]) -> Bytes {
    let mut out = BytesMut::new();
    for opt in options {
        out.put_u8(opt.kind);
        out.put_u8((opt.data.len() + 2) as u8);
        out.put_slice(&opt.data);
    }
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_packet_round_trip_ignores_padding() {
        let pkt = ControlPacket::new(CONFIGURE_REQUEST, 7, vec![1, 4, 5, 0x4a]);
        let mut wire = BytesMut::from(&pkt.encode()[..]);
        wire.put_slice(&[0, 0, 0]);
        assert_eq!(ControlPacket::parse(&wire.freeze()), Some(pkt));
    }

    #[test]
    fn rejects_short_or_overlong_packets() {
        assert!(ControlPacket::parse(&Bytes::from_static(&[1, 1, 0])).is_none());
        assert!(ControlPacket::parse(&Bytes::from_static(&[1, 1, 0, 9, 0])).is_none());
    }

    #[test]
    fn options_round_trip() {
        let opts = vec![
            ConfigOption::new(1, vec![0x05, 0x4a]),
            ConfigOption::new(5, vec![1, 2, 3, 4]),
            ConfigOption::new(7, Bytes::new()),
        ];
        let encoded = encode_options(&opts);
        assert_eq!(parse_options(&encoded), Some(opts.clone()));
        assert_eq!(opts[0].u16(), Some(1354));
        assert_eq!(opts[1].u32(), Some(0x01020304));
    }

    #[test]
    fn rejects_malformed_options() {
        assert!(parse_options(&Bytes::from_static(&[1, 1])).is_none());
        assert!(parse_options(&Bytes::from_static(&[1, 6, 0])).is_none());
        assert!(parse_options(&Bytes::from_static(&[1])).is_none());
    }
}
