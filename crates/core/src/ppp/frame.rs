//! Fortinet's framing of PPP over the TLS tunnel.
//!
//! Each PPP packet is preceded by a 6-byte header:
//! `total length (u16 BE) | 0x5050 | PPP length (u16 BE)`, where total
//! length = PPP length + 6. The PPP packet itself has no HDLC flags,
//! escaping or checksum, and starts with the protocol number.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};

pub const HEADER_LEN: usize = 6;
const MAGIC: u16 = 0x5050;

/// One PPP packet: protocol number and information field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub protocol: u16,
    pub payload: Bytes,
}

/// Appends a framed PPP packet to `out`. The protocol field is always sent
/// uncompressed.
pub fn encode(protocol: u16, payload: &[u8], out: &mut BytesMut) {
    let ppp_len = 2 + payload.len();
    debug_assert!(
        ppp_len + HEADER_LEN <= u16::MAX as usize,
        "PPP packet too large"
    );
    out.reserve(HEADER_LEN + ppp_len);
    out.put_u16((ppp_len + HEADER_LEN) as u16);
    out.put_u16(MAGIC);
    out.put_u16(ppp_len as u16);
    out.put_u16(protocol);
    out.put_slice(payload);
}

/// Takes one complete frame off the front of `buf`, or returns `None` if
/// more bytes are needed.
pub fn decode(buf: &mut BytesMut) -> Result<Option<Frame>> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let total = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let magic = u16::from_be_bytes([buf[2], buf[3]]);
    let ppp_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if magic != MAGIC || total != ppp_len + HEADER_LEN || ppp_len == 0 {
        return Err(Error::Protocol(format!(
            "bad tunnel frame header {:02x?}",
            &buf[..HEADER_LEN]
        )));
    }
    if buf.len() < total {
        buf.reserve(total - buf.len());
        return Ok(None);
    }

    buf.advance(HEADER_LEN);
    let mut ppp = buf.split_to(ppp_len).freeze();

    // Address and control fields are not expected, but tolerate them.
    if ppp.starts_with(&[0xff, 0x03]) {
        ppp.advance(2);
    }
    // With protocol-field compression the protocol is one byte (odd value).
    let protocol = match ppp.first() {
        Some(b) if b & 1 == 1 => u16::from(ppp.get_u8()),
        Some(_) if ppp.len() >= 2 => ppp.get_u16(),
        _ => return Err(Error::Protocol("tunnel frame without PPP protocol".into())),
    };
    Ok(Some(Frame {
        protocol,
        payload: ppp,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_frame() {
        let mut buf = BytesMut::new();
        encode(0xc021, &[1, 2, 0, 4], &mut buf);
        assert_eq!(&buf[..], &[0, 12, 0x50, 0x50, 0, 6, 0xc0, 0x21, 1, 2, 0, 4]);
        let frame = decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.protocol, 0xc021);
        assert_eq!(&frame.payload[..], &[1, 2, 0, 4]);
        assert!(buf.is_empty());
    }

    #[test]
    fn waits_for_partial_frames() {
        let mut full = BytesMut::new();
        encode(0x0021, &[0x45; 20], &mut full);
        let mut buf = BytesMut::new();
        for (i, byte) in full.iter().enumerate() {
            assert!(
                decode(&mut buf).unwrap().is_none(),
                "frame finished early at byte {i}"
            );
            buf.put_u8(*byte);
        }
        assert_eq!(decode(&mut buf).unwrap().unwrap().payload.len(), 20);
    }

    #[test]
    fn decodes_back_to_back_frames() {
        let mut buf = BytesMut::new();
        encode(0xc021, &[9, 1, 0, 8, 0, 0, 0, 0], &mut buf);
        encode(0x8021, &[1, 1, 0, 4], &mut buf);
        assert_eq!(decode(&mut buf).unwrap().unwrap().protocol, 0xc021);
        assert_eq!(decode(&mut buf).unwrap().unwrap().protocol, 0x8021);
        assert!(decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn accepts_compressed_protocol_and_address_field() {
        let mut buf = BytesMut::from(&[0, 11, 0x50, 0x50, 0, 5, 0xff, 0x03, 0x21, 0x45, 0x00][..]);
        let frame = decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.protocol, 0x0021);
        assert_eq!(&frame.payload[..], &[0x45, 0x00]);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = BytesMut::from(&[0, 8, 0x12, 0x34, 0, 2, 0xc0, 0x21][..]);
        assert!(decode(&mut buf).is_err());
    }

    #[test]
    fn rejects_inconsistent_lengths() {
        let mut buf = BytesMut::from(&[0, 9, 0x50, 0x50, 0, 2, 0xc0, 0x21, 0][..]);
        assert!(decode(&mut buf).is_err());
    }
}
