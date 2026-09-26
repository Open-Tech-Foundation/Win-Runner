//! Versioned, transport-neutral framing for WinCLI instance control.
//!
//! Unix sockets, Windows named pipes, and a future remote worker transport
//! carry these same frames. The frame is intentionally small and supports
//! concurrent command streams without coupling the instance API to a host OS.

use std::io::{Read, Write};

pub const VERSION: u8 = 1;
pub const MAX_PAYLOAD: usize = 1024 * 1024;
const MAGIC: [u8; 4] = *b"WCLI";
const HEADER_LEN: usize = 16;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Request = 1,
    Response = 2,
    Stdout = 3,
    Stderr = 4,
    Stdin = 5,
    Exit = 6,
    Cancel = 7,
    Failure = 8,
}

impl TryFrom<u8> for Kind {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Stdout),
            4 => Ok(Self::Stderr),
            5 => Ok(Self::Stdin),
            6 => Ok(Self::Exit),
            7 => Ok(Self::Cancel),
            8 => Ok(Self::Failure),
            _ => Err(format!("unknown protocol frame kind: {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub stream: u32,
    pub kind: Kind,
    /// Bit 0 marks this direction of the stream closed.
    pub flags: u16,
    pub payload: Vec<u8>,
}

pub fn write_frame(mut writer: impl Write, frame: &Frame) -> Result<(), String> {
    if frame.payload.len() > MAX_PAYLOAD {
        return Err(format!("protocol frame exceeds {} bytes", MAX_PAYLOAD));
    }
    let mut header = [0; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4] = VERSION;
    header[5] = frame.kind as u8;
    header[6..8].copy_from_slice(&frame.flags.to_be_bytes());
    header[8..12].copy_from_slice(&frame.stream.to_be_bytes());
    header[12..16].copy_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    writer
        .write_all(&header)
        .and_then(|_| writer.write_all(&frame.payload))
        .map_err(|e| format!("cannot write protocol frame: {e}"))
}

pub fn read_frame(mut reader: impl Read) -> Result<Frame, String> {
    let mut header = [0; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .map_err(|e| format!("cannot read protocol frame header: {e}"))?;
    if header[..4] != MAGIC {
        return Err("invalid protocol frame magic".to_string());
    }
    if header[4] != VERSION {
        return Err(format!("unsupported protocol version: {}", header[4]));
    }
    let kind = Kind::try_from(header[5])?;
    let flags = u16::from_be_bytes([header[6], header[7]]);
    let stream = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    let len = u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(format!("protocol frame exceeds {} bytes", MAX_PAYLOAD));
    }
    let mut payload = vec![0; len];
    reader
        .read_exact(&mut payload)
        .map_err(|e| format!("cannot read protocol frame payload: {e}"))?;
    Ok(Frame {
        stream,
        kind,
        flags,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_streamed_output_frame() {
        let frame = Frame {
            stream: 7,
            kind: Kind::Stdout,
            flags: 1,
            payload: b"hello\n".to_vec(),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        assert_eq!(read_frame(bytes.as_slice()).unwrap(), frame);
    }

    #[test]
    fn rejects_unknown_versions_and_oversized_payloads() {
        let mut invalid = b"WCLI".to_vec();
        invalid.extend_from_slice(&[2, Kind::Request as u8, 0, 0]);
        invalid.extend_from_slice(&0u32.to_be_bytes());
        invalid.extend_from_slice(&0u32.to_be_bytes());
        assert!(read_frame(invalid.as_slice())
            .unwrap_err()
            .contains("version"));
        let oversized = Frame {
            stream: 1,
            kind: Kind::Request,
            flags: 0,
            payload: vec![0; MAX_PAYLOAD + 1],
        };
        assert!(write_frame(Vec::new(), &oversized).is_err());
    }
}
