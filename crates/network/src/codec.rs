//! Length-prefixed JSON codec for coordinator ↔ aux node communication.
//!
//! # Wire format
//!
//! Every message is framed as:
//!
//! ```text
//! ┌────────────────────────┬────────────────────────────────┐
//! │  4-byte BE length (N)  │  N bytes of UTF-8 JSON payload │
//! └────────────────────────┴────────────────────────────────┘
//! ```
//!
//! The JSON payload is either a `NodeRequest` or a `NodeResponse`.
//! Both are closed enums so the deserializer can always distinguish them.
//!
//! # Security
//!
//! This codec provides **no authentication or confidentiality** — it is a
//! framing layer only. For production, wrap the TCP stream in mTLS (see
//! `SignedEnvelope` in the Layer 4 plan) before instantiating a codec.
//!
//! # Max frame size
//!
//! `MAX_FRAME_BYTES` (4 MiB) prevents allocating unbounded memory on a
//! malicious or buggy peer. Adjust for very large FROST quorums.

use crate::error::NetworkError;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[cfg(feature = "tcp")]
use crate::messages::{
    FrostRound1Request, FrostRound1Response, FrostRound2Request, FrostRound2Response,
    HandshakeBindingRound1Request, HandshakeBindingRound1Response,
    HandshakeBindingRound2Request, HandshakeBindingRound2Response,
};

/// Maximum frame body size (4 MiB).
pub const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

// ── Wire message enums ────────────────────────────────────────────────────────

/// A request sent from the coordinator to an auxiliary node.
#[cfg(feature = "tcp")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum NodeRequest {
    FrostRound1(FrostRound1Request),
    FrostRound2(FrostRound2Request),
    HandshakeBindingRound1(HandshakeBindingRound1Request),
    HandshakeBindingRound2(HandshakeBindingRound2Request),
}

/// A response sent from an auxiliary node back to the coordinator.
#[cfg(feature = "tcp")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum NodeResponse {
    FrostRound1(FrostRound1Response),
    FrostRound2(FrostRound2Response),
    HandshakeBindingRound1(HandshakeBindingRound1Response),
    HandshakeBindingRound2(HandshakeBindingRound2Response),
    /// An error the aux node wants to surface to the coordinator.
    Error { reason: String },
}

// ── Framing helpers ───────────────────────────────────────────────────────────

/// Write a single length-prefixed JSON frame to `sink`.
///
/// Serializes `value` to JSON, then writes a 4-byte big-endian length
/// followed by the UTF-8 bytes.
pub fn write_frame<W: Write, T: Serialize>(sink: &mut W, value: &T) -> Result<(), NetworkError> {
    let json = serde_json::to_vec(value)
        .map_err(|e| NetworkError::Serialization(e.to_string()))?;

    let len = json.len() as u32;
    if len > MAX_FRAME_BYTES {
        return Err(NetworkError::Serialization(format!(
            "frame too large: {} bytes (max {})",
            len, MAX_FRAME_BYTES
        )));
    }

    sink.write_all(&len.to_be_bytes())
        .map_err(|e| NetworkError::Serialization(e.to_string()))?;
    sink.write_all(&json)
        .map_err(|e| NetworkError::Serialization(e.to_string()))?;
    sink.flush()
        .map_err(|e| NetworkError::Serialization(e.to_string()))?;
    Ok(())
}

/// Read a single length-prefixed JSON frame from `source` and deserialize it.
///
/// Returns `Err(NetworkError::ChannelClosed)` when the peer closed the connection
/// cleanly (EOF at the length bytes).
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(
    source: &mut R,
) -> Result<T, NetworkError> {
    // Read the 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    match source.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(NetworkError::ChannelClosed);
        }
        Err(e) => return Err(NetworkError::Serialization(e.to_string())),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(NetworkError::Serialization(format!(
            "incoming frame too large: {} bytes (max {})",
            len, MAX_FRAME_BYTES
        )));
    }

    // Read the JSON body.
    let mut body = vec![0u8; len as usize];
    source
        .read_exact(&mut body)
        .map_err(|e| NetworkError::Serialization(e.to_string()))?;

    serde_json::from_slice(&body)
        .map_err(|e| NetworkError::Serialization(format!("JSON decode: {e}")))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::Cursor;

    fn roundtrip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(v: &T) {
        let mut buf = Vec::new();
        write_frame(&mut buf, v).unwrap();
        let decoded: T = read_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(&decoded, v);
    }

    #[test]
    fn roundtrip_string() {
        roundtrip(&"hello world".to_string());
    }

    #[test]
    fn roundtrip_json_value() {
        let val = serde_json::json!({"key": "value", "num": 42});
        roundtrip(&val);
    }

    #[test]
    fn channel_closed_on_empty_reader() {
        let mut empty: &[u8] = &[];
        let result: Result<Value, _> = read_frame(&mut empty);
        assert!(matches!(result, Err(NetworkError::ChannelClosed)));
    }

    #[test]
    fn rejects_oversized_frame() {
        // Write a fake length header that claims 5 MiB.
        let huge_len: u32 = 5 * 1024 * 1024;
        let buf: Vec<u8> = huge_len.to_be_bytes().to_vec();
        let result: Result<Value, _> = read_frame(&mut Cursor::new(&buf));
        assert!(matches!(result, Err(NetworkError::Serialization(_))));
    }

    #[test]
    fn length_prefix_is_big_endian() {
        let payload = b"{}";
        let mut buf = Vec::new();
        write_frame(&mut buf, &serde_json::json!({})).unwrap();
        // First 4 bytes should be BE length of the JSON "{}" → 2 bytes.
        let json_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(json_len as usize, buf.len() - 4);
    }
}