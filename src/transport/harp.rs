// FRD: specs/frds/FRD-20260223-harp-frame-codec.md
// FRD: specs/frds/FRD-20260223-harp-pipeline-bridge.md

//! HARP frame codec and pipeline bridge for the HTTPS API Relay Protocol.
//!
//! Encodes and decodes HARP binary frames used to encapsulate encrypted
//! tunnel packets over HTTP-based transports (WebSocket or polling).
//!
//! # Wire Format
//!
//! ```text
//! Byte 0:     [Version (4 bits)] [Type (4 bits)]
//! Byte 1:     Reserved (0x00)
//! Bytes 2-3:  Payload Length (16 bits, big-endian)
//! Bytes 4+:   Encrypted Payload (variable, 0..65535 bytes)
//! ```
//!
//! Total header size: 4 bytes. Maximum payload: 65535 bytes.

use super::TransportError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HARP protocol version. MUST be 0x1.
pub const HARP_VERSION: u8 = 0x1;

/// Size of the HARP frame header in bytes.
pub const HARP_HEADER_LEN: usize = 4;

/// Maximum payload length (limited by 16-bit length field).
pub const HARP_MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// Reserved byte value (byte 1 of the header).
const HARP_RESERVED_BYTE: u8 = 0x00;

/// Bit shift for version field in byte 0.
const VERSION_SHIFT: u8 = 4;

/// Mask for the type field in byte 0 (lower 4 bits).
const TYPE_MASK: u8 = 0x0F;

// ---------------------------------------------------------------------------
// Frame Type
// ---------------------------------------------------------------------------

/// HARP frame type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HarpFrameType {
    /// Encrypted tunnel packet (VPN traffic).
    Data = 0x0,
    /// Empty payload, cover traffic / connection keep-alive.
    Keepalive = 0x1,
    /// Session teardown.
    Close = 0x2,
}

impl HarpFrameType {
    /// Convert a raw byte value to a `HarpFrameType`.
    fn from_u8(value: u8) -> Result<Self, TransportError> {
        match value {
            0x0 => Ok(Self::Data),
            0x1 => Ok(Self::Keepalive),
            0x2 => Ok(Self::Close),
            other => Err(TransportError::HarpUnknownFrameType(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

/// A decoded HARP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarpFrame {
    /// The frame type.
    pub frame_type: HarpFrameType,
    /// The frame payload (encrypted tunnel data, or empty for keepalive/close).
    pub payload: Vec<u8>,
}

impl HarpFrame {
    /// Create a new HARP frame.
    pub fn new(frame_type: HarpFrameType, payload: Vec<u8>) -> Self {
        Self { frame_type, payload }
    }

    /// Create a DATA frame with the given payload.
    pub fn data(payload: Vec<u8>) -> Self {
        Self::new(HarpFrameType::Data, payload)
    }

    /// Create a KEEPALIVE frame (empty payload).
    pub fn keepalive() -> Self {
        Self::new(HarpFrameType::Keepalive, Vec::new())
    }

    /// Create a CLOSE frame (empty payload).
    pub fn close() -> Self {
        Self::new(HarpFrameType::Close, Vec::new())
    }

    /// Encode this frame into wire bytes.
    ///
    /// Returns `Err(HarpPayloadTooLarge)` if the payload exceeds [`HARP_MAX_PAYLOAD_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        if self.payload.len() > HARP_MAX_PAYLOAD_LEN {
            return Err(TransportError::HarpPayloadTooLarge(self.payload.len()));
        }

        let first_byte = (HARP_VERSION << VERSION_SHIFT) | (self.frame_type as u8 & TYPE_MASK);
        let payload_len = self.payload.len() as u16;

        let mut buf = Vec::with_capacity(HARP_HEADER_LEN + self.payload.len());
        buf.push(first_byte);
        buf.push(HARP_RESERVED_BYTE);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);

        Ok(buf)
    }

    /// Decode a HARP frame from a byte slice.
    ///
    /// Returns the decoded frame and the number of bytes consumed from `data`.
    /// This enables streaming parsers to process multiple frames from a single buffer.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), TransportError> {
        if data.len() < HARP_HEADER_LEN {
            return Err(TransportError::HarpFrameTooShort {
                expected: HARP_HEADER_LEN,
                actual: data.len(),
            });
        }

        let version = data[0] >> VERSION_SHIFT;
        if version != HARP_VERSION {
            return Err(TransportError::HarpUnsupportedVersion(version));
        }

        let frame_type = HarpFrameType::from_u8(data[0] & TYPE_MASK)?;
        // Byte 1 is reserved — ignored on decode per spec.
        let payload_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        let available = data.len() - HARP_HEADER_LEN;
        if available < payload_len {
            return Err(TransportError::HarpFrameTruncated {
                header_len: payload_len,
                available,
            });
        }

        let payload = data[HARP_HEADER_LEN..HARP_HEADER_LEN + payload_len].to_vec();
        let bytes_consumed = HARP_HEADER_LEN + payload_len;

        Ok((Self { frame_type, payload }, bytes_consumed))
    }
}

// ---------------------------------------------------------------------------
// Stream Reader
// ---------------------------------------------------------------------------

/// Streaming HARP frame reader that accumulates partial data across pushes.
///
/// Handles the case where a frame spans multiple TCP segments or WebSocket
/// messages. Push incoming bytes with [`push`], then call [`next_frame`]
/// repeatedly to drain complete frames.
pub struct HarpFrameReader {
    buffer: Vec<u8>,
}

impl Default for HarpFrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl HarpFrameReader {
    /// Create a new empty frame reader.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Push incoming bytes into the reader's internal buffer.
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to decode and return the next complete frame from the buffer.
    ///
    /// Returns `None` if there is not enough data for a complete frame.
    /// Returns `Some(Err(...))` if the buffered data contains a protocol error
    /// (e.g., unsupported version). On error, the buffer is NOT drained — the
    /// caller should discard the reader.
    pub fn next_frame(&mut self) -> Option<Result<HarpFrame, TransportError>> {
        if self.buffer.len() < HARP_HEADER_LEN {
            return None;
        }

        // Peek at payload length to check if we have enough data.
        let payload_len = u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize;
        let total_frame_len = HARP_HEADER_LEN + payload_len;

        if self.buffer.len() < total_frame_len {
            return None;
        }

        // We have enough data — attempt full decode.
        match HarpFrame::decode(&self.buffer) {
            Ok((frame, consumed)) => {
                self.buffer.drain(..consumed);
                Some(Ok(frame))
            }
            Err(e) => Some(Err(e)),
        }
    }

    /// Return the number of buffered bytes not yet consumed.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

// ---------------------------------------------------------------------------
// Pipeline Bridge: HarpSender / HarpReceiver
// ---------------------------------------------------------------------------

use std::sync::Arc;

use tokio::sync::{Mutex as TokioMutex, mpsc};

use crate::tunnel::pipeline::{DatagramReceiver, DatagramSender};

/// Adapter that sends encrypted payloads as HARP DATA frames via an mpsc channel.
///
/// Implements [`DatagramSender`] so it can be used as the sender half of a
/// [`TunnelPipeline`](crate::tunnel::pipeline::TunnelPipeline).
pub struct HarpSender {
    tx: mpsc::Sender<Vec<u8>>,
}

impl HarpSender {
    /// Create a new `HarpSender` wrapping the given channel sender.
    pub fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl DatagramSender for HarpSender {
    fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError> {
        let frame = HarpFrame::data(payload.to_vec());
        let wire_bytes = frame.encode()?;
        self.tx.try_send(wire_bytes).map_err(|_| TransportError::HarpChannelClosed)
    }
}

/// Adapter that receives HARP frames from an mpsc channel and returns DATA payloads.
///
/// Implements [`DatagramReceiver`] so it can be used as the receiver half of a
/// [`TunnelPipeline`](crate::tunnel::pipeline::TunnelPipeline).
///
/// KEEPALIVE frames are silently skipped. CLOSE frames cause the receiver to
/// return [`TransportError::HarpSessionClosed`].
pub struct HarpReceiver {
    rx: Arc<TokioMutex<mpsc::Receiver<Vec<u8>>>>,
}

impl HarpReceiver {
    /// Create a new `HarpReceiver` wrapping the given channel receiver.
    pub fn new(rx: Arc<TokioMutex<mpsc::Receiver<Vec<u8>>>>) -> Self {
        Self { rx }
    }
}

impl DatagramReceiver for HarpReceiver {
    async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let mut rx = self.rx.lock().await;
        loop {
            let raw = rx.recv().await.ok_or(TransportError::HarpChannelClosed)?;
            let (frame, _consumed) = HarpFrame::decode(&raw)?;
            match frame.frame_type {
                HarpFrameType::Data => return Ok(frame.payload),
                HarpFrameType::Keepalive => continue,
                HarpFrameType::Close => return Err(TransportError::HarpSessionClosed),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Constants for test payloads
    const SMALL_PAYLOAD: &[u8] = b"hello harp";
    const EMPTY_PAYLOAD: &[u8] = b"";

    // -- AC-1: DATA frame encode/decode round-trip --

    #[test]
    fn data_frame_round_trip_small_payload() {
        let frame = HarpFrame::data(SMALL_PAYLOAD.to_vec());
        let wire = frame.encode().expect("encode");
        let (decoded, consumed) = HarpFrame::decode(&wire).expect("decode");

        assert_eq!(decoded, frame);
        assert_eq!(consumed, wire.len());
    }

    // -- AC-2: KEEPALIVE frame round-trip --

    #[test]
    fn keepalive_frame_round_trip() {
        let frame = HarpFrame::keepalive();
        let wire = frame.encode().expect("encode");
        let (decoded, consumed) = HarpFrame::decode(&wire).expect("decode");

        assert_eq!(decoded.frame_type, HarpFrameType::Keepalive);
        assert_eq!(decoded.payload, EMPTY_PAYLOAD);
        assert_eq!(consumed, HARP_HEADER_LEN);
    }

    // -- AC-3: CLOSE frame round-trip --

    #[test]
    fn close_frame_round_trip() {
        let frame = HarpFrame::close();
        let wire = frame.encode().expect("encode");
        let (decoded, consumed) = HarpFrame::decode(&wire).expect("decode");

        assert_eq!(decoded.frame_type, HarpFrameType::Close);
        assert_eq!(decoded.payload, EMPTY_PAYLOAD);
        assert_eq!(consumed, HARP_HEADER_LEN);
    }

    // -- AC-4: Decode rejects buffer < 4 bytes --

    #[test]
    fn decode_rejects_empty_buffer() {
        let result = HarpFrame::decode(&[]);
        assert!(matches!(
            result,
            Err(TransportError::HarpFrameTooShort {
                expected: HARP_HEADER_LEN,
                actual: 0,
            })
        ));
    }

    #[test]
    fn decode_rejects_one_byte() {
        let result = HarpFrame::decode(&[0x10]);
        assert!(matches!(
            result,
            Err(TransportError::HarpFrameTooShort {
                expected: HARP_HEADER_LEN,
                actual: 1,
            })
        ));
    }

    #[test]
    fn decode_rejects_three_bytes() {
        let result = HarpFrame::decode(&[0x10, 0x00, 0x00]);
        assert!(matches!(
            result,
            Err(TransportError::HarpFrameTooShort {
                expected: HARP_HEADER_LEN,
                actual: 3,
            })
        ));
    }

    // -- AC-5: Decode rejects unsupported version --

    #[test]
    fn decode_rejects_version_zero() {
        // Version 0, type DATA, no payload
        let wire = [0x00, 0x00, 0x00, 0x00];
        let result = HarpFrame::decode(&wire);
        assert!(matches!(result, Err(TransportError::HarpUnsupportedVersion(0))));
    }

    #[test]
    fn decode_rejects_version_two() {
        // Version 2, type DATA, no payload
        let wire = [0x20, 0x00, 0x00, 0x00];
        let result = HarpFrame::decode(&wire);
        assert!(matches!(result, Err(TransportError::HarpUnsupportedVersion(2))));
    }

    #[test]
    fn decode_rejects_version_fifteen() {
        // Version 0xF, type DATA, no payload
        let wire = [0xF0, 0x00, 0x00, 0x00];
        let result = HarpFrame::decode(&wire);
        assert!(matches!(result, Err(TransportError::HarpUnsupportedVersion(0xF))));
    }

    // -- AC-6: Decode rejects truncated payload --

    #[test]
    fn decode_rejects_truncated_payload() {
        // Version 1, type DATA, payload length = 100, but only 50 bytes follow
        let declared_len: u16 = 100;
        let actual_payload = vec![0xAA; 50];
        let mut wire = vec![0x10, 0x00];
        wire.extend_from_slice(&declared_len.to_be_bytes());
        wire.extend_from_slice(&actual_payload);

        let result = HarpFrame::decode(&wire);
        assert!(matches!(
            result,
            Err(TransportError::HarpFrameTruncated {
                header_len: 100,
                available: 50,
            })
        ));
    }

    // -- AC-7: Decode returns correct bytes_consumed with trailing data --

    #[test]
    fn decode_with_trailing_data() {
        let frame = HarpFrame::data(SMALL_PAYLOAD.to_vec());
        let mut wire = frame.encode().expect("encode");
        let expected_consumed = wire.len();

        // Append trailing garbage
        wire.extend_from_slice(b"trailing data that should be ignored");

        let (decoded, consumed) = HarpFrame::decode(&wire).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, expected_consumed);
    }

    // -- AC-8: Max payload round-trip --

    #[test]
    fn max_payload_round_trip() {
        let payload = vec![0xBB; HARP_MAX_PAYLOAD_LEN];
        let frame = HarpFrame::data(payload.clone());
        let wire = frame.encode().expect("encode");

        assert_eq!(wire.len(), HARP_HEADER_LEN + HARP_MAX_PAYLOAD_LEN);

        let (decoded, consumed) = HarpFrame::decode(&wire).expect("decode");
        assert_eq!(decoded.payload.len(), HARP_MAX_PAYLOAD_LEN);
        assert_eq!(decoded.payload, payload);
        assert_eq!(consumed, wire.len());
    }

    // -- AC-9: Encode rejects payload > 65535 --

    #[test]
    fn encode_rejects_oversized_payload() {
        let payload = vec![0xCC; HARP_MAX_PAYLOAD_LEN + 1];
        let frame = HarpFrame::data(payload);
        let result = frame.encode();
        assert!(matches!(
            result,
            Err(TransportError::HarpPayloadTooLarge(size)) if size == HARP_MAX_PAYLOAD_LEN + 1
        ));
    }

    // -- AC-10: EncryptedChannel output as HARP DATA payload --

    #[test]
    fn encrypted_channel_payload_round_trip() {
        use crate::{crypto::aead::KEY_LEN, transport::encrypted_channel::EncryptedChannel};

        let tx_key = [0x01u8; KEY_LEN];
        let rx_key = [0x02u8; KEY_LEN];

        let mut sender = EncryptedChannel::new(tx_key, rx_key);
        let mut receiver = EncryptedChannel::new(rx_key, tx_key);

        let original = b"tunnel packet data";
        let encrypted = sender.send(original).expect("encrypt");

        // Wrap encrypted data in HARP frame
        let frame = HarpFrame::data(encrypted);
        let wire = frame.encode().expect("encode");
        let (decoded, _consumed) = HarpFrame::decode(&wire).expect("decode");

        // Decrypt from HARP frame payload
        let decrypted = receiver.recv(&decoded.payload).expect("decrypt");
        assert_eq!(decrypted, original);
    }

    // -- AC-11: HarpFrameReader accumulates partial data --

    #[test]
    fn reader_accumulates_partial_data() {
        let frame = HarpFrame::data(SMALL_PAYLOAD.to_vec());
        let wire = frame.encode().expect("encode");

        let mut reader = HarpFrameReader::new();

        // Push only the header (not enough for the full frame)
        reader.push(&wire[..HARP_HEADER_LEN]);
        assert!(reader.next_frame().is_none(), "should not yield frame with only header");

        // Push the rest of the payload
        reader.push(&wire[HARP_HEADER_LEN..]);
        let result = reader.next_frame();
        assert!(result.is_some(), "should yield frame after full data pushed");
        let decoded = result.unwrap().expect("decode");
        assert_eq!(decoded, frame);

        // Buffer should be drained
        assert_eq!(reader.buffered_len(), 0);
    }

    // -- AC-12: HarpFrameReader yields multiple frames from single buffer --

    #[test]
    fn reader_yields_multiple_frames() {
        let frame1 = HarpFrame::data(b"first".to_vec());
        let frame2 = HarpFrame::keepalive();
        let frame3 = HarpFrame::data(b"third".to_vec());

        let mut combined = Vec::new();
        combined.extend_from_slice(&frame1.encode().expect("encode1"));
        combined.extend_from_slice(&frame2.encode().expect("encode2"));
        combined.extend_from_slice(&frame3.encode().expect("encode3"));

        let mut reader = HarpFrameReader::new();
        reader.push(&combined);

        let decoded1 = reader.next_frame().unwrap().expect("decode1");
        assert_eq!(decoded1, frame1);

        let decoded2 = reader.next_frame().unwrap().expect("decode2");
        assert_eq!(decoded2, frame2);

        let decoded3 = reader.next_frame().unwrap().expect("decode3");
        assert_eq!(decoded3, frame3);

        assert!(reader.next_frame().is_none());
        assert_eq!(reader.buffered_len(), 0);
    }

    // -- AC-13: HarpFrameReader handles split at every byte boundary --

    #[test]
    fn reader_handles_byte_by_byte_push() {
        let frame = HarpFrame::data(SMALL_PAYLOAD.to_vec());
        let wire = frame.encode().expect("encode");

        let mut reader = HarpFrameReader::new();

        // Push one byte at a time
        for (i, &byte) in wire.iter().enumerate() {
            reader.push(&[byte]);
            if i < wire.len() - 1 {
                assert!(reader.next_frame().is_none(), "should not yield frame at byte {i}");
            }
        }

        let decoded = reader.next_frame().unwrap().expect("decode after all bytes");
        assert_eq!(decoded, frame);
        assert_eq!(reader.buffered_len(), 0);
    }

    // -- AC-14: Decode rejects unknown frame type --

    #[test]
    fn decode_rejects_unknown_frame_type() {
        // Version 1, type 0x3 (unknown), no payload
        let wire = [0x13, 0x00, 0x00, 0x00];
        let result = HarpFrame::decode(&wire);
        assert!(matches!(result, Err(TransportError::HarpUnknownFrameType(0x3))));
    }

    #[test]
    fn decode_rejects_frame_type_0xf() {
        // Version 1, type 0xF (unknown), no payload
        let wire = [0x1F, 0x00, 0x00, 0x00];
        let result = HarpFrame::decode(&wire);
        assert!(matches!(result, Err(TransportError::HarpUnknownFrameType(0xF))));
    }

    // -- Wire format verification --

    #[test]
    fn wire_format_structure() {
        let payload = b"test";
        let frame = HarpFrame::data(payload.to_vec());
        let wire = frame.encode().expect("encode");

        // Byte 0: version=1 << 4 | type=0 = 0x10
        assert_eq!(wire[0], 0x10);
        // Byte 1: reserved = 0x00
        assert_eq!(wire[1], HARP_RESERVED_BYTE);
        // Bytes 2-3: payload length = 4
        let len = u16::from_be_bytes([wire[2], wire[3]]);
        assert_eq!(len, payload.len() as u16);
        // Bytes 4+: payload
        assert_eq!(&wire[HARP_HEADER_LEN..], payload);
    }

    #[test]
    fn keepalive_wire_format() {
        let frame = HarpFrame::keepalive();
        let wire = frame.encode().expect("encode");

        // Byte 0: version=1 << 4 | type=1 = 0x11
        assert_eq!(wire[0], 0x11);
        assert_eq!(wire[1], HARP_RESERVED_BYTE);
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 0);
        assert_eq!(wire.len(), HARP_HEADER_LEN);
    }

    #[test]
    fn close_wire_format() {
        let frame = HarpFrame::close();
        let wire = frame.encode().expect("encode");

        // Byte 0: version=1 << 4 | type=2 = 0x12
        assert_eq!(wire[0], 0x12);
        assert_eq!(wire[1], HARP_RESERVED_BYTE);
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 0);
        assert_eq!(wire.len(), HARP_HEADER_LEN);
    }

    // -- Reader error propagation --

    #[test]
    fn reader_propagates_version_error() {
        let mut reader = HarpFrameReader::new();
        // Push a frame with bad version (0x00) but valid length=0
        reader.push(&[0x00, 0x00, 0x00, 0x00]);

        let result = reader.next_frame();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Err(TransportError::HarpUnsupportedVersion(0))));
    }

    // -- Data frame with empty payload --

    #[test]
    fn data_frame_empty_payload() {
        let frame = HarpFrame::data(Vec::new());
        let wire = frame.encode().expect("encode");
        let (decoded, consumed) = HarpFrame::decode(&wire).expect("decode");

        assert_eq!(decoded.frame_type, HarpFrameType::Data);
        assert!(decoded.payload.is_empty());
        assert_eq!(consumed, HARP_HEADER_LEN);
    }

    // -- Decode ignores reserved byte --

    #[test]
    fn decode_ignores_nonzero_reserved_byte() {
        // Version 1, type DATA, reserved=0xFF, payload_len=0
        let wire = [0x10, 0xFF, 0x00, 0x00];
        let (decoded, _consumed) = HarpFrame::decode(&wire).expect("decode");
        assert_eq!(decoded.frame_type, HarpFrameType::Data);
        assert!(decoded.payload.is_empty());
    }

    // -- Reader with two frames, second partially buffered --

    #[test]
    fn reader_partial_second_frame() {
        let frame1 = HarpFrame::keepalive();
        let frame2 = HarpFrame::data(b"payload".to_vec());

        let wire1 = frame1.encode().expect("encode1");
        let wire2 = frame2.encode().expect("encode2");

        let mut reader = HarpFrameReader::new();

        // Push all of frame1 + half of frame2
        let split_point = wire2.len() / 2;
        let mut combined = wire1.clone();
        combined.extend_from_slice(&wire2[..split_point]);
        reader.push(&combined);

        // Frame1 should be available
        let decoded1 = reader.next_frame().unwrap().expect("decode1");
        assert_eq!(decoded1, frame1);

        // Frame2 not yet complete
        assert!(reader.next_frame().is_none());

        // Push the rest of frame2
        reader.push(&wire2[split_point..]);
        let decoded2 = reader.next_frame().unwrap().expect("decode2");
        assert_eq!(decoded2, frame2);

        assert_eq!(reader.buffered_len(), 0);
    }

    // -- Default trait for HarpFrameReader --

    #[test]
    fn reader_default_is_empty() {
        let reader = HarpFrameReader::default();
        assert_eq!(reader.buffered_len(), 0);
    }

    // -----------------------------------------------------------------------
    // Pipeline Bridge Tests (FRD: specs/frds/FRD-20260223-harp-pipeline-bridge.md)
    // -----------------------------------------------------------------------

    /// Channel capacity used in pipeline bridge tests.
    const TEST_CHANNEL_CAPACITY: usize = 16;

    // -- AC-1: HarpSender encodes payload as HARP DATA frame and sends --

    #[tokio::test]
    async fn harp_sender_encodes_data_frame() {
        let (tx, mut rx) = mpsc::channel(TEST_CHANNEL_CAPACITY);
        let sender = HarpSender::new(tx);

        let payload = b"encrypted-payload";
        sender.send_datagram(payload).expect("send");

        let raw = rx.recv().await.expect("recv");
        let (frame, _consumed) = HarpFrame::decode(&raw).expect("decode");
        assert_eq!(frame.frame_type, HarpFrameType::Data);
        assert_eq!(frame.payload, payload);
    }

    // -- AC-2: HarpReceiver decodes DATA frame and returns payload --

    #[tokio::test]
    async fn harp_receiver_decodes_data_frame() {
        let (tx, rx) = mpsc::channel(TEST_CHANNEL_CAPACITY);
        let receiver = HarpReceiver::new(Arc::new(TokioMutex::new(rx)));

        let payload = b"tunnel-packet".to_vec();
        let frame = HarpFrame::data(payload.clone());
        let wire = frame.encode().expect("encode");
        tx.send(wire).await.expect("send");

        let result = receiver.recv_datagram().await.expect("recv");
        assert_eq!(result, payload);
    }

    // -- AC-3: HarpReceiver skips KEEPALIVE frames --

    #[tokio::test]
    async fn harp_receiver_skips_keepalive() {
        let (tx, rx) = mpsc::channel(TEST_CHANNEL_CAPACITY);
        let receiver = HarpReceiver::new(Arc::new(TokioMutex::new(rx)));

        // Send keepalive, then data
        let keepalive = HarpFrame::keepalive().encode().expect("encode ka");
        let payload = b"after-keepalive".to_vec();
        let data = HarpFrame::data(payload.clone()).encode().expect("encode data");
        tx.send(keepalive).await.expect("send ka");
        tx.send(data).await.expect("send data");

        // Should skip keepalive and return data payload
        let result = receiver.recv_datagram().await.expect("recv");
        assert_eq!(result, payload);
    }

    // -- AC-4: HarpReceiver returns error on CLOSE frame --

    #[tokio::test]
    async fn harp_receiver_returns_error_on_close() {
        let (tx, rx) = mpsc::channel(TEST_CHANNEL_CAPACITY);
        let receiver = HarpReceiver::new(Arc::new(TokioMutex::new(rx)));

        let close = HarpFrame::close().encode().expect("encode close");
        tx.send(close).await.expect("send close");

        let result = receiver.recv_datagram().await;
        assert!(matches!(result, Err(TransportError::HarpSessionClosed)));
    }

    // -- AC-5: HarpSender returns error on closed channel --

    #[test]
    fn harp_sender_returns_error_on_closed_channel() {
        let (tx, rx) = mpsc::channel(TEST_CHANNEL_CAPACITY);
        drop(rx); // close the receiving end
        let sender = HarpSender::new(tx);

        let result = sender.send_datagram(b"payload");
        assert!(matches!(result, Err(TransportError::HarpChannelClosed)));
    }

    // -- AC-6: HarpReceiver returns error on closed channel --

    #[tokio::test]
    async fn harp_receiver_returns_error_on_closed_channel() {
        let (tx, rx) = mpsc::channel(TEST_CHANNEL_CAPACITY);
        drop(tx); // close the sending end
        let receiver = HarpReceiver::new(Arc::new(TokioMutex::new(rx)));

        let result = receiver.recv_datagram().await;
        assert!(matches!(result, Err(TransportError::HarpChannelClosed)));
    }

    // -- HarpSender round-trip: encode then decode --

    #[tokio::test]
    async fn harp_sender_round_trip() {
        let (tx, mut rx) = mpsc::channel(TEST_CHANNEL_CAPACITY);
        let sender = HarpSender::new(tx);

        let payloads: Vec<&[u8]> = vec![b"first", b"second", b"third"];
        for payload in &payloads {
            sender.send_datagram(payload).expect("send");
        }

        for expected in &payloads {
            let raw = rx.recv().await.expect("recv");
            let (frame, _) = HarpFrame::decode(&raw).expect("decode");
            assert_eq!(frame.payload, *expected);
        }
    }

    // -- HarpReceiver skips multiple keepalives --

    #[tokio::test]
    async fn harp_receiver_skips_multiple_keepalives() {
        let (tx, rx) = mpsc::channel(TEST_CHANNEL_CAPACITY);
        let receiver = HarpReceiver::new(Arc::new(TokioMutex::new(rx)));

        let ka = HarpFrame::keepalive().encode().expect("encode");
        tx.send(ka.clone()).await.expect("send ka1");
        tx.send(ka.clone()).await.expect("send ka2");
        tx.send(ka).await.expect("send ka3");

        let payload = b"after-three-keepalives".to_vec();
        let data = HarpFrame::data(payload.clone()).encode().expect("encode");
        tx.send(data).await.expect("send data");

        let result = receiver.recv_datagram().await.expect("recv");
        assert_eq!(result, payload);
    }

    // -- Sender + Receiver end-to-end --

    #[tokio::test]
    async fn sender_receiver_end_to_end() {
        let (tx, rx) = mpsc::channel(TEST_CHANNEL_CAPACITY);
        let sender = HarpSender::new(tx);
        let receiver = HarpReceiver::new(Arc::new(TokioMutex::new(rx)));

        let payload = b"e2e-test-payload";
        sender.send_datagram(payload).expect("send");

        let result = receiver.recv_datagram().await.expect("recv");
        assert_eq!(result, payload);
    }
}
