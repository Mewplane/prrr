// FRD: specs/frds/FRD-016.md

//! Wire message types for the Whisper messaging protocol.
//!
//! Defines the serializable envelope format for messages exchanged between
//! clients and the relay server. All messages use a self-describing binary
//! format with version, type, sender identity, and unique message ID.

use crate::crypto::x25519;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current wire protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Byte length of a message ID (random UUID-like identifier).
pub const MSG_ID_LEN: usize = 16;

/// Byte length of a peer identity (X25519 public key).
pub const PEER_ID_LEN: usize = x25519::KEY_LEN;

/// Minimum wire message size: version(1) + type(1) + sender_id(32) + msg_id(16) = 50.
pub const MIN_WIRE_LEN: usize = 1 + 1 + PEER_ID_LEN + MSG_ID_LEN;

/// Length prefix for the ratchet header inside an encrypted envelope (4 bytes, BE).
pub const HEADER_LEN_PREFIX: usize = 4;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Wire message type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Encrypted data message carrying a ratchet-encrypted payload.
    Data = 0x01,
    /// Acknowledgment of a previously received message.
    Ack = 0x02,
    /// Request to fetch all queued messages from the relay.
    Fetch = 0x03,
}

impl MessageType {
    /// Parse a message type from a byte value.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Data),
            0x02 => Some(Self::Ack),
            0x03 => Some(Self::Fetch),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique peer identity — an X25519 public key.
pub type PeerId = [u8; PEER_ID_LEN];

/// Unique message identifier (16 random bytes).
pub type MessageId = [u8; MSG_ID_LEN];

/// Encrypted envelope: ratchet header + AEAD ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    /// Serialized `MessageHeader` from the Double Ratchet.
    pub ratchet_header: Vec<u8>,
    /// AEAD ciphertext produced by `RatchetState::encrypt()`.
    pub ciphertext: Vec<u8>,
}

impl EncryptedEnvelope {
    /// Serialize to bytes: `[4-byte header_len (BE)][ratchet_header][ciphertext]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_len = self.ratchet_header.len() as u32;
        let total = HEADER_LEN_PREFIX + self.ratchet_header.len() + self.ciphertext.len();
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&header_len.to_be_bytes());
        buf.extend_from_slice(&self.ratchet_header);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, WireError> {
        if data.len() < HEADER_LEN_PREFIX {
            return Err(WireError::TooShort {
                expected: HEADER_LEN_PREFIX,
                actual: data.len(),
            });
        }

        let header_len = u32::from_be_bytes(data[..HEADER_LEN_PREFIX].try_into().map_err(|_| WireError::InvalidFormat)?) as usize;

        let envelope_min = HEADER_LEN_PREFIX + header_len;
        if data.len() < envelope_min {
            return Err(WireError::TooShort {
                expected: envelope_min,
                actual: data.len(),
            });
        }

        let ratchet_header = data[HEADER_LEN_PREFIX..envelope_min].to_vec();
        let ciphertext = data[envelope_min..].to_vec();

        Ok(Self {
            ratchet_header,
            ciphertext,
        })
    }
}

/// Payload for a Data message: recipient + encrypted envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayload {
    /// Recipient's peer identity.
    pub recipient_id: PeerId,
    /// Encrypted envelope containing ratchet header + ciphertext.
    pub envelope: EncryptedEnvelope,
}

/// Payload for an Ack message: the ID of the acknowledged message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckPayload {
    /// Message ID being acknowledged.
    pub acked_msg_id: MessageId,
}

/// Wire message envelope for the Whisper protocol.
#[derive(Debug, Clone)]
pub struct WireMessage {
    /// Sender's peer identity (X25519 public key).
    pub sender_id: PeerId,
    /// Unique message identifier.
    pub msg_id: MessageId,
    /// Message payload (type-dependent).
    pub payload: WirePayload,
}

/// Type-discriminated payload.
#[derive(Debug, Clone)]
pub enum WirePayload {
    /// Encrypted data message.
    Data(DataPayload),
    /// Delivery acknowledgment.
    Ack(AckPayload),
    /// Fetch request (no payload).
    Fetch,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from wire message serialization/deserialization.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Message too short to contain required fields.
    #[error("message too short: expected at least {expected} bytes, got {actual}")]
    TooShort {
        /// Minimum expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Unknown or unsupported protocol version.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Unknown message type byte.
    #[error("unknown message type: 0x{0:02x}")]
    UnknownType(u8),

    /// Payload format invalid.
    #[error("invalid message format")]
    InvalidFormat,
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

impl WireMessage {
    /// Serialize this message to its wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let msg_type = match &self.payload {
            WirePayload::Data(_) => MessageType::Data,
            WirePayload::Ack(_) => MessageType::Ack,
            WirePayload::Fetch => MessageType::Fetch,
        };

        let payload_bytes = match &self.payload {
            WirePayload::Data(data) => {
                let env_bytes = data.envelope.to_bytes();
                let mut buf = Vec::with_capacity(PEER_ID_LEN + env_bytes.len());
                buf.extend_from_slice(&data.recipient_id);
                buf.extend_from_slice(&env_bytes);
                buf
            }
            WirePayload::Ack(ack) => ack.acked_msg_id.to_vec(),
            WirePayload::Fetch => Vec::new(),
        };

        let total = MIN_WIRE_LEN + payload_bytes.len();
        let mut buf = Vec::with_capacity(total);
        buf.push(PROTOCOL_VERSION);
        buf.push(msg_type as u8);
        buf.extend_from_slice(&self.sender_id);
        buf.extend_from_slice(&self.msg_id);
        buf.extend_from_slice(&payload_bytes);
        buf
    }

    /// Deserialize a wire message from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, WireError> {
        if data.len() < MIN_WIRE_LEN {
            return Err(WireError::TooShort {
                expected: MIN_WIRE_LEN,
                actual: data.len(),
            });
        }

        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }

        let msg_type = MessageType::from_byte(data[1]).ok_or(WireError::UnknownType(data[1]))?;

        let sender_id: PeerId = data[2..2 + PEER_ID_LEN].try_into().map_err(|_| WireError::InvalidFormat)?;

        let msg_id_start = 2 + PEER_ID_LEN;
        let msg_id: MessageId = data[msg_id_start..msg_id_start + MSG_ID_LEN]
            .try_into()
            .map_err(|_| WireError::InvalidFormat)?;

        let payload_start = MIN_WIRE_LEN;
        let payload_data = &data[payload_start..];

        let payload = match msg_type {
            MessageType::Data => {
                let min_data_len = PEER_ID_LEN + HEADER_LEN_PREFIX;
                if payload_data.len() < min_data_len {
                    return Err(WireError::TooShort {
                        expected: MIN_WIRE_LEN + min_data_len,
                        actual: data.len(),
                    });
                }
                let recipient_id: PeerId = payload_data[..PEER_ID_LEN].try_into().map_err(|_| WireError::InvalidFormat)?;
                let envelope = EncryptedEnvelope::from_bytes(&payload_data[PEER_ID_LEN..])?;
                WirePayload::Data(DataPayload { recipient_id, envelope })
            }
            MessageType::Ack => {
                if payload_data.len() < MSG_ID_LEN {
                    return Err(WireError::TooShort {
                        expected: MIN_WIRE_LEN + MSG_ID_LEN,
                        actual: data.len(),
                    });
                }
                let acked_msg_id: MessageId = payload_data[..MSG_ID_LEN].try_into().map_err(|_| WireError::InvalidFormat)?;
                WirePayload::Ack(AckPayload { acked_msg_id })
            }
            MessageType::Fetch => WirePayload::Fetch,
        };

        Ok(Self {
            sender_id,
            msg_id,
            payload,
        })
    }
}

/// Generate a random message ID using the OS CSPRNG.
pub fn generate_msg_id() -> MessageId {
    let mut id = [0u8; MSG_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    id
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SENDER: PeerId = [0xAA; PEER_ID_LEN];
    const TEST_RECIPIENT: PeerId = [0xBB; PEER_ID_LEN];
    const TEST_MSG_ID: MessageId = [0x11; MSG_ID_LEN];
    const TEST_ACK_MSG_ID: MessageId = [0x22; MSG_ID_LEN];

    fn test_data_message() -> WireMessage {
        WireMessage {
            sender_id: TEST_SENDER,
            msg_id: TEST_MSG_ID,
            payload: WirePayload::Data(DataPayload {
                recipient_id: TEST_RECIPIENT,
                envelope: EncryptedEnvelope {
                    ratchet_header: vec![0xCC; 41],
                    ciphertext: vec![0xDD; 64],
                },
            }),
        }
    }

    fn test_ack_message() -> WireMessage {
        WireMessage {
            sender_id: TEST_SENDER,
            msg_id: TEST_MSG_ID,
            payload: WirePayload::Ack(AckPayload {
                acked_msg_id: TEST_ACK_MSG_ID,
            }),
        }
    }

    fn test_fetch_message() -> WireMessage {
        WireMessage {
            sender_id: TEST_SENDER,
            msg_id: TEST_MSG_ID,
            payload: WirePayload::Fetch,
        }
    }

    // T-1: Data message serialize/deserialize round-trip
    #[test]
    fn data_message_round_trip() {
        let msg = test_data_message();
        let bytes = msg.to_bytes();
        let parsed = WireMessage::from_bytes(&bytes).expect("parse should succeed");

        assert_eq!(parsed.sender_id, TEST_SENDER);
        assert_eq!(parsed.msg_id, TEST_MSG_ID);
        match parsed.payload {
            WirePayload::Data(ref data) => {
                assert_eq!(data.recipient_id, TEST_RECIPIENT);
                assert_eq!(data.envelope.ratchet_header.len(), 41);
                assert_eq!(data.envelope.ciphertext.len(), 64);
            }
            _ => panic!("expected Data payload"),
        }
    }

    // T-2: Ack message serialize/deserialize round-trip
    #[test]
    fn ack_message_round_trip() {
        let msg = test_ack_message();
        let bytes = msg.to_bytes();
        let parsed = WireMessage::from_bytes(&bytes).expect("parse should succeed");

        assert_eq!(parsed.sender_id, TEST_SENDER);
        assert_eq!(parsed.msg_id, TEST_MSG_ID);
        match parsed.payload {
            WirePayload::Ack(ref ack) => {
                assert_eq!(ack.acked_msg_id, TEST_ACK_MSG_ID);
            }
            _ => panic!("expected Ack payload"),
        }
    }

    // T-3: Fetch message serialize/deserialize round-trip
    #[test]
    fn fetch_message_round_trip() {
        let msg = test_fetch_message();
        let bytes = msg.to_bytes();
        let parsed = WireMessage::from_bytes(&bytes).expect("parse should succeed");

        assert_eq!(parsed.sender_id, TEST_SENDER);
        assert_eq!(parsed.msg_id, TEST_MSG_ID);
        assert!(matches!(parsed.payload, WirePayload::Fetch));
    }

    // T-4a: Too short message → error
    #[test]
    fn too_short_message_error() {
        let short = vec![0u8; MIN_WIRE_LEN - 1];
        let result = WireMessage::from_bytes(&short);
        assert!(matches!(result, Err(WireError::TooShort { .. })));
    }

    // T-4b: Wrong version → error
    #[test]
    fn wrong_version_error() {
        let mut bytes = test_fetch_message().to_bytes();
        bytes[0] = 0xFF;
        let result = WireMessage::from_bytes(&bytes);
        assert!(matches!(result, Err(WireError::UnsupportedVersion(0xFF))));
    }

    // T-4c: Unknown message type → error
    #[test]
    fn unknown_type_error() {
        let mut bytes = test_fetch_message().to_bytes();
        bytes[1] = 0xFF;
        let result = WireMessage::from_bytes(&bytes);
        assert!(matches!(result, Err(WireError::UnknownType(0xFF))));
    }

    // T-4d: Data message with truncated payload → error
    #[test]
    fn data_message_truncated_payload_error() {
        let mut bytes = test_data_message().to_bytes();
        bytes.truncate(MIN_WIRE_LEN + 10); // Too short for recipient + envelope
        let result = WireMessage::from_bytes(&bytes);
        assert!(result.is_err());
    }

    // T-4e: Ack message with truncated payload → error
    #[test]
    fn ack_message_truncated_payload_error() {
        let mut bytes = test_ack_message().to_bytes();
        bytes.truncate(MIN_WIRE_LEN + 5); // Too short for acked_msg_id
        let result = WireMessage::from_bytes(&bytes);
        assert!(matches!(result, Err(WireError::TooShort { .. })));
    }

    // EncryptedEnvelope round-trip
    #[test]
    fn encrypted_envelope_round_trip() {
        let envelope = EncryptedEnvelope {
            ratchet_header: vec![0x01, 0x02, 0x03],
            ciphertext: vec![0x04, 0x05],
        };
        let bytes = envelope.to_bytes();
        let parsed = EncryptedEnvelope::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, envelope);
    }

    // EncryptedEnvelope empty ciphertext
    #[test]
    fn encrypted_envelope_empty_ciphertext() {
        let envelope = EncryptedEnvelope {
            ratchet_header: vec![0xAA; 41],
            ciphertext: Vec::new(),
        };
        let bytes = envelope.to_bytes();
        let parsed = EncryptedEnvelope::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, envelope);
    }

    // generate_msg_id produces unique IDs
    #[test]
    fn generate_msg_id_unique() {
        let id1 = generate_msg_id();
        let id2 = generate_msg_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), MSG_ID_LEN);
    }

    // MessageType from_byte covers all variants
    #[test]
    fn message_type_from_byte() {
        assert_eq!(MessageType::from_byte(0x01), Some(MessageType::Data));
        assert_eq!(MessageType::from_byte(0x02), Some(MessageType::Ack));
        assert_eq!(MessageType::from_byte(0x03), Some(MessageType::Fetch));
        assert_eq!(MessageType::from_byte(0x00), None);
        assert_eq!(MessageType::from_byte(0x04), None);
    }
}
