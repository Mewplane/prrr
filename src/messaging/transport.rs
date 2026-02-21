// FRD: specs/frds/FRD-016.md

//! Message transport: send/receive `WireMessage` over byte-oriented channels.
//!
//! This module provides traits and implementations for transporting serialized
//! wire messages. The transport is agnostic to the underlying byte channel —
//! it can use MASQUE datagrams, channels, or any byte sender/receiver.

use super::types::{WireError, WireMessage};

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Trait for sending raw bytes (wire messages) to a remote peer or relay.
pub trait MessageSender: Send + Sync {
    /// Send raw bytes to the remote side.
    fn send(&self, data: &[u8]) -> Result<(), TransportError>;
}

/// Trait for receiving raw bytes (wire messages) from a remote peer or relay.
pub trait MessageReceiver: Send + Sync {
    /// Receive raw bytes from the remote side.
    ///
    /// This is an async operation — implementations block until data arrives.
    fn recv(&self) -> impl std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from message transport operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Wire serialization/deserialization error.
    #[error(transparent)]
    Wire(#[from] WireError),

    /// Underlying I/O or channel error.
    #[error("transport send/recv failed: {0}")]
    Io(String),
}

// ---------------------------------------------------------------------------
// MessageTransport
// ---------------------------------------------------------------------------

/// Message transport that serializes/deserializes `WireMessage` over a byte channel.
pub struct MessageTransport<S, R> {
    sender: S,
    receiver: R,
}

impl<S: MessageSender, R: MessageReceiver> MessageTransport<S, R> {
    /// Create a new transport from a sender and receiver.
    pub fn new(sender: S, receiver: R) -> Self {
        Self { sender, receiver }
    }

    /// Send a wire message: serialize to bytes and transmit.
    pub fn send(&self, msg: &WireMessage) -> Result<(), TransportError> {
        let bytes = msg.to_bytes();
        self.sender.send(&bytes)
    }

    /// Receive a wire message: receive bytes and deserialize.
    pub async fn recv(&self) -> Result<WireMessage, TransportError> {
        let bytes = self.receiver.recv().await?;
        WireMessage::from_bytes(&bytes).map_err(TransportError::from)
    }
}

// ---------------------------------------------------------------------------
// Channel-based implementation (for testing and in-process use)
// ---------------------------------------------------------------------------

/// Channel-based message sender using `tokio::sync::mpsc`.
pub struct ChannelSender {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl ChannelSender {
    /// Create a new channel sender.
    pub fn new(tx: tokio::sync::mpsc::Sender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl MessageSender for ChannelSender {
    fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        self.tx.try_send(data.to_vec()).map_err(|e| TransportError::Io(e.to_string()))
    }
}

/// Channel-based message receiver using `tokio::sync::mpsc`.
pub struct ChannelReceiver {
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl ChannelReceiver {
    /// Create a new channel receiver.
    pub fn new(rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx: tokio::sync::Mutex::new(rx),
        }
    }
}

impl MessageReceiver for ChannelReceiver {
    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| TransportError::Io("channel closed".to_string()))
    }
}

/// Create a paired channel transport for testing.
///
/// Returns `(transport_a, transport_b)` where messages sent by A are received by B
/// and vice versa.
pub fn channel_pair(
    buffer: usize,
) -> (
    MessageTransport<ChannelSender, ChannelReceiver>,
    MessageTransport<ChannelSender, ChannelReceiver>,
) {
    let (tx_a, rx_a) = tokio::sync::mpsc::channel(buffer);
    let (tx_b, rx_b) = tokio::sync::mpsc::channel(buffer);

    let transport_a = MessageTransport::new(ChannelSender::new(tx_b), ChannelReceiver::new(rx_a));
    let transport_b = MessageTransport::new(ChannelSender::new(tx_a), ChannelReceiver::new(rx_b));

    (transport_a, transport_b)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::types::{AckPayload, DataPayload, EncryptedEnvelope, MSG_ID_LEN, MessageId, PEER_ID_LEN, PeerId, WirePayload};

    const TEST_SENDER: PeerId = [0xAA; PEER_ID_LEN];
    const TEST_RECIPIENT: PeerId = [0xBB; PEER_ID_LEN];
    const TEST_MSG_ID: MessageId = [0x11; MSG_ID_LEN];

    fn test_data_msg() -> WireMessage {
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

    fn test_ack_msg() -> WireMessage {
        WireMessage {
            sender_id: TEST_SENDER,
            msg_id: TEST_MSG_ID,
            payload: WirePayload::Ack(AckPayload {
                acked_msg_id: [0x22; MSG_ID_LEN],
            }),
        }
    }

    // T-11: Transport send/recv round-trip (Data)
    #[tokio::test]
    async fn transport_data_round_trip() {
        let channel_buf: usize = 16;
        let (transport_a, transport_b) = channel_pair(channel_buf);

        let msg = test_data_msg();
        transport_a.send(&msg).expect("send");

        let received = transport_b.recv().await.expect("recv");
        assert_eq!(received.sender_id, TEST_SENDER);
        assert_eq!(received.msg_id, TEST_MSG_ID);
        match received.payload {
            WirePayload::Data(ref data) => {
                assert_eq!(data.recipient_id, TEST_RECIPIENT);
            }
            _ => panic!("expected Data"),
        }
    }

    // Transport send/recv round-trip (Ack)
    #[tokio::test]
    async fn transport_ack_round_trip() {
        let channel_buf: usize = 16;
        let (transport_a, transport_b) = channel_pair(channel_buf);

        let msg = test_ack_msg();
        transport_a.send(&msg).expect("send");

        let received = transport_b.recv().await.expect("recv");
        assert_eq!(received.msg_id, TEST_MSG_ID);
        match received.payload {
            WirePayload::Ack(ref ack) => {
                assert_eq!(ack.acked_msg_id, [0x22; MSG_ID_LEN]);
            }
            _ => panic!("expected Ack"),
        }
    }

    // Transport channel closed → error
    #[tokio::test]
    async fn transport_channel_closed_error() {
        let channel_buf: usize = 16;
        let (tx_to_b, rx_from_a) = tokio::sync::mpsc::channel(channel_buf);
        let (tx_to_a, rx_from_b) = tokio::sync::mpsc::channel::<Vec<u8>>(channel_buf);

        let transport_b = MessageTransport::new(ChannelSender::new(tx_to_a), ChannelReceiver::new(rx_from_a));

        // Drop the only sender to B's receiver — channel closes
        drop(tx_to_b);
        let result = transport_b.recv().await;
        assert!(matches!(result, Err(TransportError::Io(_))));

        // Keep rx_from_b alive to avoid unused variable
        drop(rx_from_b);
    }

    // Bidirectional communication
    #[tokio::test]
    async fn bidirectional_communication() {
        let channel_buf: usize = 16;
        let (transport_a, transport_b) = channel_pair(channel_buf);

        // A sends to B
        let msg_a = test_data_msg();
        transport_a.send(&msg_a).expect("A send");

        // B sends to A
        let msg_b = test_ack_msg();
        transport_b.send(&msg_b).expect("B send");

        // B receives from A
        let recv_b = transport_b.recv().await.expect("B recv");
        assert!(matches!(recv_b.payload, WirePayload::Data(_)));

        // A receives from B
        let recv_a = transport_a.recv().await.expect("A recv");
        assert!(matches!(recv_a.payload, WirePayload::Ack(_)));
    }
}
