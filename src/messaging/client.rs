// FRD: specs/frds/FRD-016.md

//! High-level messaging client API for the Whisper protocol.
//!
//! Orchestrates the full send/receive lifecycle: session management,
//! ratchet encryption/decryption, wire serialization, and transport.
//! Sessions with peers are created lazily on first message and persist
//! for the connection lifetime.

use std::collections::HashMap;

use crate::{
    crypto::x25519,
    messaging::{
        ratchet::{MessageHeader, RatchetConfig, RatchetError, RatchetState},
        types::{AckPayload, DataPayload, EncryptedEnvelope, PeerId, WireMessage, WirePayload, generate_msg_id},
    },
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the messaging client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// No session exists with this peer.
    #[error("no session with peer {0:02x?}")]
    NoSession(PeerId),

    /// Ratchet encryption/decryption failed.
    #[error(transparent)]
    Ratchet(#[from] RatchetError),

    /// Message format error.
    #[error("message not a data message")]
    NotDataMessage,
}

// ---------------------------------------------------------------------------
// MessagingClient
// ---------------------------------------------------------------------------

/// High-level messaging client that manages peer sessions and message
/// encryption/decryption via the Double Ratchet.
pub struct MessagingClient {
    /// Our identity public key (used as sender_id in wire messages).
    identity: PeerId,
    /// Active ratchet sessions keyed by peer identity.
    sessions: HashMap<PeerId, RatchetState>,
    /// Ratchet configuration for new sessions.
    ratchet_config: RatchetConfig,
}

impl MessagingClient {
    /// Create a new messaging client with the given identity.
    pub fn new(identity: PeerId, ratchet_config: RatchetConfig) -> Self {
        Self {
            identity,
            sessions: HashMap::new(),
            ratchet_config,
        }
    }

    /// Register a pre-established ratchet session with a peer.
    ///
    /// This is used after PQXDH completes to register the resulting
    /// ratchet state for ongoing messaging.
    pub fn add_session(&mut self, peer_id: PeerId, state: RatchetState) {
        self.sessions.insert(peer_id, state);
    }

    /// Check if a session exists with a peer.
    pub fn has_session(&self, peer_id: &PeerId) -> bool {
        self.sessions.contains_key(peer_id)
    }

    /// Return the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Return this client's identity.
    pub fn identity(&self) -> &PeerId {
        &self.identity
    }

    /// Return a reference to the ratchet config (for creating sessions externally).
    pub fn ratchet_config(&self) -> &RatchetConfig {
        &self.ratchet_config
    }

    /// Encrypt a message for a peer and produce a `WireMessage` ready for sending.
    ///
    /// Returns the wire message and the generated message ID.
    pub fn prepare_message(&mut self, peer_id: &PeerId, plaintext: &[u8]) -> Result<WireMessage, ClientError> {
        let session = self.sessions.get_mut(peer_id).ok_or(ClientError::NoSession(*peer_id))?;

        let (header, ciphertext) = session.encrypt(plaintext)?;
        let ratchet_header = header.to_bytes();

        let msg_id = generate_msg_id();

        Ok(WireMessage {
            sender_id: self.identity,
            msg_id,
            payload: WirePayload::Data(DataPayload {
                recipient_id: *peer_id,
                envelope: EncryptedEnvelope {
                    ratchet_header,
                    ciphertext,
                },
            }),
        })
    }

    /// Process an incoming data message: decrypt and return the plaintext.
    ///
    /// Returns `(sender_id, plaintext)`.
    pub fn process_incoming(&mut self, msg: &WireMessage) -> Result<(PeerId, Vec<u8>), ClientError> {
        let data = match &msg.payload {
            WirePayload::Data(d) => d,
            _ => return Err(ClientError::NotDataMessage),
        };

        let session = self.sessions.get_mut(&msg.sender_id).ok_or(ClientError::NoSession(msg.sender_id))?;

        let header = MessageHeader::from_bytes(&data.envelope.ratchet_header)?;
        let plaintext = session.decrypt(&header, &data.envelope.ciphertext)?;

        Ok((msg.sender_id, plaintext))
    }

    /// Create an acknowledgment message for a received message.
    pub fn create_ack(&self, original_msg: &WireMessage) -> WireMessage {
        WireMessage {
            sender_id: self.identity,
            msg_id: generate_msg_id(),
            payload: WirePayload::Ack(AckPayload {
                acked_msg_id: original_msg.msg_id,
            }),
        }
    }

    /// Create a fetch request message.
    pub fn create_fetch(&self) -> WireMessage {
        WireMessage {
            sender_id: self.identity,
            msg_id: generate_msg_id(),
            payload: WirePayload::Fetch,
        }
    }
}

/// Helper: create a pair of messaging clients with pre-established ratchet sessions.
///
/// Returns `(alice_client, bob_client)` with sessions already registered.
/// Alice is the initiator, Bob is the responder.
pub fn create_session_pair(
    alice_identity: PeerId,
    bob_identity: PeerId,
    shared_secret: [u8; 32],
    ratchet_config: RatchetConfig,
) -> Result<(MessagingClient, MessagingClient), RatchetError> {
    let bob_dh = x25519::KeyPair::generate();
    let bob_dh_pub = bob_dh.public_key_bytes();

    // Alice and Bob need separate config instances
    let alice_config = RatchetConfig {
        max_skip: ratchet_config.max_skip,
        pq_ratchet_interval: ratchet_config.pq_ratchet_interval,
    };
    let bob_config = RatchetConfig {
        max_skip: ratchet_config.max_skip,
        pq_ratchet_interval: ratchet_config.pq_ratchet_interval,
    };
    let client_alice_config = RatchetConfig {
        max_skip: ratchet_config.max_skip,
        pq_ratchet_interval: ratchet_config.pq_ratchet_interval,
    };
    let client_bob_config = RatchetConfig {
        max_skip: ratchet_config.max_skip,
        pq_ratchet_interval: ratchet_config.pq_ratchet_interval,
    };

    let alice_ratchet = RatchetState::init_alice(shared_secret, bob_dh_pub, alice_config)?;
    let bob_ratchet = RatchetState::init_bob(shared_secret, bob_dh, bob_config);

    let mut alice = MessagingClient::new(alice_identity, client_alice_config);
    let mut bob = MessagingClient::new(bob_identity, client_bob_config);

    alice.add_session(bob_identity, alice_ratchet);
    bob.add_session(alice_identity, bob_ratchet);

    Ok((alice, bob))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::types::{MSG_ID_LEN, PEER_ID_LEN};

    const ALICE_ID: PeerId = [0xAA; PEER_ID_LEN];
    const BOB_ID: PeerId = [0xBB; PEER_ID_LEN];
    const SHARED_SECRET: [u8; 32] = [0xAB; 32];
    const TEST_PLAINTEXT: &[u8] = b"hello whisper";

    fn default_pair() -> (MessagingClient, MessagingClient) {
        create_session_pair(ALICE_ID, BOB_ID, SHARED_SECRET, RatchetConfig::default()).expect("session pair")
    }

    // T-12: Client send_message encrypts and produces valid wire message
    #[test]
    fn prepare_message_produces_wire_message() {
        let (mut alice, _bob) = default_pair();

        let wire_msg = alice.prepare_message(&BOB_ID, TEST_PLAINTEXT).expect("prepare");

        assert_eq!(wire_msg.sender_id, ALICE_ID);
        assert_eq!(wire_msg.msg_id.len(), MSG_ID_LEN);
        match &wire_msg.payload {
            WirePayload::Data(data) => {
                assert_eq!(data.recipient_id, BOB_ID);
                assert!(!data.envelope.ratchet_header.is_empty());
                assert!(!data.envelope.ciphertext.is_empty());
            }
            _ => panic!("expected Data payload"),
        }
    }

    // T-13: Client process_incoming decrypts correctly
    #[test]
    fn process_incoming_decrypts() {
        let (mut alice, mut bob) = default_pair();

        let wire_msg = alice.prepare_message(&BOB_ID, TEST_PLAINTEXT).expect("prepare");

        let (sender, plaintext) = bob.process_incoming(&wire_msg).expect("process");
        assert_eq!(sender, ALICE_ID);
        assert_eq!(plaintext, TEST_PLAINTEXT);
    }

    // T-14: Client creates ack after successful decrypt
    #[test]
    fn create_ack_after_decrypt() {
        let (mut alice, mut bob) = default_pair();

        let wire_msg = alice.prepare_message(&BOB_ID, TEST_PLAINTEXT).expect("prepare");

        bob.process_incoming(&wire_msg).expect("process");
        let ack = bob.create_ack(&wire_msg);

        assert_eq!(ack.sender_id, BOB_ID);
        match &ack.payload {
            WirePayload::Ack(a) => {
                assert_eq!(a.acked_msg_id, wire_msg.msg_id);
            }
            _ => panic!("expected Ack payload"),
        }
    }

    // No session → error
    #[test]
    fn no_session_error() {
        let unknown_peer: PeerId = [0xFF; PEER_ID_LEN];
        let mut alice = MessagingClient::new(ALICE_ID, RatchetConfig::default());

        let result = alice.prepare_message(&unknown_peer, TEST_PLAINTEXT);
        assert!(matches!(result, Err(ClientError::NoSession(_))));
    }

    // Process non-data message → error
    #[test]
    fn process_non_data_error() {
        let (mut _alice, mut bob) = default_pair();

        let fetch_msg = bob.create_fetch();
        let result = bob.process_incoming(&fetch_msg);
        assert!(matches!(result, Err(ClientError::NotDataMessage)));
    }

    // Bidirectional message exchange
    #[test]
    fn bidirectional_exchange() {
        let (mut alice, mut bob) = default_pair();

        // Alice → Bob
        let msg1 = alice.prepare_message(&BOB_ID, b"hello bob").expect("prepare");
        let (sender, pt) = bob.process_incoming(&msg1).expect("process");
        assert_eq!(sender, ALICE_ID);
        assert_eq!(pt, b"hello bob");

        // Bob → Alice
        let msg2 = bob.prepare_message(&ALICE_ID, b"hello alice").expect("prepare");
        let (sender, pt) = alice.process_incoming(&msg2).expect("process");
        assert_eq!(sender, BOB_ID);
        assert_eq!(pt, b"hello alice");
    }

    // T-15 (partial): 100 sequential messages Alice → Bob
    #[test]
    fn sequential_100_messages() {
        let (mut alice, mut bob) = default_pair();
        let msg_count: u32 = 100;

        for i in 0..msg_count {
            let plaintext = format!("message {i}");
            let wire_msg = alice.prepare_message(&BOB_ID, plaintext.as_bytes()).expect("prepare");
            let (sender, pt) = bob.process_incoming(&wire_msg).expect("process");
            assert_eq!(sender, ALICE_ID);
            assert_eq!(pt, plaintext.as_bytes());
        }
    }

    // T-15 (full): 100 bidirectional messages
    #[test]
    fn bidirectional_100_messages() {
        let (mut alice, mut bob) = default_pair();
        let msg_count: u32 = 100;

        for i in 0..msg_count {
            let a_text = format!("alice {i}");
            let a_msg = alice.prepare_message(&BOB_ID, a_text.as_bytes()).expect("prepare");
            let (sender, pt) = bob.process_incoming(&a_msg).expect("process");
            assert_eq!(sender, ALICE_ID);
            assert_eq!(pt, a_text.as_bytes());

            let b_text = format!("bob {i}");
            let b_msg = bob.prepare_message(&ALICE_ID, b_text.as_bytes()).expect("prepare");
            let (sender, pt) = alice.process_incoming(&b_msg).expect("process");
            assert_eq!(sender, BOB_ID);
            assert_eq!(pt, b_text.as_bytes());
        }
    }

    // Session management
    #[test]
    fn session_management() {
        let alice = MessagingClient::new(ALICE_ID, RatchetConfig::default());
        let expected_count: usize = 0;
        assert_eq!(alice.session_count(), expected_count);
        assert!(!alice.has_session(&BOB_ID));
        assert_eq!(*alice.identity(), ALICE_ID);
    }

    // Create fetch message
    #[test]
    fn create_fetch_message() {
        let alice = MessagingClient::new(ALICE_ID, RatchetConfig::default());
        let fetch = alice.create_fetch();
        assert_eq!(fetch.sender_id, ALICE_ID);
        assert!(matches!(fetch.payload, WirePayload::Fetch));
    }

    // T-16: Offline delivery simulation (enqueue, then process)
    #[test]
    fn offline_delivery_simulation() {
        use crate::messaging::relay::{MessageRelay, RelayConfig};

        let (mut alice, mut bob) = default_pair();

        // Alice sends messages while Bob is "offline" — relay queues them
        let mut relay = MessageRelay::new(RelayConfig::default());

        let msg_count: u32 = 5;
        for i in 0..msg_count {
            let text = format!("offline msg {i}");
            let wire_msg = alice.prepare_message(&BOB_ID, text.as_bytes()).expect("prepare");
            relay.enqueue(BOB_ID, wire_msg).expect("enqueue");
        }

        // Bob comes "online" — dequeue and process all messages
        let pending = relay.dequeue(&BOB_ID);
        assert_eq!(pending.len(), msg_count as usize);

        for (i, msg) in pending.iter().enumerate() {
            let (sender, pt) = bob.process_incoming(msg).expect("process");
            assert_eq!(sender, ALICE_ID);
            let expected = format!("offline msg {i}");
            assert_eq!(pt, expected.as_bytes());
        }
    }

    // Wire message round-trip through serialization
    #[test]
    fn wire_round_trip_through_serialization() {
        let (mut alice, mut bob) = default_pair();

        let wire_msg = alice.prepare_message(&BOB_ID, TEST_PLAINTEXT).expect("prepare");

        // Serialize and deserialize
        let bytes = wire_msg.to_bytes();
        let parsed = WireMessage::from_bytes(&bytes).expect("parse");

        // Bob can decrypt the deserialized message
        let (sender, pt) = bob.process_incoming(&parsed).expect("process");
        assert_eq!(sender, ALICE_ID);
        assert_eq!(pt, TEST_PLAINTEXT);
    }
}
