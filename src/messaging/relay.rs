// FRD: specs/frds/FRD-016.md

//! Server-side message relay for store-and-forward delivery.
//!
//! The relay maintains per-peer bounded queues for messages awaiting delivery.
//! When a recipient connects and sends a Fetch request, all queued messages
//! are dequeued and sent. Acknowledgments confirm delivery and remove messages
//! from the queue. Duplicate message IDs are detected and dropped.

use std::collections::{HashMap, HashSet, VecDeque};

use super::types::{MessageId, PeerId, WireMessage};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum number of messages per peer queue.
const DEFAULT_MAX_QUEUE_SIZE: usize = 1000;

/// Default maximum size of the deduplication seen-ID set.
const DEFAULT_MAX_SEEN_IDS: usize = 10_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from relay operations.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// Message with this ID has already been processed.
    #[error("duplicate message: {0:02x?}")]
    Duplicate(MessageId),
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the message relay.
pub struct RelayConfig {
    /// Maximum number of messages per peer queue.
    pub max_queue_size: usize,
    /// Maximum size of the deduplication window.
    pub max_seen_ids: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_queue_size: DEFAULT_MAX_QUEUE_SIZE,
            max_seen_ids: DEFAULT_MAX_SEEN_IDS,
        }
    }
}

// ---------------------------------------------------------------------------
// MessageRelay
// ---------------------------------------------------------------------------

/// Server-side message relay with per-peer bounded queues.
pub struct MessageRelay {
    /// Per-peer message queues.
    queues: HashMap<PeerId, VecDeque<WireMessage>>,
    /// Set of recently seen message IDs for deduplication.
    seen_ids: HashSet<MessageId>,
    /// Insertion-order tracking for LRU eviction of seen IDs.
    seen_order: VecDeque<MessageId>,
    /// Configuration.
    config: RelayConfig,
}

impl MessageRelay {
    /// Create a new relay with the given configuration.
    pub fn new(config: RelayConfig) -> Self {
        Self {
            queues: HashMap::new(),
            seen_ids: HashSet::new(),
            seen_order: VecDeque::new(),
            config,
        }
    }

    /// Enqueue a message for a recipient.
    ///
    /// Returns `Err(RelayError::Duplicate)` if the message ID was already seen.
    /// If the recipient's queue is full, the oldest message is dropped.
    pub fn enqueue(&mut self, recipient_id: PeerId, msg: WireMessage) -> Result<(), RelayError> {
        // Deduplication check
        if self.seen_ids.contains(&msg.msg_id) {
            return Err(RelayError::Duplicate(msg.msg_id));
        }

        // Track message ID in seen set
        self.mark_seen(msg.msg_id);

        // Get or create the recipient's queue
        let queue = self.queues.entry(recipient_id).or_default();

        // Drop oldest if queue is full
        if queue.len() >= self.config.max_queue_size {
            queue.pop_front();
        }

        queue.push_back(msg);
        Ok(())
    }

    /// Dequeue all pending messages for a peer.
    ///
    /// Returns the messages in FIFO order and removes them from the queue.
    pub fn dequeue(&mut self, peer_id: &PeerId) -> Vec<WireMessage> {
        self.queues.remove(peer_id).map(Vec::from).unwrap_or_default()
    }

    /// Acknowledge a message, removing it from the recipient's queue if present.
    pub fn ack(&mut self, recipient_id: &PeerId, msg_id: &MessageId) {
        if let Some(queue) = self.queues.get_mut(recipient_id) {
            queue.retain(|m| m.msg_id != *msg_id);
            if queue.is_empty() {
                self.queues.remove(recipient_id);
            }
        }
    }

    /// Check if a message ID has been seen recently.
    pub fn is_duplicate(&self, msg_id: &MessageId) -> bool {
        self.seen_ids.contains(msg_id)
    }

    /// Return the number of queued messages for a peer.
    pub fn queue_len(&self, peer_id: &PeerId) -> usize {
        self.queues.get(peer_id).map_or(0, VecDeque::len)
    }

    /// Return the total number of messages across all queues.
    pub fn total_queued(&self) -> usize {
        self.queues.values().map(VecDeque::len).sum()
    }

    /// Return the number of tracked seen IDs.
    pub fn seen_count(&self) -> usize {
        self.seen_ids.len()
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Mark a message ID as seen, evicting oldest if window is full.
    fn mark_seen(&mut self, msg_id: MessageId) {
        self.seen_ids.insert(msg_id);
        self.seen_order.push_back(msg_id);

        // LRU eviction when seen set exceeds max
        while self.seen_ids.len() > self.config.max_seen_ids {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_ids.remove(&oldest);
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
    use crate::messaging::types::{DataPayload, EncryptedEnvelope, PEER_ID_LEN, WirePayload};

    const PEER_A: PeerId = [0xAA; PEER_ID_LEN];
    const PEER_B: PeerId = [0xBB; PEER_ID_LEN];
    const PEER_C: PeerId = [0xCC; PEER_ID_LEN];

    fn make_data_msg(sender: PeerId, msg_id: MessageId, recipient: PeerId) -> WireMessage {
        WireMessage {
            sender_id: sender,
            msg_id,
            payload: WirePayload::Data(DataPayload {
                recipient_id: recipient,
                envelope: EncryptedEnvelope {
                    ratchet_header: vec![0x01; 41],
                    ciphertext: vec![0x02; 32],
                },
            }),
        }
    }

    fn msg_id(val: u8) -> MessageId {
        [val; 16]
    }

    // T-5: Enqueue and dequeue single message
    #[test]
    fn enqueue_dequeue_single() {
        let mut relay = MessageRelay::new(RelayConfig::default());
        let msg = make_data_msg(PEER_A, msg_id(1), PEER_B);

        relay.enqueue(PEER_B, msg).expect("enqueue");
        let expected_queue_len: usize = 1;
        assert_eq!(relay.queue_len(&PEER_B), expected_queue_len);

        let msgs = relay.dequeue(&PEER_B);
        assert_eq!(msgs.len(), expected_queue_len);
        assert_eq!(msgs[0].sender_id, PEER_A);
        assert_eq!(msgs[0].msg_id, msg_id(1));

        // Queue is empty after dequeue
        let expected_empty: usize = 0;
        assert_eq!(relay.queue_len(&PEER_B), expected_empty);
    }

    // T-6: Enqueue multiple peers, dequeue correct peer
    #[test]
    fn enqueue_multiple_peers_dequeue_correct() {
        let mut relay = MessageRelay::new(RelayConfig::default());

        relay.enqueue(PEER_B, make_data_msg(PEER_A, msg_id(1), PEER_B)).expect("enqueue B");
        relay.enqueue(PEER_C, make_data_msg(PEER_A, msg_id(2), PEER_C)).expect("enqueue C");
        relay
            .enqueue(PEER_B, make_data_msg(PEER_C, msg_id(3), PEER_B))
            .expect("enqueue B again");

        // Dequeue PEER_B: should get 2 messages
        let b_msgs = relay.dequeue(&PEER_B);
        let expected_b_count: usize = 2;
        assert_eq!(b_msgs.len(), expected_b_count);
        assert_eq!(b_msgs[0].msg_id, msg_id(1));
        assert_eq!(b_msgs[1].msg_id, msg_id(3));

        // Dequeue PEER_C: should get 1 message
        let c_msgs = relay.dequeue(&PEER_C);
        let expected_c_count: usize = 1;
        assert_eq!(c_msgs.len(), expected_c_count);
        assert_eq!(c_msgs[0].msg_id, msg_id(2));
    }

    // T-7: Dedup: same msg_id ignored
    #[test]
    fn dedup_same_msg_id_ignored() {
        let mut relay = MessageRelay::new(RelayConfig::default());
        let id = msg_id(42);

        relay.enqueue(PEER_B, make_data_msg(PEER_A, id, PEER_B)).expect("first enqueue");

        let result = relay.enqueue(PEER_B, make_data_msg(PEER_A, id, PEER_B));
        assert!(matches!(result, Err(RelayError::Duplicate(_))));

        // Only one message in queue
        let expected_count: usize = 1;
        assert_eq!(relay.queue_len(&PEER_B), expected_count);
    }

    // T-8: Ack removes message
    #[test]
    fn ack_removes_message() {
        let mut relay = MessageRelay::new(RelayConfig::default());
        let id1 = msg_id(1);
        let id2 = msg_id(2);

        relay.enqueue(PEER_B, make_data_msg(PEER_A, id1, PEER_B)).expect("enqueue 1");
        relay.enqueue(PEER_B, make_data_msg(PEER_A, id2, PEER_B)).expect("enqueue 2");

        let expected_before: usize = 2;
        assert_eq!(relay.queue_len(&PEER_B), expected_before);

        relay.ack(&PEER_B, &id1);
        let expected_after: usize = 1;
        assert_eq!(relay.queue_len(&PEER_B), expected_after);

        // Remaining message is id2
        let msgs = relay.dequeue(&PEER_B);
        assert_eq!(msgs[0].msg_id, id2);
    }

    // T-9: Queue overflow drops oldest
    #[test]
    fn queue_overflow_drops_oldest() {
        let max_size: usize = 3;
        let mut relay = MessageRelay::new(RelayConfig {
            max_queue_size: max_size,
            max_seen_ids: DEFAULT_MAX_SEEN_IDS,
        });

        for i in 0..4u8 {
            relay.enqueue(PEER_B, make_data_msg(PEER_A, msg_id(i), PEER_B)).expect("enqueue");
        }

        // Queue should be at max (3), oldest (msg_id 0) dropped
        assert_eq!(relay.queue_len(&PEER_B), max_size);
        let msgs = relay.dequeue(&PEER_B);
        assert_eq!(msgs[0].msg_id, msg_id(1)); // oldest is now 1
        assert_eq!(msgs[1].msg_id, msg_id(2));
        assert_eq!(msgs[2].msg_id, msg_id(3));
    }

    // T-10: FIFO ordering
    #[test]
    fn fifo_ordering() {
        let mut relay = MessageRelay::new(RelayConfig::default());

        for i in 0..5u8 {
            relay.enqueue(PEER_B, make_data_msg(PEER_A, msg_id(i), PEER_B)).expect("enqueue");
        }

        let msgs = relay.dequeue(&PEER_B);
        let expected_count: usize = 5;
        assert_eq!(msgs.len(), expected_count);
        for (i, msg) in msgs.iter().enumerate() {
            assert_eq!(msg.msg_id, msg_id(i as u8));
        }
    }

    // T-18: Dedup window bounded — evicts oldest when full
    #[test]
    fn dedup_window_bounded() {
        let max_seen: usize = 5;
        let mut relay = MessageRelay::new(RelayConfig {
            max_queue_size: DEFAULT_MAX_QUEUE_SIZE,
            max_seen_ids: max_seen,
        });

        // Enqueue 6 messages (exceeds max_seen_ids of 5)
        for i in 0..6u8 {
            relay.enqueue(PEER_B, make_data_msg(PEER_A, msg_id(i), PEER_B)).expect("enqueue");
        }

        assert_eq!(relay.seen_count(), max_seen);

        // msg_id(0) should have been evicted from seen set
        assert!(!relay.is_duplicate(&msg_id(0)));
        // msg_id(5) should still be in seen set
        assert!(relay.is_duplicate(&msg_id(5)));
    }

    // T-19: Configurable queue size
    #[test]
    fn configurable_queue_size() {
        let max_size: usize = 2;
        let mut relay = MessageRelay::new(RelayConfig {
            max_queue_size: max_size,
            max_seen_ids: DEFAULT_MAX_SEEN_IDS,
        });

        for i in 0..5u8 {
            relay.enqueue(PEER_B, make_data_msg(PEER_A, msg_id(i), PEER_B)).expect("enqueue");
        }

        assert_eq!(relay.queue_len(&PEER_B), max_size);
    }

    // Dequeue empty queue returns empty vec
    #[test]
    fn dequeue_empty_returns_empty() {
        let mut relay = MessageRelay::new(RelayConfig::default());
        let msgs = relay.dequeue(&PEER_A);
        assert!(msgs.is_empty());
    }

    // Ack non-existent message is no-op
    #[test]
    fn ack_nonexistent_is_noop() {
        let mut relay = MessageRelay::new(RelayConfig::default());
        relay.ack(&PEER_A, &msg_id(99)); // Should not panic
        let expected_total: usize = 0;
        assert_eq!(relay.total_queued(), expected_total);
    }

    // Total queued across multiple peers
    #[test]
    fn total_queued_multiple_peers() {
        let mut relay = MessageRelay::new(RelayConfig::default());
        relay.enqueue(PEER_B, make_data_msg(PEER_A, msg_id(1), PEER_B)).expect("enqueue");
        relay.enqueue(PEER_C, make_data_msg(PEER_A, msg_id(2), PEER_C)).expect("enqueue");
        relay.enqueue(PEER_B, make_data_msg(PEER_C, msg_id(3), PEER_B)).expect("enqueue");

        let expected_total: usize = 3;
        assert_eq!(relay.total_queued(), expected_total);
    }
}
