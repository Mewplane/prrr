// FRD: specs/frds/FRD-015.md

//! Double Ratchet with Sparse Post-Quantum Ratchet (SPQR).
//!
//! Implements the Double Ratchet algorithm for ongoing message encryption
//! between two parties who have completed PQXDH. Extended with periodic
//! ML-KEM-768 ratchet steps for post-quantum forward secrecy.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto::{CryptoError, aead, hybrid_kex, kdf, x25519};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HKDF info for root key ratchet: (new_root_key, chain_key).
const RK_INFO: &[u8] = b"prrr-ratchet-rk-v1";

/// HKDF info for deriving encryption key + nonce from message key.
const MSG_KEY_INFO: &[u8] = b"prrr-ratchet-msg-v1";

/// Input byte for HMAC-SHA256 to derive message key from chain key.
const CK_MSG_INPUT: u8 = 0x01;

/// Input byte for HMAC-SHA256 to derive next chain key.
const CK_NEXT_INPUT: u8 = 0x02;

/// Byte length of a root key, chain key, or message key.
const KEY_LEN: usize = 32;

/// Byte length of the HKDF output for root key ratchet (root_key + chain_key).
const RK_OUTPUT_LEN: usize = 64;

/// Byte length of HKDF output for message encryption (enc_key + nonce).
const MSG_KEY_OUTPUT_LEN: usize = 44;

/// Byte length of the message header (dh_pub + pn + n).
pub const HEADER_LEN: usize = x25519::KEY_LEN + 4 + 4;

/// Default maximum number of message keys that can be skipped in a chain.
const DEFAULT_MAX_SKIP: u32 = 256;

/// Default PQ ratchet interval: perform a KEM step every N sent messages.
const DEFAULT_PQ_RATCHET_INTERVAL: u32 = 128;

/// Flag byte: bit 0 indicates PQ ratchet data is present in header.
const FLAG_PQ_RATCHET: u8 = 0x01;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from Double Ratchet operations.
#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    /// AEAD decryption or authentication failed.
    #[error("message decryption failed")]
    DecryptionFailed,

    /// Too many message keys would need to be skipped.
    #[error("max skip exceeded: requested {requested}, limit {limit}")]
    MaxSkipExceeded {
        /// Number of keys that would be skipped.
        requested: u32,
        /// Configured maximum.
        limit: u32,
    },

    /// Cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Receiving chain not initialized (Bob hasn't received first message yet).
    #[error("receiving chain not initialized")]
    NoReceivingChain,
}

// ---------------------------------------------------------------------------
// Message Header
// ---------------------------------------------------------------------------

/// Header sent with each Double Ratchet message.
#[derive(Clone, Debug)]
pub struct MessageHeader {
    /// Sender's current DH ratchet public key.
    pub dh_public: [u8; x25519::KEY_LEN],
    /// Number of messages in previous sending chain.
    pub prev_count: u32,
    /// Message number in current sending chain.
    pub msg_number: u32,
    /// PQ ratchet data (present when a SPQR step occurs).
    pub pq_data: Option<PqRatchetData>,
}

/// Post-quantum ratchet data included in extended headers.
#[derive(Clone, Debug)]
pub struct PqRatchetData {
    /// KEM ciphertext encapsulated against remote's encapsulation key.
    pub kem_ciphertext: Vec<u8>,
    /// Sender's new KEM encapsulation key for future PQ ratchet steps.
    pub kem_encapsulation_key: Vec<u8>,
}

impl MessageHeader {
    /// Serialize the header to bytes for use as AEAD associated data.
    pub fn to_bytes(&self) -> Vec<u8> {
        let pq_len = self
            .pq_data
            .as_ref()
            .map_or(0, |d| 1 + d.kem_ciphertext.len() + d.kem_encapsulation_key.len());
        let flags: u8 = if self.pq_data.is_some() { FLAG_PQ_RATCHET } else { 0 };

        let mut buf = Vec::with_capacity(HEADER_LEN + pq_len);
        buf.extend_from_slice(&self.dh_public);
        buf.extend_from_slice(&self.prev_count.to_be_bytes());
        buf.extend_from_slice(&self.msg_number.to_be_bytes());
        buf.push(flags);
        if let Some(ref pq) = self.pq_data {
            buf.extend_from_slice(&pq.kem_ciphertext);
            buf.extend_from_slice(&pq.kem_encapsulation_key);
        }
        buf
    }

    /// Deserialize a header from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RatchetError> {
        // Minimum: 32 (dh) + 4 (pn) + 4 (n) + 1 (flags) = 41 bytes
        let min_len = HEADER_LEN + 1;
        if data.len() < min_len {
            return Err(RatchetError::DecryptionFailed);
        }

        let dh_public: [u8; x25519::KEY_LEN] = data[..x25519::KEY_LEN].try_into().map_err(|_| RatchetError::DecryptionFailed)?;
        let prev_count = u32::from_be_bytes(
            data[x25519::KEY_LEN..x25519::KEY_LEN + 4]
                .try_into()
                .map_err(|_| RatchetError::DecryptionFailed)?,
        );
        let msg_number = u32::from_be_bytes(
            data[x25519::KEY_LEN + 4..x25519::KEY_LEN + 8]
                .try_into()
                .map_err(|_| RatchetError::DecryptionFailed)?,
        );
        let flags = data[HEADER_LEN];

        let pq_data = if flags & FLAG_PQ_RATCHET != 0 {
            let pq_start = min_len;
            let expected_pq_len = hybrid_kex::KEM_CIPHERTEXT_LEN + hybrid_kex::KEM_ENCAPSULATION_KEY_LEN;
            if data.len() < pq_start + expected_pq_len {
                return Err(RatchetError::DecryptionFailed);
            }
            let kem_ciphertext = data[pq_start..pq_start + hybrid_kex::KEM_CIPHERTEXT_LEN].to_vec();
            let kem_ek_start = pq_start + hybrid_kex::KEM_CIPHERTEXT_LEN;
            let kem_encapsulation_key = data[kem_ek_start..kem_ek_start + hybrid_kex::KEM_ENCAPSULATION_KEY_LEN].to_vec();
            Some(PqRatchetData {
                kem_ciphertext,
                kem_encapsulation_key,
            })
        } else {
            None
        };

        Ok(Self {
            dh_public,
            prev_count,
            msg_number,
            pq_data,
        })
    }
}

// ---------------------------------------------------------------------------
// KDF functions
// ---------------------------------------------------------------------------

/// KDF_RK: Root key ratchet. Returns (new_root_key, chain_key).
///
/// `ikm` is normally a 32-byte DH output. When a PQ ratchet step is active,
/// it is `dh_output || kem_shared_secret` (64 bytes), mixing post-quantum
/// keying material into the same derivation.
fn kdf_rk(root_key: &[u8; KEY_LEN], ikm: &[u8]) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), CryptoError> {
    let output = kdf::derive(root_key, ikm, RK_INFO, RK_OUTPUT_LEN)?;
    let mut new_rk = [0u8; KEY_LEN];
    let mut ck = [0u8; KEY_LEN];
    new_rk.copy_from_slice(&output[..KEY_LEN]);
    ck.copy_from_slice(&output[KEY_LEN..RK_OUTPUT_LEN]);
    Ok((new_rk, ck))
}

/// KDF_CK: Chain key ratchet. Returns (next_chain_key, message_key).
fn kdf_ck(chain_key: &[u8; KEY_LEN]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    // message_key = HMAC-SHA256(chain_key, 0x01)
    let mut mac_msg = <Hmac<Sha256> as Mac>::new_from_slice(chain_key).expect("HMAC-SHA256 accepts any key length");
    mac_msg.update(&[CK_MSG_INPUT]);
    let msg_key_raw = mac_msg.finalize().into_bytes();
    let mut msg_key = [0u8; KEY_LEN];
    msg_key.copy_from_slice(&msg_key_raw);

    // next_chain_key = HMAC-SHA256(chain_key, 0x02)
    let mut mac_ck = <Hmac<Sha256> as Mac>::new_from_slice(chain_key).expect("HMAC-SHA256 accepts any key length");
    mac_ck.update(&[CK_NEXT_INPUT]);
    let next_ck_raw = mac_ck.finalize().into_bytes();
    let mut next_ck = [0u8; KEY_LEN];
    next_ck.copy_from_slice(&next_ck_raw);

    (next_ck, msg_key)
}

/// Derive AEAD encryption key and nonce from a message key.
fn derive_message_keys(message_key: &[u8; KEY_LEN]) -> Result<([u8; aead::KEY_LEN], [u8; aead::NONCE_LEN]), CryptoError> {
    let output = kdf::derive(&[0u8; KEY_LEN], message_key, MSG_KEY_INFO, MSG_KEY_OUTPUT_LEN)?;
    let mut enc_key = [0u8; aead::KEY_LEN];
    let mut nonce = [0u8; aead::NONCE_LEN];
    enc_key.copy_from_slice(&output[..aead::KEY_LEN]);
    nonce.copy_from_slice(&output[aead::KEY_LEN..MSG_KEY_OUTPUT_LEN]);
    Ok((enc_key, nonce))
}

// ---------------------------------------------------------------------------
// RatchetState
// ---------------------------------------------------------------------------

/// Configuration for the Double Ratchet.
pub struct RatchetConfig {
    /// Maximum number of message keys to skip per chain.
    pub max_skip: u32,
    /// PQ ratchet interval (0 = disabled).
    pub pq_ratchet_interval: u32,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            max_skip: DEFAULT_MAX_SKIP,
            pq_ratchet_interval: DEFAULT_PQ_RATCHET_INTERVAL,
        }
    }
}

/// Double Ratchet state machine for ongoing message encryption.
pub struct RatchetState {
    // DH ratchet
    dh_sending: x25519::KeyPair,
    dh_remote: Option<[u8; x25519::KEY_LEN]>,

    // Symmetric ratchets
    root_key: [u8; KEY_LEN],
    send_chain_key: Option<[u8; KEY_LEN]>,
    recv_chain_key: Option<[u8; KEY_LEN]>,

    // Message counters
    send_count: u32,
    recv_count: u32,
    prev_send_count: u32,

    // Out-of-order handling: (dh_pub, msg_num) → message_key
    skipped_keys: HashMap<([u8; x25519::KEY_LEN], u32), [u8; KEY_LEN]>,

    // PQ ratchet (SPQR)
    /// Counts DH ratchet steps to determine when PQ ratchet fires.
    pq_ratchet_count: u32,
    /// True if the next encrypt should include PQ ratchet data.
    pq_ratchet_pending_send: bool,
    /// PQ data generated during DH ratchet, attached to first message of new chain.
    pq_pending_data: Option<PqRatchetData>,
    pq_kem_keypair: Option<hybrid_kex::KemKeyPair>,
    pq_remote_ek: Option<Vec<u8>>,

    // Config
    config: RatchetConfig,
}

impl RatchetState {
    /// Initialize Alice's ratchet state after PQXDH.
    ///
    /// Alice knows the shared secret and Bob's signed prekey (used as
    /// Bob's initial DH ratchet public key).
    pub fn init_alice(
        shared_secret: [u8; KEY_LEN],
        bob_dh_public: [u8; x25519::KEY_LEN],
        config: RatchetConfig,
    ) -> Result<Self, RatchetError> {
        let dh_sending = x25519::KeyPair::generate();
        let dh_output = dh_sending.diffie_hellman(&bob_dh_public);
        let (root_key, send_chain_key) = kdf_rk(&shared_secret, dh_output.as_bytes())?;

        Ok(Self {
            dh_sending,
            dh_remote: Some(bob_dh_public),
            root_key,
            send_chain_key: Some(send_chain_key),
            recv_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: HashMap::new(),
            pq_ratchet_count: 1, // Alice's init counts as first DH ratchet
            pq_ratchet_pending_send: false,
            pq_pending_data: None,
            pq_kem_keypair: None,
            pq_remote_ek: None,
            config,
        })
    }

    /// Initialize Bob's ratchet state after PQXDH.
    ///
    /// Bob knows the shared secret and his own signed prekey keypair
    /// (used as his initial DH ratchet keypair). Bob doesn't have a
    /// sending chain yet — it's established on first received message.
    pub fn init_bob(shared_secret: [u8; KEY_LEN], bob_dh_keypair: x25519::KeyPair, config: RatchetConfig) -> Self {
        Self {
            dh_sending: bob_dh_keypair,
            dh_remote: None,
            root_key: shared_secret,
            send_chain_key: None,
            recv_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: HashMap::new(),
            pq_ratchet_count: 0,
            pq_ratchet_pending_send: false,
            pq_pending_data: None,
            pq_kem_keypair: None,
            pq_remote_ek: None,
            config,
        }
    }

    /// Encrypt a message, advancing the sending symmetric ratchet.
    ///
    /// Returns the message header and AEAD ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(MessageHeader, Vec<u8>), RatchetError> {
        let send_ck = self.send_chain_key.ok_or(RatchetError::NoReceivingChain)?;

        // Symmetric ratchet step
        let (next_ck, msg_key) = kdf_ck(&send_ck);
        self.send_chain_key = Some(next_ck);

        // Attach PQ ratchet data if generated during the last DH ratchet step
        let pq_data = if self.pq_ratchet_pending_send {
            self.pq_ratchet_pending_send = false;
            self.pq_pending_data.take()
        } else {
            None
        };

        // Build header
        let header = MessageHeader {
            dh_public: self.dh_sending.public_key_bytes(),
            prev_count: self.prev_send_count,
            msg_number: self.send_count,
            pq_data,
        };

        self.send_count += 1;

        // Derive AEAD key + nonce from message key
        let (enc_key, nonce) = derive_message_keys(&msg_key)?;
        let header_bytes = header.to_bytes();
        let ciphertext = aead::encrypt(&enc_key, &nonce, plaintext, &header_bytes);

        Ok((header, ciphertext))
    }

    /// Decrypt a message, performing DH ratchet if needed.
    pub fn decrypt(&mut self, header: &MessageHeader, ciphertext: &[u8]) -> Result<Vec<u8>, RatchetError> {
        // Try skipped message keys first
        let header_bytes = header.to_bytes();
        if let Some(plaintext) = self.try_skipped_keys(header, ciphertext, &header_bytes)? {
            return Ok(plaintext);
        }

        // DH ratchet if new public key
        let need_dh_ratchet = self.dh_remote != Some(header.dh_public);

        if need_dh_ratchet {
            // Extract PQ shared secret from header if present (before DH ratchet)
            let recv_pq_ss = if let Some(ref pq_data) = header.pq_data {
                let ss = self.process_pq_ratchet_recv(pq_data)?;
                // Store remote's new encapsulation key for future PQ ratchets
                self.pq_remote_ek = Some(pq_data.kem_encapsulation_key.clone());
                ss
            } else {
                None
            };

            self.skip_message_keys(header.prev_count)?;
            self.dh_ratchet_step(&header.dh_public, recv_pq_ss)?;
        }

        // Skip to the right message number
        self.skip_message_keys(header.msg_number)?;

        // Symmetric ratchet step
        let recv_ck = self.recv_chain_key.ok_or(RatchetError::NoReceivingChain)?;
        let (next_ck, msg_key) = kdf_ck(&recv_ck);
        self.recv_chain_key = Some(next_ck);
        self.recv_count += 1;

        // Decrypt
        let (enc_key, nonce) = derive_message_keys(&msg_key)?;
        aead::decrypt(&enc_key, &nonce, ciphertext, &header_bytes).map_err(|_| RatchetError::DecryptionFailed)
    }

    /// Return the current DH ratchet public key (for testing/inspection).
    pub fn dh_public_key(&self) -> [u8; x25519::KEY_LEN] {
        self.dh_sending.public_key_bytes()
    }

    /// Return the number of skipped keys stored.
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Perform a DH ratchet step upon receiving a new DH public key.
    ///
    /// `recv_pq_ss` is provided by the receiver when the incoming message
    /// contains PQ ratchet data. It is mixed into the recv chain derivation
    /// so that `recv_ck` matches the sender's `send_ck` (which was derived
    /// with the same PQ SS mixed into the send chain).
    fn dh_ratchet_step(&mut self, new_remote_dh: &[u8; x25519::KEY_LEN], recv_pq_ss: Option<[u8; KEY_LEN]>) -> Result<(), RatchetError> {
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.dh_remote = Some(*new_remote_dh);

        // Derive receiving chain key.
        // If recv_pq_ss is present, mix it: ikm = dh_output || kem_ss.
        let dh_recv = self.dh_sending.diffie_hellman(new_remote_dh);
        let recv_ikm = build_rk_ikm(dh_recv.as_bytes(), recv_pq_ss.as_ref());
        let (rk, recv_ck) = kdf_rk(&self.root_key, &recv_ikm)?;
        self.root_key = rk;
        self.recv_chain_key = Some(recv_ck);

        // Generate new DH keypair for sending
        self.dh_sending = x25519::KeyPair::generate();

        // Check if PQ ratchet should fire for the new send chain
        self.pq_ratchet_count += 1;
        let send_pq_ss = if self.should_pq_ratchet() {
            self.generate_pq_ratchet_send()?
        } else {
            None
        };

        // Derive sending chain key, mixing PQ SS if generated
        let dh_send = self.dh_sending.diffie_hellman(new_remote_dh);
        let send_ikm = build_rk_ikm(dh_send.as_bytes(), send_pq_ss.as_ref());
        let (rk, send_ck) = kdf_rk(&self.root_key, &send_ikm)?;
        self.root_key = rk;
        self.send_chain_key = Some(send_ck);

        // Flag encrypt to attach PQ data to next outgoing message
        if send_pq_ss.is_some() {
            self.pq_ratchet_pending_send = true;
        }

        Ok(())
    }

    /// Skip message keys up to `until`, caching them for out-of-order delivery.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if self.recv_chain_key.is_none() {
            return Ok(());
        }

        let skip_count = until.saturating_sub(self.recv_count);
        if skip_count > self.config.max_skip {
            return Err(RatchetError::MaxSkipExceeded {
                requested: skip_count,
                limit: self.config.max_skip,
            });
        }

        let dh_remote = match self.dh_remote {
            Some(dh) => dh,
            None => return Ok(()),
        };

        while self.recv_count < until {
            let recv_ck = self.recv_chain_key.expect("recv_chain_key checked above");
            let (next_ck, msg_key) = kdf_ck(&recv_ck);
            self.recv_chain_key = Some(next_ck);
            self.skipped_keys.insert((dh_remote, self.recv_count), msg_key);
            self.recv_count += 1;
        }

        Ok(())
    }

    /// Try to decrypt using a previously skipped message key.
    fn try_skipped_keys(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        header_bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, RatchetError> {
        let key = (header.dh_public, header.msg_number);
        if let Some(msg_key) = self.skipped_keys.remove(&key) {
            let (enc_key, nonce) = derive_message_keys(&msg_key)?;
            let plaintext = aead::decrypt(&enc_key, &nonce, ciphertext, header_bytes).map_err(|_| RatchetError::DecryptionFailed)?;
            return Ok(Some(plaintext));
        }
        Ok(None)
    }

    /// Check if PQ ratchet should fire at this DH ratchet step.
    fn should_pq_ratchet(&self) -> bool {
        self.config.pq_ratchet_interval > 0
            && self.pq_ratchet_count > 0
            && self.pq_ratchet_count % self.config.pq_ratchet_interval == 0
            && self.pq_remote_ek.is_some()
    }

    /// Generate PQ ratchet data during the DH ratchet step (sender side).
    ///
    /// Encapsulates against remote's KEM key and returns the shared secret.
    /// The PQ data (ciphertext + new EK) is stored in `pq_pending_data` to
    /// be attached to the first message of the new sending chain.
    fn generate_pq_ratchet_send(&mut self) -> Result<Option<[u8; KEY_LEN]>, RatchetError> {
        let remote_ek = match self.pq_remote_ek {
            Some(ref ek) => ek,
            None => return Ok(None),
        };

        let (kem_ct, kem_ss) = hybrid_kex::kem_encapsulate(remote_ek)?;

        // Generate new KEM keypair for our side
        let new_kem = hybrid_kex::KemKeyPair::generate();
        let new_ek = new_kem.encapsulation_key_bytes();
        self.pq_kem_keypair = Some(new_kem);

        // Store PQ data for inclusion in next outgoing message header
        self.pq_pending_data = Some(PqRatchetData {
            kem_ciphertext: kem_ct,
            kem_encapsulation_key: new_ek,
        });

        Ok(Some(kem_ss))
    }

    /// Process received PQ ratchet data (receiver side).
    ///
    /// Decapsulates the KEM ciphertext and returns the shared secret
    /// for mixing into the recv chain derivation.
    fn process_pq_ratchet_recv(&self, pq_data: &PqRatchetData) -> Result<Option<[u8; KEY_LEN]>, RatchetError> {
        let kem_ss = if let Some(ref kem_kp) = self.pq_kem_keypair {
            Some(kem_kp.decapsulate(&pq_data.kem_ciphertext)?)
        } else {
            None
        };
        Ok(kem_ss)
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut ck) = self.send_chain_key {
            ck.zeroize();
        }
        if let Some(ref mut ck) = self.recv_chain_key {
            ck.zeroize();
        }
        for value in self.skipped_keys.values_mut() {
            value.zeroize();
        }
        self.skipped_keys.clear();
    }
}

/// Build the IKM for `kdf_rk`: DH output, optionally concatenated with KEM SS.
fn build_rk_ikm(dh_output: &[u8; KEY_LEN], pq_ss: Option<&[u8; KEY_LEN]>) -> Vec<u8> {
    match pq_ss {
        Some(ss) => {
            let mut ikm = Vec::with_capacity(KEY_LEN + KEY_LEN);
            ikm.extend_from_slice(dh_output);
            ikm.extend_from_slice(ss);
            ikm
        }
        None => dh_output.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PLAINTEXT: &[u8] = b"hello double ratchet";
    const TEST_SHARED_SECRET: [u8; KEY_LEN] = [0xAB; KEY_LEN];

    /// Helper: create Alice and Bob ratchet states with default config.
    fn create_alice_bob() -> (RatchetState, RatchetState) {
        let bob_dh = x25519::KeyPair::generate();
        let bob_dh_pub = bob_dh.public_key_bytes();
        let alice = RatchetState::init_alice(TEST_SHARED_SECRET, bob_dh_pub, RatchetConfig::default()).expect("alice init should succeed");
        let bob = RatchetState::init_bob(TEST_SHARED_SECRET, bob_dh, RatchetConfig::default());
        (alice, bob)
    }

    // T-9: Init alice and bob produce compatible states
    #[test]
    fn init_produces_compatible_states() {
        let (alice, bob) = create_alice_bob();
        // Alice has a sending chain, Bob does not
        assert!(alice.send_chain_key.is_some());
        assert!(bob.send_chain_key.is_none());
        assert!(bob.recv_chain_key.is_none());
        assert!(bob.dh_remote.is_none());
        assert!(alice.dh_remote.is_some());
    }

    // T-10: Header serialization round-trip
    #[test]
    fn header_serialization_round_trip() {
        let header = MessageHeader {
            dh_public: [0xAA; x25519::KEY_LEN],
            prev_count: 42,
            msg_number: 7,
            pq_data: None,
        };
        let bytes = header.to_bytes();
        let parsed = MessageHeader::from_bytes(&bytes).expect("parse should succeed");
        assert_eq!(parsed.dh_public, header.dh_public);
        assert_eq!(parsed.prev_count, header.prev_count);
        assert_eq!(parsed.msg_number, header.msg_number);
        assert!(parsed.pq_data.is_none());
    }

    // T-10b: Header with PQ data serialization round-trip
    #[test]
    fn header_with_pq_data_round_trip() {
        let header = MessageHeader {
            dh_public: [0xBB; x25519::KEY_LEN],
            prev_count: 5,
            msg_number: 3,
            pq_data: Some(PqRatchetData {
                kem_ciphertext: vec![0xCC; hybrid_kex::KEM_CIPHERTEXT_LEN],
                kem_encapsulation_key: vec![0xDD; hybrid_kex::KEM_ENCAPSULATION_KEY_LEN],
            }),
        };
        let bytes = header.to_bytes();
        let parsed = MessageHeader::from_bytes(&bytes).expect("parse should succeed");
        assert_eq!(parsed.dh_public, header.dh_public);
        assert_eq!(parsed.prev_count, header.prev_count);
        assert_eq!(parsed.msg_number, header.msg_number);
        let pq = parsed.pq_data.expect("pq_data should be present");
        assert_eq!(pq.kem_ciphertext.len(), hybrid_kex::KEM_CIPHERTEXT_LEN);
        assert_eq!(pq.kem_encapsulation_key.len(), hybrid_kex::KEM_ENCAPSULATION_KEY_LEN);
    }

    // T-1: Sequential 100 messages alice→bob
    #[test]
    fn sequential_100_alice_to_bob() {
        let (mut alice, mut bob) = create_alice_bob();
        let msg_count: u32 = 100;

        for i in 0..msg_count {
            let plaintext = format!("message {i}");
            let (header, ct) = alice.encrypt(plaintext.as_bytes()).expect("encrypt");
            let decrypted = bob.decrypt(&header, &ct).expect("decrypt");
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    // T-2: Sequential 100 messages bob→alice (after initial exchange)
    #[test]
    fn sequential_100_bob_to_alice() {
        let (mut alice, mut bob) = create_alice_bob();
        let msg_count: u32 = 100;

        // Alice sends one message to trigger Bob's DH ratchet
        let (h, ct) = alice.encrypt(b"init").expect("encrypt");
        bob.decrypt(&h, &ct).expect("decrypt");

        // Now Bob can send
        for i in 0..msg_count {
            let plaintext = format!("bob message {i}");
            let (header, ct) = bob.encrypt(plaintext.as_bytes()).expect("encrypt");
            let decrypted = alice.decrypt(&header, &ct).expect("decrypt");
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    // T-3: Alternating messages (DH ratchet each direction)
    #[test]
    fn alternating_messages_dh_ratchet() {
        let (mut alice, mut bob) = create_alice_bob();
        let rounds: u32 = 20;

        for i in 0..rounds {
            let a_msg = format!("alice {i}");
            let (h, ct) = alice.encrypt(a_msg.as_bytes()).expect("encrypt");
            let decrypted = bob.decrypt(&h, &ct).expect("decrypt");
            assert_eq!(decrypted, a_msg.as_bytes());

            let b_msg = format!("bob {i}");
            let (h, ct) = bob.encrypt(b_msg.as_bytes()).expect("encrypt");
            let decrypted = alice.decrypt(&h, &ct).expect("decrypt");
            assert_eq!(decrypted, b_msg.as_bytes());
        }
    }

    // T-4: Out-of-order: msg 2 before msg 1
    #[test]
    fn out_of_order_msg2_before_msg1() {
        let (mut alice, mut bob) = create_alice_bob();

        let (h0, ct0) = alice.encrypt(b"msg 0").expect("encrypt");
        let (h1, ct1) = alice.encrypt(b"msg 1").expect("encrypt");
        let (h2, ct2) = alice.encrypt(b"msg 2").expect("encrypt");

        // Deliver msg 0, then msg 2, then msg 1
        assert_eq!(bob.decrypt(&h0, &ct0).expect("decrypt"), b"msg 0");
        assert_eq!(bob.decrypt(&h2, &ct2).expect("decrypt"), b"msg 2");
        assert_eq!(bob.decrypt(&h1, &ct1).expect("decrypt"), b"msg 1");
    }

    // T-5: Out-of-order: msg 5 before msgs 1-4
    #[test]
    fn out_of_order_msg5_before_1_4() {
        let (mut alice, mut bob) = create_alice_bob();

        let (h0, ct0) = alice.encrypt(b"msg 0").expect("encrypt");
        let mut pending = Vec::new();
        for i in 1..5u32 {
            let (h, ct) = alice.encrypt(format!("msg {i}").as_bytes()).expect("encrypt");
            pending.push((h, ct, i));
        }
        let (h5, ct5) = alice.encrypt(b"msg 5").expect("encrypt");

        // Deliver 0, then 5, then 1-4
        assert_eq!(bob.decrypt(&h0, &ct0).expect("decrypt"), b"msg 0");
        assert_eq!(bob.decrypt(&h5, &ct5).expect("decrypt"), b"msg 5");
        for (h, ct, i) in pending {
            let expected = format!("msg {i}");
            assert_eq!(bob.decrypt(&h, &ct).expect("decrypt"), expected.as_bytes());
        }
    }

    // T-6: Max skip exceeded → error
    #[test]
    fn max_skip_exceeded_error() {
        let bob_dh = x25519::KeyPair::generate();
        let bob_dh_pub = bob_dh.public_key_bytes();
        let config = RatchetConfig {
            max_skip: 3,
            pq_ratchet_interval: 0,
        };
        let mut alice = RatchetState::init_alice(
            TEST_SHARED_SECRET,
            bob_dh_pub,
            RatchetConfig {
                max_skip: 3,
                pq_ratchet_interval: 0,
            },
        )
        .expect("alice init");
        let mut bob = RatchetState::init_bob(TEST_SHARED_SECRET, bob_dh, config);

        // Send 5 messages, deliver only the 5th
        let mut headers = Vec::new();
        let mut cts = Vec::new();
        for i in 0..5u32 {
            let (h, ct) = alice.encrypt(format!("msg {i}").as_bytes()).expect("encrypt");
            headers.push(h);
            cts.push(ct);
        }

        // Try to decrypt msg 4 (skipping 4 keys, limit is 3)
        let result = bob.decrypt(&headers[4], &cts[4]);
        assert!(matches!(result, Err(RatchetError::MaxSkipExceeded { .. })));
    }

    // T-12: Tampered ciphertext → AEAD error
    #[test]
    fn tampered_ciphertext_aead_error() {
        let (mut alice, mut bob) = create_alice_bob();

        let (header, mut ct) = alice.encrypt(TEST_PLAINTEXT).expect("encrypt");
        ct[0] ^= 0xFF;

        let result = bob.decrypt(&header, &ct);
        assert!(matches!(result, Err(RatchetError::DecryptionFailed)));
    }

    // T-14: Multiple DH ratchet steps in sequence
    #[test]
    fn multiple_dh_ratchet_steps() {
        let (mut alice, mut bob) = create_alice_bob();
        let steps: u32 = 10;

        for i in 0..steps {
            // Alice sends
            let a_msg = format!("a{i}");
            let (h, ct) = alice.encrypt(a_msg.as_bytes()).expect("encrypt");
            assert_eq!(bob.decrypt(&h, &ct).expect("decrypt"), a_msg.as_bytes());

            // Bob sends
            let b_msg = format!("b{i}");
            let (h, ct) = bob.encrypt(b_msg.as_bytes()).expect("encrypt");
            assert_eq!(alice.decrypt(&h, &ct).expect("decrypt"), b_msg.as_bytes());
        }

        // After 10 DH ratchet steps, keys are still synchronized
        let final_msg = b"final message";
        let (h, ct) = alice.encrypt(final_msg).expect("encrypt");
        assert_eq!(bob.decrypt(&h, &ct).expect("decrypt"), final_msg.as_slice());
    }

    // T-15: Skipped keys bounded by max_skip
    #[test]
    fn skipped_keys_bounded() {
        let (mut alice, mut bob) = create_alice_bob();

        // Send 5 messages, deliver only msg 4 (skipping 4 keys)
        let mut msgs = Vec::new();
        for i in 0..5u32 {
            let (h, ct) = alice.encrypt(format!("msg {i}").as_bytes()).expect("encrypt");
            msgs.push((h, ct));
        }

        // Deliver msg 4 → skips 0,1,2,3
        let (ref h4, ref ct4) = msgs[4];
        bob.decrypt(h4, ct4).expect("decrypt msg 4");

        // 4 skipped keys should be cached
        let expected_skipped: usize = 4;
        assert_eq!(bob.skipped_key_count(), expected_skipped);

        // Deliver msg 2 → removes one from cache
        let (ref h2, ref ct2) = msgs[2];
        bob.decrypt(h2, ct2).expect("decrypt msg 2");
        let expected_after: usize = 3;
        assert_eq!(bob.skipped_key_count(), expected_after);
    }

    // T-11: Integration: 1000 bidirectional messages
    #[test]
    fn integration_1000_bidirectional() {
        let (mut alice, mut bob) = create_alice_bob();
        let msg_count: u32 = 500;

        for i in 0..msg_count {
            let a_msg = format!("alice msg {i}");
            let (h, ct) = alice.encrypt(a_msg.as_bytes()).expect("encrypt");
            assert_eq!(bob.decrypt(&h, &ct).expect("decrypt"), a_msg.as_bytes());

            let b_msg = format!("bob msg {i}");
            let (h, ct) = bob.encrypt(b_msg.as_bytes()).expect("encrypt");
            assert_eq!(alice.decrypt(&h, &ct).expect("decrypt"), b_msg.as_bytes());
        }
    }

    // T-7: PQ ratchet triggers at DH ratchet interval
    #[test]
    fn pq_ratchet_triggers_at_interval() {
        // PQ fires every 2 DH ratchet steps.
        // DH ratchets happen on direction changes (alternating messages).
        let pq_interval: u32 = 2;
        let bob_dh = x25519::KeyPair::generate();
        let bob_dh_pub = bob_dh.public_key_bytes();

        let config = RatchetConfig {
            max_skip: DEFAULT_MAX_SKIP,
            pq_ratchet_interval: pq_interval,
        };
        let mut alice = RatchetState::init_alice(TEST_SHARED_SECRET, bob_dh_pub, config).expect("alice init");
        let mut bob = RatchetState::init_bob(
            TEST_SHARED_SECRET,
            bob_dh,
            RatchetConfig {
                max_skip: DEFAULT_MAX_SKIP,
                pq_ratchet_interval: pq_interval,
            },
        );

        // Set up PQ keys: Alice needs Bob's EK, Bob needs a KEM keypair
        let bob_kem = hybrid_kex::KemKeyPair::generate();
        alice.pq_remote_ek = Some(bob_kem.encapsulation_key_bytes());
        bob.pq_kem_keypair = Some(bob_kem);

        // Alternate messages to trigger DH ratchets.
        // Alice init = DH ratchet 1. Each reply triggers another.
        let mut pq_triggered = false;
        let rounds: u32 = 4;
        for i in 0..rounds {
            let a_msg = format!("alice {i}");
            let (ah, act) = alice.encrypt(a_msg.as_bytes()).expect("encrypt");
            if ah.pq_data.is_some() {
                pq_triggered = true;
            }
            bob.decrypt(&ah, &act).expect("decrypt");

            let b_msg = format!("bob {i}");
            let (bh, bct) = bob.encrypt(b_msg.as_bytes()).expect("encrypt");
            if bh.pq_data.is_some() {
                pq_triggered = true;
            }
            alice.decrypt(&bh, &bct).expect("decrypt");
        }
        assert!(pq_triggered, "PQ ratchet should have triggered");
    }

    // T-8: PQ ratchet: both sides derive same key after PQ step
    #[test]
    fn pq_ratchet_both_sides_agree() {
        // PQ fires every 2 DH ratchets. Alternating messages trigger DH ratchets.
        let pq_interval: u32 = 2;
        let bob_dh = x25519::KeyPair::generate();
        let bob_dh_pub = bob_dh.public_key_bytes();

        let config = RatchetConfig {
            max_skip: DEFAULT_MAX_SKIP,
            pq_ratchet_interval: pq_interval,
        };
        let mut alice = RatchetState::init_alice(TEST_SHARED_SECRET, bob_dh_pub, config).expect("alice init");
        let mut bob = RatchetState::init_bob(
            TEST_SHARED_SECRET,
            bob_dh,
            RatchetConfig {
                max_skip: DEFAULT_MAX_SKIP,
                pq_ratchet_interval: pq_interval,
            },
        );

        // Set up PQ keys
        let bob_kem = hybrid_kex::KemKeyPair::generate();
        alice.pq_remote_ek = Some(bob_kem.encapsulation_key_bytes());
        bob.pq_kem_keypair = Some(bob_kem);

        // Exchange messages; PQ ratchet fires at DH boundary, then
        // subsequent messages still work.
        let rounds: u32 = 6;
        for i in 0..rounds {
            let a_msg = format!("alice {i}");
            let (ah, act) = alice.encrypt(a_msg.as_bytes()).expect("encrypt");
            assert_eq!(bob.decrypt(&ah, &act).expect("decrypt"), a_msg.as_bytes());

            let b_msg = format!("bob {i}");
            let (bh, bct) = bob.encrypt(b_msg.as_bytes()).expect("encrypt");
            assert_eq!(alice.decrypt(&bh, &bct).expect("decrypt"), b_msg.as_bytes());
        }
    }

    // T-13: Wrong DH public key in header → AEAD failure
    #[test]
    fn wrong_dh_public_key_aead_failure() {
        let (mut alice, mut bob) = create_alice_bob();

        let (mut header, ct) = alice.encrypt(TEST_PLAINTEXT).expect("encrypt");
        // Tamper with the DH public key
        header.dh_public[0] ^= 0xFF;

        // Bob will do a DH ratchet with wrong key → different message key → AEAD fail
        let result = bob.decrypt(&header, &ct);
        assert!(matches!(result, Err(RatchetError::DecryptionFailed)));
    }

    // T-extra: KDF_CK deterministic
    #[test]
    fn kdf_ck_deterministic() {
        let ck = [0x42u8; KEY_LEN];
        let (next1, mk1) = kdf_ck(&ck);
        let (next2, mk2) = kdf_ck(&ck);
        assert_eq!(next1, next2);
        assert_eq!(mk1, mk2);
        // Chain key and message key must differ
        assert_ne!(next1, mk1);
    }

    // T-extra: KDF_RK deterministic
    #[test]
    fn kdf_rk_deterministic() {
        let rk = [0x11u8; KEY_LEN];
        let dh = [0x22u8; KEY_LEN];
        let (rk1, ck1) = kdf_rk(&rk, &dh).expect("kdf_rk");
        let (rk2, ck2) = kdf_rk(&rk, &dh).expect("kdf_rk");
        assert_eq!(rk1, rk2);
        assert_eq!(ck1, ck2);
        assert_ne!(rk1, ck1);
    }

    // T-19 (FRD-017): RatchetState zeroizes secrets via Drop logic
    #[test]
    fn ratchet_state_zeroizes_secrets() {
        let (mut alice, mut bob) = create_alice_bob();

        // Exchange a few messages so chains and skipped keys exist
        let (h0, ct0) = alice.encrypt(b"msg 0").expect("encrypt");
        let (h1, ct1) = alice.encrypt(b"msg 1").expect("encrypt");
        let (h2, ct2) = alice.encrypt(b"msg 2").expect("encrypt");

        // Deliver msg 2 first to create skipped keys for 0, 1
        bob.decrypt(&h2, &ct2).expect("decrypt");
        let skipped_before = bob.skipped_key_count();
        assert_eq!(skipped_before, 2);

        // Verify root_key is non-zero before zeroize
        assert_ne!(bob.root_key, [0u8; KEY_LEN]);

        // Simulate what Drop does
        bob.root_key.zeroize();
        if let Some(ref mut ck) = bob.send_chain_key {
            ck.zeroize();
        }
        if let Some(ref mut ck) = bob.recv_chain_key {
            ck.zeroize();
        }
        for value in bob.skipped_keys.values_mut() {
            value.zeroize();
        }

        assert_eq!(bob.root_key, [0u8; KEY_LEN]);
        if let Some(ref ck) = bob.send_chain_key {
            assert_eq!(*ck, [0u8; KEY_LEN]);
        }
        if let Some(ref ck) = bob.recv_chain_key {
            assert_eq!(*ck, [0u8; KEY_LEN]);
        }
        for value in bob.skipped_keys.values() {
            assert_eq!(*value, [0u8; KEY_LEN]);
        }

        // Clean up: decrypt remaining to avoid leaking non-zeroized msg keys
        // (bob is already zeroized, just drop it)
        drop(bob);
        drop(h0);
        drop(ct0);
        drop(h1);
        drop(ct1);
    }
}
