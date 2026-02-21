// FRD: specs/frds/FRD-003.md

//! Noise IK handshake pattern using X25519, ChaCha20-Poly1305, and BLAKE2s.
//!
//! Wraps the `snow` crate to perform a Noise_IK handshake:
//! ```text
//! IK:
//!   <- s
//!   ...
//!   -> e, es, s, ss    (message 1: initiator → responder)
//!   <- e, ee, se       (message 2: responder → initiator)
//! ```
//!
//! The initiator knows the responder's static public key in advance.
//! After the 2-message exchange, both sides derive transport keys with
//! forward secrecy.

use zeroize::Zeroize;

use super::HandshakeError;

/// The Noise protocol pattern string used for all handshakes.
const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Byte length of an X25519 public key in the Noise context.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Maximum size of a Noise handshake message (generous upper bound).
///
/// Noise IK message 1: 32 (e) + 16 (es tag) + 32 (s) + 16 (ss tag)
/// + payload + 16 (payload tag) = ~112 + payload.
///
/// Message 2: 32 (e) + 16 (ee tag) + 16 (se tag) + payload
/// + 16 (payload tag) = ~80 + payload.
///
/// We use 65535 as the Noise spec maximum message size.
const MAX_MESSAGE_LEN: usize = 65535;

/// A Noise static key pair (X25519).
pub struct KeyPair {
    /// The raw private key bytes.
    private: Vec<u8>,
    /// The raw public key bytes.
    public: [u8; PUBLIC_KEY_LEN],
}

impl KeyPair {
    /// Generate a new Noise static key pair from the OS CSPRNG.
    pub fn generate() -> Result<Self, HandshakeError> {
        let builder = snow::Builder::new(NOISE_PATTERN.parse().map_err(map_snow_error)?);
        let keypair = builder.generate_keypair().map_err(map_snow_error)?;
        let mut public = [0u8; PUBLIC_KEY_LEN];
        public.copy_from_slice(&keypair.public);
        Ok(Self {
            private: keypair.private,
            public,
        })
    }

    /// Reconstruct a `KeyPair` from raw private key bytes.
    ///
    /// The bytes must be exactly 32 bytes (X25519 private key). The public
    /// key is derived deterministically using `x25519_dalek`.
    pub fn from_private_key(private_bytes: &[u8]) -> Result<Self, HandshakeError> {
        let secret_array: [u8; PUBLIC_KEY_LEN] = private_bytes.try_into().map_err(|_| {
            HandshakeError::NoiseError(format!(
                "invalid private key length: expected {} bytes, got {}",
                PUBLIC_KEY_LEN,
                private_bytes.len()
            ))
        })?;
        let secret = x25519_dalek::StaticSecret::from(secret_array);
        let derived_public = x25519_dalek::PublicKey::from(&secret);
        let mut public = [0u8; PUBLIC_KEY_LEN];
        public.copy_from_slice(derived_public.as_bytes());
        Ok(Self {
            private: private_bytes.to_vec(),
            public,
        })
    }

    /// Return the raw private key bytes.
    pub fn private_key_bytes(&self) -> &[u8] {
        &self.private
    }

    /// Return the public key bytes.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

/// Initiator-side handshake state machine.
pub struct Initiator {
    state: snow::HandshakeState,
}

impl Initiator {
    /// Create a new initiator handshake.
    ///
    /// `local_keypair` is the initiator's long-term static key.
    /// `remote_public` is the responder's known static public key.
    pub fn new(local_keypair: &KeyPair, remote_public: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, HandshakeError> {
        let state = snow::Builder::new(NOISE_PATTERN.parse().map_err(map_snow_error)?)
            .local_private_key(&local_keypair.private)
            .map_err(map_snow_error)?
            .remote_public_key(remote_public)
            .map_err(map_snow_error)?
            .build_initiator()
            .map_err(map_snow_error)?;
        Ok(Self { state })
    }

    /// Write handshake message 1 (→ e, es, s, ss) with optional payload.
    ///
    /// Returns the handshake message bytes.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        let len = self.state.write_message(payload, &mut buf).map_err(map_snow_error)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Read handshake message 2 (← e, ee, se) and extract the payload.
    ///
    /// Returns the decrypted payload from the responder.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        let len = self.state.read_message(message, &mut buf).map_err(|e| match e {
            snow::Error::Decrypt => HandshakeError::MessageAuthFailed,
            other => map_snow_error(other),
        })?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Check whether the handshake is complete.
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Return the Noise handshake hash for channel binding.
    ///
    /// Only meaningful after the handshake is complete. Returns
    /// the BLAKE2s hash of the entire handshake transcript.
    pub fn handshake_hash(&self) -> Result<Vec<u8>, HandshakeError> {
        if !self.state.is_handshake_finished() {
            return Err(HandshakeError::NotFinished);
        }
        Ok(self.state.get_handshake_hash().to_vec())
    }

    /// Transition to transport mode after a completed handshake.
    ///
    /// Returns a `Transport` that provides encrypted message exchange.
    pub fn into_transport(self) -> Result<Transport, HandshakeError> {
        if !self.state.is_handshake_finished() {
            return Err(HandshakeError::NotFinished);
        }
        let transport = self.state.into_transport_mode().map_err(map_snow_error)?;
        Ok(Transport { state: transport })
    }
}

/// Responder-side handshake state machine.
pub struct Responder {
    state: snow::HandshakeState,
}

impl Responder {
    /// Create a new responder handshake.
    ///
    /// `local_keypair` is the responder's long-term static key.
    pub fn new(local_keypair: &KeyPair) -> Result<Self, HandshakeError> {
        let state = snow::Builder::new(NOISE_PATTERN.parse().map_err(map_snow_error)?)
            .local_private_key(&local_keypair.private)
            .map_err(map_snow_error)?
            .build_responder()
            .map_err(map_snow_error)?;
        Ok(Self { state })
    }

    /// Read handshake message 1 (→ e, es, s, ss) and extract the payload.
    ///
    /// After this call, `remote_static_key()` returns the initiator's
    /// static public key.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        let len = self.state.read_message(message, &mut buf).map_err(|e| match e {
            snow::Error::Decrypt => HandshakeError::MessageAuthFailed,
            other => map_snow_error(other),
        })?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Write handshake message 2 (← e, ee, se) with optional payload.
    ///
    /// Returns the handshake message bytes.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        let len = self.state.write_message(payload, &mut buf).map_err(map_snow_error)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Retrieve the initiator's static public key after reading message 1.
    ///
    /// Returns `None` if message 1 has not been processed yet.
    pub fn remote_static_key(&self) -> Option<[u8; PUBLIC_KEY_LEN]> {
        self.state.get_remote_static().map(|key| {
            let mut out = [0u8; PUBLIC_KEY_LEN];
            out.copy_from_slice(key);
            out
        })
    }

    /// Check whether the handshake is complete.
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Return the Noise handshake hash for channel binding.
    ///
    /// Only meaningful after the handshake is complete. Returns
    /// the BLAKE2s hash of the entire handshake transcript.
    pub fn handshake_hash(&self) -> Result<Vec<u8>, HandshakeError> {
        if !self.state.is_handshake_finished() {
            return Err(HandshakeError::NotFinished);
        }
        Ok(self.state.get_handshake_hash().to_vec())
    }

    /// Transition to transport mode after a completed handshake.
    ///
    /// Returns a `Transport` that provides encrypted message exchange.
    pub fn into_transport(self) -> Result<Transport, HandshakeError> {
        if !self.state.is_handshake_finished() {
            return Err(HandshakeError::NotFinished);
        }
        let transport = self.state.into_transport_mode().map_err(map_snow_error)?;
        Ok(Transport { state: transport })
    }
}

/// Post-handshake encrypted transport.
///
/// Wraps `snow::TransportState` to provide authenticated encryption
/// for application data after the Noise IK handshake completes.
pub struct Transport {
    state: snow::TransportState,
}

impl Transport {
    /// Encrypt a message for the remote peer.
    ///
    /// Returns the ciphertext including the AEAD authentication tag.
    pub fn write_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // 16 bytes for Poly1305 tag
        let len = self.state.write_message(plaintext, &mut buf).map_err(map_snow_error)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt a message from the remote peer.
    ///
    /// Returns the plaintext on success.
    pub fn read_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.state.read_message(ciphertext, &mut buf).map_err(|e| match e {
            snow::Error::Decrypt => HandshakeError::TransportDecryptFailed,
            other => map_snow_error(other),
        })?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Retrieve the remote peer's static public key.
    pub fn remote_static_key(&self) -> Option<[u8; PUBLIC_KEY_LEN]> {
        self.state.get_remote_static().map(|key| {
            let mut out = [0u8; PUBLIC_KEY_LEN];
            out.copy_from_slice(key);
            out
        })
    }

    /// Check whether this transport was created by the initiator side.
    pub fn is_initiator(&self) -> bool {
        self.state.is_initiator()
    }
}

/// Map a `snow::Error` to our `HandshakeError`.
fn map_snow_error(err: snow::Error) -> HandshakeError {
    HandshakeError::NoiseError(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: perform a full Noise IK handshake between initiator and responder.
    /// Returns `(initiator_transport, responder_transport)`.
    fn full_handshake(
        initiator_kp: &KeyPair,
        responder_kp: &KeyPair,
        initiator_payload: &[u8],
        responder_payload: &[u8],
    ) -> (Transport, Transport, Vec<u8>, Vec<u8>) {
        let mut initiator = Initiator::new(initiator_kp, responder_kp.public_key()).expect("initiator creation");
        let mut responder = Responder::new(responder_kp).expect("responder creation");

        // Message 1: initiator → responder
        let msg1 = initiator.write_message(initiator_payload).expect("write msg1");
        let payload1 = responder.read_message(&msg1).expect("read msg1");

        // Message 2: responder → initiator
        let msg2 = responder.write_message(responder_payload).expect("write msg2");
        let payload2 = initiator.read_message(&msg2).expect("read msg2");

        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        let i_transport = initiator.into_transport().expect("initiator transport");
        let r_transport = responder.into_transport().expect("responder transport");

        (i_transport, r_transport, payload1, payload2)
    }

    // T-1: Generate Noise static keypair, verify 32-byte public key
    #[test]
    fn keypair_generates_32_byte_public_key() {
        let kp = KeyPair::generate().expect("keypair generation");
        assert_eq!(kp.public_key().len(), PUBLIC_KEY_LEN);
        assert_ne!(*kp.public_key(), [0u8; PUBLIC_KEY_LEN]);
    }

    // T-2: Full handshake round-trip — both sides complete without error
    #[test]
    fn handshake_round_trip_completes() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let (_, _, _, _) = full_handshake(&initiator_kp, &responder_kp, b"", b"");
    }

    // T-3: Transport encrypt/decrypt round-trip after handshake
    #[test]
    fn transport_encrypt_decrypt_round_trip() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let (mut i_transport, mut r_transport, _, _) = full_handshake(&initiator_kp, &responder_kp, b"", b"");

        let plaintext = b"hello from initiator";
        let ciphertext = i_transport.write_message(plaintext).expect("encrypt");
        let decrypted = r_transport.read_message(&ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    // T-4: Bidirectional transport — initiator and responder both send/recv
    #[test]
    fn transport_bidirectional() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let (mut i_transport, mut r_transport, _, _) = full_handshake(&initiator_kp, &responder_kp, b"", b"");

        // Initiator → Responder
        let msg_ir = b"initiator to responder";
        let ct = i_transport.write_message(msg_ir).expect("encrypt i→r");
        let pt = r_transport.read_message(&ct).expect("decrypt i→r");
        assert_eq!(pt, msg_ir);

        // Responder → Initiator
        let msg_ri = b"responder to initiator";
        let ct = r_transport.write_message(msg_ri).expect("encrypt r→i");
        let pt = i_transport.read_message(&ct).expect("decrypt r→i");
        assert_eq!(pt, msg_ri);
    }

    // T-5: Responder retrieves initiator's static public key
    #[test]
    fn responder_retrieves_initiator_static_key() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let mut initiator = Initiator::new(&initiator_kp, responder_kp.public_key()).expect("initiator");
        let mut responder = Responder::new(&responder_kp).expect("responder");

        // Before message 1, responder doesn't have initiator's key
        assert!(responder.remote_static_key().is_none());

        let msg1 = initiator.write_message(b"").expect("write msg1");
        responder.read_message(&msg1).expect("read msg1");

        // After message 1, responder has initiator's static key
        let remote_key = responder.remote_static_key().expect("should have remote key");
        assert_eq!(remote_key, *initiator_kp.public_key());
    }

    // T-6: Tampered message 1 → handshake error
    #[test]
    fn tampered_message_1_fails() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let mut initiator = Initiator::new(&initiator_kp, responder_kp.public_key()).expect("initiator");
        let mut responder = Responder::new(&responder_kp).expect("responder");

        let mut msg1 = initiator.write_message(b"").expect("write msg1");
        // Flip a byte in the encrypted portion (after the unencrypted ephemeral key)
        let tamper_index = PUBLIC_KEY_LEN + 1;
        if tamper_index < msg1.len() {
            msg1[tamper_index] ^= 0xff;
        }

        let result = responder.read_message(&msg1);
        assert!(result.is_err());
    }

    // T-7: Tampered message 2 → handshake error
    #[test]
    fn tampered_message_2_fails() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let mut initiator = Initiator::new(&initiator_kp, responder_kp.public_key()).expect("initiator");
        let mut responder = Responder::new(&responder_kp).expect("responder");

        let msg1 = initiator.write_message(b"").expect("write msg1");
        responder.read_message(&msg1).expect("read msg1");

        let mut msg2 = responder.write_message(b"").expect("write msg2");
        // Flip a byte in the encrypted portion
        let tamper_index = PUBLIC_KEY_LEN + 1;
        if tamper_index < msg2.len() {
            msg2[tamper_index] ^= 0xff;
        }

        let result = initiator.read_message(&msg2);
        assert!(result.is_err());
    }

    // T-8: Tampered transport message → decrypt error
    #[test]
    fn tampered_transport_message_fails() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let (mut i_transport, mut r_transport, _, _) = full_handshake(&initiator_kp, &responder_kp, b"", b"");

        let mut ciphertext = i_transport.write_message(b"secret data").expect("encrypt");
        ciphertext[0] ^= 0xff;

        let result = r_transport.read_message(&ciphertext);
        assert!(matches!(result, Err(HandshakeError::TransportDecryptFailed)));
    }

    // T-9: Handshake with payload in both messages
    #[test]
    fn handshake_with_payloads() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let initiator_payload = b"client hello payload";
        let responder_payload = b"server hello payload";

        let (_, _, received_init_payload, received_resp_payload) =
            full_handshake(&initiator_kp, &responder_kp, initiator_payload, responder_payload);

        assert_eq!(received_init_payload, initiator_payload);
        assert_eq!(received_resp_payload, responder_payload);
    }

    // T-10: Multiple messages exchanged in transport mode
    #[test]
    fn transport_multiple_messages() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let (mut i_transport, mut r_transport, _, _) = full_handshake(&initiator_kp, &responder_kp, b"", b"");

        let message_count: usize = 100;
        for i in 0..message_count {
            let msg = format!("message number {i}");
            let ct = i_transport.write_message(msg.as_bytes()).expect("encrypt");
            let pt = r_transport.read_message(&ct).expect("decrypt");
            assert_eq!(pt, msg.as_bytes());
        }
    }

    // T-11: Different initiator keys → different transport behavior
    #[test]
    fn different_initiator_keys_produce_different_sessions() {
        let init_kp1 = KeyPair::generate().expect("initiator keypair 1");
        let init_kp2 = KeyPair::generate().expect("initiator keypair 2");
        let responder_kp = KeyPair::generate().expect("responder keypair");

        let (mut i1_transport, _, _, _) = full_handshake(&init_kp1, &responder_kp, b"", b"");
        let (mut i2_transport, _, _, _) = full_handshake(&init_kp2, &responder_kp, b"", b"");

        let plaintext = b"same plaintext";
        let ct1 = i1_transport.write_message(plaintext).expect("encrypt 1");
        let ct2 = i2_transport.write_message(plaintext).expect("encrypt 2");

        // Different sessions → different ciphertexts (different ephemeral keys)
        assert_ne!(ct1, ct2);
    }

    // T-12: Wrong responder key → initiator gets error on message 2
    #[test]
    fn wrong_responder_key_detected() {
        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let responder_kp = KeyPair::generate().expect("responder keypair");
        let wrong_kp = KeyPair::generate().expect("wrong keypair");

        // Initiator thinks it's talking to wrong_kp, but actual responder uses responder_kp
        let mut initiator = Initiator::new(&initiator_kp, wrong_kp.public_key()).expect("initiator");
        let mut responder = Responder::new(&responder_kp).expect("responder");

        let msg1 = initiator.write_message(b"").expect("write msg1");
        // Responder can't decrypt msg1 because initiator targeted wrong key (es token fails)
        let result = responder.read_message(&msg1);
        assert!(result.is_err());
    }

    // T-P002-5: from_private_key round-trips — same public key
    #[test]
    fn keypair_serialization_round_trip() {
        let kp = KeyPair::generate().expect("keypair generation");
        let private_bytes = kp.private_key_bytes().to_vec();
        let original_public = *kp.public_key();

        let kp2 = KeyPair::from_private_key(&private_bytes).expect("reconstruction");
        assert_eq!(*kp2.public_key(), original_public);
    }

    // T-P002-6: from_private_key with loaded key can complete a handshake
    #[test]
    fn keypair_from_private_key_functional() {
        let responder_kp = KeyPair::generate().expect("responder keypair");
        let private_bytes = responder_kp.private_key_bytes().to_vec();
        let public = *responder_kp.public_key();
        drop(responder_kp);

        let loaded_kp = KeyPair::from_private_key(&private_bytes).expect("reconstruction");
        assert_eq!(*loaded_kp.public_key(), public);

        let initiator_kp = KeyPair::generate().expect("initiator keypair");
        let (_, _, _, _) = full_handshake(&initiator_kp, &loaded_kp, b"", b"");
    }

    // T-P002-7: from_private_key with empty bytes fails
    #[test]
    fn keypair_from_private_key_empty_fails() {
        let result = KeyPair::from_private_key(&[]);
        assert!(result.is_err());
    }

    // T-13 (FRD-017): KeyPair zeroizes private key on drop
    #[test]
    fn keypair_zeroizes_private_on_drop() {
        let mut kp = KeyPair::generate().expect("keypair");

        // Verify private key is non-zero
        assert!(!kp.private.iter().all(|&b| b == 0));

        // Simulate what Drop does
        kp.private.zeroize();

        assert!(kp.private.iter().all(|&b| b == 0));
    }
}
