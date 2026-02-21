// FRD: specs/frds/FRD-014.md, specs/frds/FRD-015.md, specs/frds/FRD-016.md

//! Messaging layer ("Whisper") for end-to-end encrypted communication.
//!
//! This module implements the PQXDH key agreement protocol for establishing
//! shared secrets between parties, even when one party is offline, the
//! Double Ratchet algorithm for ongoing message encryption with forward secrecy,
//! and message queuing and delivery over the VPN tunnel.

/// Key types, prekey bundles, and prekey signing for PQXDH.
pub mod keys;

/// PQXDH initial key agreement protocol.
pub mod pqxdh;

/// Double Ratchet with Sparse Post-Quantum Ratchet (SPQR).
pub mod ratchet;

/// Wire message types and serialization for the Whisper protocol.
pub mod types;

/// Server-side message relay for store-and-forward delivery.
pub mod relay;

/// Message transport: send/receive over VPN tunnel datagrams.
pub mod transport;

/// High-level messaging client API.
pub mod client;
