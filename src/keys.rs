// FRD: specs/frds/FRD-P002.md

//! Persistent key management for the `prrr` server.
//!
//! Provides [`KeyStore`] for loading, generating, saving, and rotating
//! X25519 (Noise IK) and ML-KEM-768 key pairs. Keys are stored as raw
//! bytes on disk with restrictive file permissions.
//!
//! # File Layout
//!
//! ```text
//! <identity_key_path>        # Noise IK private key (32 bytes)
//! <identity_key_path>.pub    # Noise IK public key (32 bytes)
//! <pq_key_path>              # ML-KEM-768 decapsulation key (2400 bytes)
//! <pq_key_path>.pub          # ML-KEM-768 encapsulation key (1184 bytes)
//! ```

use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};

use crate::{
    crypto::hybrid_kex::{self, KEM_DECAPSULATION_KEY_LEN, KemKeyPair},
    handshake::noise_ik::{self, PUBLIC_KEY_LEN},
};

/// File extension appended to key paths for the public key file.
const PUBLIC_KEY_SUFFIX: &str = ".pub";

/// File extension appended to key paths for backup files during rotation.
const BACKUP_SUFFIX: &str = ".bak";

/// Unix file permissions for private key files (owner read/write only).
#[cfg(unix)]
const PRIVATE_KEY_PERMISSIONS: u32 = 0o600;

/// Errors that can occur during key store operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// An I/O error occurred at the given path.
    #[error("io error at {path}: {source}")]
    Io {
        /// The filesystem path where the error occurred.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// A key file has an unexpected size, indicating corruption.
    #[error("invalid key size at {path}: expected {expected} bytes, got {actual}")]
    InvalidKeySize {
        /// The filesystem path of the invalid key file.
        path: PathBuf,
        /// The expected key size in bytes.
        expected: usize,
        /// The actual key size in bytes.
        actual: usize,
    },

    /// Noise IK key generation or reconstruction failed.
    #[error("noise key error: {0}")]
    NoiseKey(String),

    /// ML-KEM-768 key reconstruction from bytes failed.
    #[error("KEM key reconstruction failed: {0}")]
    KemReconstruction(String),
}

/// Persistent key store for server identity keys.
///
/// Owns both the Noise IK keypair (X25519) and the ML-KEM-768 keypair.
/// Supports loading from disk, generating fresh keys, saving to disk,
/// and rotating keys with backup.
pub struct KeyStore {
    noise_keypair: noise_ik::KeyPair,
    kem_keypair: hybrid_kex::KemKeyPair,
}

impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore")
            .field("noise_public", &self.noise_public_key_base64())
            .field("kem_public_len", &self.kem_keypair.encapsulation_key_bytes().len())
            .finish()
    }
}

impl KeyStore {
    /// Generate fresh keypairs without persisting to disk.
    pub fn generate() -> Result<Self, KeyStoreError> {
        let noise_keypair = noise_ik::KeyPair::generate().map_err(|e| KeyStoreError::NoiseKey(e.to_string()))?;
        let kem_keypair = KemKeyPair::generate();
        Ok(Self {
            noise_keypair,
            kem_keypair,
        })
    }

    /// Load keys from disk, or generate and save if the files don't exist.
    ///
    /// Checks for the private key files at `identity_key_path` and `pq_key_path`.
    /// If both exist, loads from disk. If neither exists, generates fresh keys
    /// and saves them. If only one exists, returns an error.
    pub fn load_or_generate(identity_key_path: &Path, pq_key_path: &Path) -> Result<Self, KeyStoreError> {
        let identity_exists = identity_key_path.exists();
        let pq_exists = pq_key_path.exists();

        if identity_exists && pq_exists {
            return Self::load(identity_key_path, pq_key_path);
        }

        if identity_exists != pq_exists {
            let missing = if identity_exists { pq_key_path } else { identity_key_path };
            return Err(KeyStoreError::Io {
                path: missing.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "partial key state: one key file exists but the other is missing",
                ),
            });
        }

        let store = Self::generate()?;
        store.save(identity_key_path, pq_key_path)?;
        Ok(store)
    }

    /// Load keys from existing files on disk.
    ///
    /// Reads private key files and their corresponding `.pub` files.
    /// Validates sizes before attempting reconstruction.
    fn load(identity_key_path: &Path, pq_key_path: &Path) -> Result<Self, KeyStoreError> {
        let noise_private = read_key_file(identity_key_path, PUBLIC_KEY_LEN)?;
        let noise_keypair = noise_ik::KeyPair::from_private_key(&noise_private).map_err(|e| KeyStoreError::NoiseKey(e.to_string()))?;

        let kem_dk = read_key_file(pq_key_path, KEM_DECAPSULATION_KEY_LEN)?;
        let kem_keypair = KemKeyPair::from_dk_bytes(&kem_dk).map_err(|e| KeyStoreError::KemReconstruction(e.to_string()))?;

        Ok(Self {
            noise_keypair,
            kem_keypair,
        })
    }

    /// Save keys to disk, creating parent directories as needed.
    ///
    /// Writes four files:
    /// - `identity_key_path` — Noise IK private key (32 bytes, 0600)
    /// - `identity_key_path.pub` — Noise IK public key (32 bytes)
    /// - `pq_key_path` — ML-KEM-768 decapsulation key (2400 bytes, 0600)
    /// - `pq_key_path.pub` — ML-KEM-768 encapsulation key (1184 bytes)
    pub fn save(&self, identity_key_path: &Path, pq_key_path: &Path) -> Result<(), KeyStoreError> {
        // Noise IK keys
        write_key_file(identity_key_path, self.noise_keypair.private_key_bytes(), true)?;
        write_key_file(&public_key_path(identity_key_path), self.noise_keypair.public_key(), false)?;

        // ML-KEM-768 keys
        write_key_file(pq_key_path, &self.kem_keypair.dk_bytes(), true)?;
        write_key_file(&public_key_path(pq_key_path), &self.kem_keypair.encapsulation_key_bytes(), false)?;

        Ok(())
    }

    /// Rotate keys: backup existing files, generate new keys, save.
    ///
    /// Renames existing key files (private + public) to `*.bak`, then
    /// generates and saves new keys.
    pub fn rotate(identity_key_path: &Path, pq_key_path: &Path) -> Result<Self, KeyStoreError> {
        backup_file(identity_key_path)?;
        backup_file(&public_key_path(identity_key_path))?;
        backup_file(pq_key_path)?;
        backup_file(&public_key_path(pq_key_path))?;

        let store = Self::generate()?;
        store.save(identity_key_path, pq_key_path)?;
        Ok(store)
    }

    /// Access the Noise IK keypair.
    pub fn noise_keypair(&self) -> &noise_ik::KeyPair {
        &self.noise_keypair
    }

    /// Access the KEM keypair by reference.
    pub fn kem_keypair(&self) -> &hybrid_kex::KemKeyPair {
        &self.kem_keypair
    }

    /// Consume the key store and return both keypairs.
    ///
    /// Useful when the server API requires ownership of the KEM keypair.
    pub fn into_parts(self) -> (noise_ik::KeyPair, hybrid_kex::KemKeyPair) {
        (self.noise_keypair, self.kem_keypair)
    }

    /// Return the Noise IK public key as standard base64.
    pub fn noise_public_key_base64(&self) -> String {
        BASE64_STANDARD.encode(self.noise_keypair.public_key())
    }

    /// Return the ML-KEM-768 encapsulation (public) key as standard base64.
    pub fn kem_public_key_base64(&self) -> String {
        BASE64_STANDARD.encode(self.kem_keypair.encapsulation_key_bytes())
    }
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

/// Read a key file and validate its size.
fn read_key_file(path: &Path, expected_size: usize) -> Result<Vec<u8>, KeyStoreError> {
    let bytes = std::fs::read(path).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() != expected_size {
        return Err(KeyStoreError::InvalidKeySize {
            path: path.to_path_buf(),
            expected: expected_size,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Write raw bytes to a key file, creating parent directories as needed.
///
/// On Unix, private key files get 0600 permissions.
fn write_key_file(path: &Path, data: &[u8], is_private: bool) -> Result<(), KeyStoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| KeyStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    std::fs::write(path, data).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    if is_private {
        set_permissions(path, PRIVATE_KEY_PERMISSIONS)?;
    }

    #[cfg(not(unix))]
    let _ = is_private;

    Ok(())
}

/// Set Unix file permissions.
#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> Result<(), KeyStoreError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Rename a file to `<path>.bak` if it exists. No-op if file doesn't exist.
fn backup_file(path: &Path) -> Result<(), KeyStoreError> {
    if path.exists() {
        let backup = backup_path(path);
        std::fs::rename(path, &backup).map_err(|source| KeyStoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

/// Compute the `.pub` path for a given key path.
fn public_key_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(PUBLIC_KEY_SUFFIX);
    PathBuf::from(s)
}

/// Compute the `.bak` path for a given key path.
fn backup_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P002.md
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::crypto::hybrid_kex::KEM_ENCAPSULATION_KEY_LEN;

    /// Create a temporary directory for key storage tests.
    fn test_dir() -> TempDir {
        TempDir::new().expect("create temp dir")
    }

    // AC-1: KeyStore::generate() creates valid keypairs
    #[test]
    fn keystore_generate() {
        let store = KeyStore::generate().expect("generate should succeed");
        let noise_pub = store.noise_keypair().public_key();
        assert_eq!(noise_pub.len(), PUBLIC_KEY_LEN);
        assert_ne!(*noise_pub, [0u8; PUBLIC_KEY_LEN]);

        let kem_ek = store.kem_keypair().encapsulation_key_bytes();
        assert_eq!(kem_ek.len(), KEM_ENCAPSULATION_KEY_LEN);
    }

    // AC-2: KeyStore::save() writes 4 files with correct sizes
    #[test]
    fn keystore_save_creates_files() {
        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        let store = KeyStore::generate().expect("generate");
        store.save(&id_path, &pq_path).expect("save should succeed");

        assert_eq!(fs::read(&id_path).expect("read id").len(), PUBLIC_KEY_LEN);
        assert_eq!(fs::read(public_key_path(&id_path)).expect("read id.pub").len(), PUBLIC_KEY_LEN);
        assert_eq!(fs::read(&pq_path).expect("read pq").len(), KEM_DECAPSULATION_KEY_LEN);
        assert_eq!(
            fs::read(public_key_path(&pq_path)).expect("read pq.pub").len(),
            KEM_ENCAPSULATION_KEY_LEN
        );
    }

    // AC-3: Private key files have 0600 permissions (Unix)
    #[cfg(unix)]
    #[test]
    fn keystore_save_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        let store = KeyStore::generate().expect("generate");
        store.save(&id_path, &pq_path).expect("save");

        let id_mode = fs::metadata(&id_path).expect("metadata").permissions().mode() & 0o777;
        let pq_mode = fs::metadata(&pq_path).expect("metadata").permissions().mode() & 0o777;

        assert_eq!(id_mode, PRIVATE_KEY_PERMISSIONS);
        assert_eq!(pq_mode, PRIVATE_KEY_PERMISSIONS);
    }

    // AC-4: load_or_generate generates on first call when no files exist
    #[test]
    fn keystore_load_or_generate_first_run() {
        let dir = test_dir();
        let id_path = dir.path().join("keys/identity.key");
        let pq_path = dir.path().join("keys/pq.key");

        assert!(!id_path.exists());
        assert!(!pq_path.exists());

        let store = KeyStore::load_or_generate(&id_path, &pq_path).expect("first run should generate");

        assert!(id_path.exists());
        assert!(pq_path.exists());
        assert!(public_key_path(&id_path).exists());
        assert!(public_key_path(&pq_path).exists());

        // Verify generated keys are usable
        assert_ne!(*store.noise_keypair().public_key(), [0u8; PUBLIC_KEY_LEN]);
    }

    // AC-5: load_or_generate loads on subsequent calls (same keys)
    #[test]
    fn keystore_load_or_generate_idempotent() {
        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        let store1 = KeyStore::load_or_generate(&id_path, &pq_path).expect("first run");
        let pub1_noise = *store1.noise_keypair().public_key();
        let pub1_kem = store1.kem_keypair().encapsulation_key_bytes();

        let store2 = KeyStore::load_or_generate(&id_path, &pq_path).expect("second run");
        let pub2_noise = *store2.noise_keypair().public_key();
        let pub2_kem = store2.kem_keypair().encapsulation_key_bytes();

        assert_eq!(pub1_noise, pub2_noise);
        assert_eq!(pub1_kem, pub2_kem);
    }

    // AC-6: Loaded keys produce identical public keys as generated
    #[test]
    fn keystore_round_trip_identity() {
        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        let store = KeyStore::generate().expect("generate");
        let original_noise_pub = *store.noise_keypair().public_key();
        let original_kem_ek = store.kem_keypair().encapsulation_key_bytes();

        store.save(&id_path, &pq_path).expect("save");

        let loaded = KeyStore::load(&id_path, &pq_path).expect("load");
        assert_eq!(*loaded.noise_keypair().public_key(), original_noise_pub);
        assert_eq!(loaded.kem_keypair().encapsulation_key_bytes(), original_kem_ek);
    }

    // AC-7: Corrupted (truncated) key file returns InvalidKeySize error
    #[test]
    fn keystore_corrupted_file_error() {
        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        let store = KeyStore::generate().expect("generate");
        store.save(&id_path, &pq_path).expect("save");

        // Truncate the identity key file
        fs::write(&id_path, [0u8; 16]).expect("truncate");

        let result = KeyStore::load(&id_path, &pq_path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                KeyStoreError::InvalidKeySize {
                    expected: 32,
                    actual: 16,
                    ..
                }
            ),
            "expected InvalidKeySize, got: {err}"
        );
    }

    // AC-7b: Corrupted PQ key file returns InvalidKeySize error
    #[test]
    fn keystore_corrupted_pq_file_error() {
        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        let store = KeyStore::generate().expect("generate");
        store.save(&id_path, &pq_path).expect("save");

        // Truncate the PQ key file
        fs::write(&pq_path, [0u8; 100]).expect("truncate");

        let result = KeyStore::load(&id_path, &pq_path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                KeyStoreError::InvalidKeySize {
                    expected: 2400,
                    actual: 100,
                    ..
                }
            ),
            "expected InvalidKeySize, got: {err}"
        );
    }

    // AC-8: Missing parent directories are auto-created
    #[test]
    fn keystore_creates_parent_dirs() {
        let dir = test_dir();
        let id_path = dir.path().join("deep/nested/dir/identity.key");
        let pq_path = dir.path().join("another/deep/dir/pq.key");

        let store = KeyStore::generate().expect("generate");
        store.save(&id_path, &pq_path).expect("save should create dirs");

        assert!(id_path.exists());
        assert!(pq_path.exists());
    }

    // AC-9: rotate() backs up old files with .bak suffix
    #[test]
    fn keystore_rotate_backup() {
        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        let store = KeyStore::generate().expect("generate");
        store.save(&id_path, &pq_path).expect("save");

        let _rotated = KeyStore::rotate(&id_path, &pq_path).expect("rotate");

        // Backup files should exist
        assert!(backup_path(&id_path).exists());
        assert!(backup_path(&public_key_path(&id_path)).exists());
        assert!(backup_path(&pq_path).exists());
        assert!(backup_path(&public_key_path(&pq_path)).exists());

        // New key files should also exist
        assert!(id_path.exists());
        assert!(pq_path.exists());
    }

    // AC-10: rotate() generates new keys different from old
    #[test]
    fn keystore_rotate_new_keys() {
        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        let store = KeyStore::generate().expect("generate");
        let old_noise_pub = *store.noise_keypair().public_key();
        let old_kem_ek = store.kem_keypair().encapsulation_key_bytes();
        store.save(&id_path, &pq_path).expect("save");

        let rotated = KeyStore::rotate(&id_path, &pq_path).expect("rotate");
        let new_noise_pub = *rotated.noise_keypair().public_key();
        let new_kem_ek = rotated.kem_keypair().encapsulation_key_bytes();

        assert_ne!(old_noise_pub, new_noise_pub);
        assert_ne!(old_kem_ek, new_kem_ek);
    }

    // AC-11 + AC-12: base64 encoding is valid and decodable
    #[test]
    fn keystore_base64_encoding() {
        let store = KeyStore::generate().expect("generate");

        let noise_b64 = store.noise_public_key_base64();
        let decoded_noise = BASE64_STANDARD.decode(&noise_b64).expect("decode noise base64");
        assert_eq!(decoded_noise.len(), PUBLIC_KEY_LEN);
        assert_eq!(decoded_noise.as_slice(), store.noise_keypair().public_key());

        let kem_b64 = store.kem_public_key_base64();
        let decoded_kem = BASE64_STANDARD.decode(&kem_b64).expect("decode kem base64");
        assert_eq!(decoded_kem.len(), KEM_ENCAPSULATION_KEY_LEN);
        assert_eq!(decoded_kem, store.kem_keypair().encapsulation_key_bytes());
    }

    // AC-extra: load_or_generate with partial key state returns error
    #[test]
    fn keystore_partial_state_error() {
        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        // Create only the identity key file
        fs::create_dir_all(dir.path()).expect("create dir");
        fs::write(&id_path, [0u8; PUBLIC_KEY_LEN]).expect("write");

        let result = KeyStore::load_or_generate(&id_path, &pq_path);
        assert!(result.is_err());
    }

    // AC-extra: load from nonexistent path returns Io error
    #[test]
    fn keystore_load_missing_files() {
        let dir = test_dir();
        let id_path = dir.path().join("nonexistent/identity.key");
        let pq_path = dir.path().join("nonexistent/pq.key");

        let result = KeyStore::load(&id_path, &pq_path);
        assert!(matches!(result, Err(KeyStoreError::Io { .. })));
    }

    // AC-extra: functional test — loaded keys can complete a handshake
    #[test]
    fn keystore_loaded_keys_handshake() {
        let dir = test_dir();
        let id_path = dir.path().join("identity.key");
        let pq_path = dir.path().join("pq.key");

        let store = KeyStore::load_or_generate(&id_path, &pq_path).expect("generate");

        // Load from disk
        let loaded = KeyStore::load_or_generate(&id_path, &pq_path).expect("load");

        // Use the loaded noise keypair in a handshake
        let initiator_kp = noise_ik::KeyPair::generate().expect("initiator");
        let mut initiator = noise_ik::Initiator::new(&initiator_kp, loaded.noise_keypair().public_key()).expect("create initiator");
        let mut responder = noise_ik::Responder::new(loaded.noise_keypair()).expect("create responder");

        let msg1 = initiator.write_message(b"").expect("write msg1");
        responder.read_message(&msg1).expect("read msg1");
        let msg2 = responder.write_message(b"").expect("write msg2");
        initiator.read_message(&msg2).expect("read msg2");

        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        // Verify loaded KEM key works for encap/decap
        let ek = loaded.kem_keypair().encapsulation_key_bytes();
        let (ct, sender_secret) = hybrid_kex::kem_encapsulate(&ek).expect("encapsulate");
        let receiver_secret = loaded.kem_keypair().decapsulate(&ct).expect("decapsulate");
        assert_eq!(sender_secret, receiver_secret);

        // Verify loaded keys match originally generated keys
        assert_eq!(store.noise_keypair().public_key(), loaded.noise_keypair().public_key());
    }

    // Helper: public_key_path produces correct path
    #[test]
    fn public_key_path_format() {
        let path = Path::new("/etc/prrr/keys/server.key");
        let pub_path = public_key_path(path);
        assert_eq!(pub_path, PathBuf::from("/etc/prrr/keys/server.key.pub"));
    }

    // Helper: backup_path produces correct path
    #[test]
    fn backup_path_format() {
        let path = Path::new("/etc/prrr/keys/server.key");
        let bak_path = backup_path(path);
        assert_eq!(bak_path, PathBuf::from("/etc/prrr/keys/server.key.bak"));
    }
}
