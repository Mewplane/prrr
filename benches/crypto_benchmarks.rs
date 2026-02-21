// FRD: specs/frds/FRD-017.md

//! Benchmarks for cryptographic primitives: AEAD, X25519, ML-KEM, HKDF.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use prrr::crypto::aead;
use prrr::crypto::hybrid_kex::{self, KemKeyPair};
use prrr::crypto::kdf;
use prrr::crypto::x25519;

const AEAD_KEY: [u8; aead::KEY_LEN] = [0x42; aead::KEY_LEN];
const AEAD_NONCE: [u8; aead::NONCE_LEN] = [0x01; aead::NONCE_LEN];
const AEAD_AAD: &[u8] = b"benchmark-aad";

const HKDF_SALT: [u8; 32] = [0x11; 32];
const HKDF_IKM: [u8; 32] = [0x22; 32];
const HKDF_INFO: &[u8] = b"prrr-bench-v1";

const PAYLOAD_1KB: usize = 1024;
const PAYLOAD_64KB: usize = 65536;

fn bench_aead_encrypt(c: &mut Criterion) {
    let plaintext_1kb = vec![0xAB; PAYLOAD_1KB];
    let plaintext_64kb = vec![0xAB; PAYLOAD_64KB];

    c.bench_function("aead_encrypt_1kb", |b| {
        b.iter(|| {
            aead::encrypt(
                black_box(&AEAD_KEY),
                black_box(&AEAD_NONCE),
                black_box(&plaintext_1kb),
                black_box(AEAD_AAD),
            )
        })
    });

    c.bench_function("aead_encrypt_64kb", |b| {
        b.iter(|| {
            aead::encrypt(
                black_box(&AEAD_KEY),
                black_box(&AEAD_NONCE),
                black_box(&plaintext_64kb),
                black_box(AEAD_AAD),
            )
        })
    });
}

fn bench_aead_decrypt(c: &mut Criterion) {
    let plaintext_1kb = vec![0xAB; PAYLOAD_1KB];
    let plaintext_64kb = vec![0xAB; PAYLOAD_64KB];

    let ct_1kb = aead::encrypt(&AEAD_KEY, &AEAD_NONCE, &plaintext_1kb, AEAD_AAD);
    let ct_64kb = aead::encrypt(&AEAD_KEY, &AEAD_NONCE, &plaintext_64kb, AEAD_AAD);

    c.bench_function("aead_decrypt_1kb", |b| {
        b.iter(|| {
            aead::decrypt(
                black_box(&AEAD_KEY),
                black_box(&AEAD_NONCE),
                black_box(&ct_1kb),
                black_box(AEAD_AAD),
            )
        })
    });

    c.bench_function("aead_decrypt_64kb", |b| {
        b.iter(|| {
            aead::decrypt(
                black_box(&AEAD_KEY),
                black_box(&AEAD_NONCE),
                black_box(&ct_64kb),
                black_box(AEAD_AAD),
            )
        })
    });
}

fn bench_x25519_dh(c: &mut Criterion) {
    let alice = x25519::KeyPair::generate();
    let bob = x25519::KeyPair::generate();
    let bob_pub = bob.public_key_bytes();

    c.bench_function("x25519_dh", |b| b.iter(|| alice.diffie_hellman(black_box(&bob_pub))));
}

fn bench_x25519_keygen(c: &mut Criterion) {
    c.bench_function("x25519_keygen", |b| b.iter(x25519::KeyPair::generate));
}

fn bench_kem_encap(c: &mut Criterion) {
    let kp = KemKeyPair::generate();
    let ek = kp.encapsulation_key_bytes();

    c.bench_function("mlkem768_encapsulate", |b| b.iter(|| hybrid_kex::kem_encapsulate(black_box(&ek))));
}

fn bench_kem_decap(c: &mut Criterion) {
    let kp = KemKeyPair::generate();
    let ek = kp.encapsulation_key_bytes();
    let (ct, _) = hybrid_kex::kem_encapsulate(&ek).expect("encapsulate");

    c.bench_function("mlkem768_decapsulate", |b| b.iter(|| kp.decapsulate(black_box(&ct))));
}

fn bench_hkdf_derive(c: &mut Criterion) {
    let output_32: usize = 32;
    let output_64: usize = 64;
    let output_96: usize = 96;

    c.bench_function("hkdf_derive_32b", |b| {
        b.iter(|| {
            kdf::derive(
                black_box(&HKDF_SALT),
                black_box(&HKDF_IKM),
                black_box(HKDF_INFO),
                black_box(output_32),
            )
        })
    });

    c.bench_function("hkdf_derive_64b", |b| {
        b.iter(|| {
            kdf::derive(
                black_box(&HKDF_SALT),
                black_box(&HKDF_IKM),
                black_box(HKDF_INFO),
                black_box(output_64),
            )
        })
    });

    c.bench_function("hkdf_derive_96b", |b| {
        b.iter(|| {
            kdf::derive(
                black_box(&HKDF_SALT),
                black_box(&HKDF_IKM),
                black_box(HKDF_INFO),
                black_box(output_96),
            )
        })
    });
}

fn bench_blake2s(c: &mut Criterion) {
    let data_32 = vec![0xAB; 32];
    let data_1kb = vec![0xAB; PAYLOAD_1KB];

    c.bench_function("blake2s_32b", |b| b.iter(|| kdf::blake2s(black_box(&data_32))));

    c.bench_function("blake2s_1kb", |b| b.iter(|| kdf::blake2s(black_box(&data_1kb))));
}

criterion_group!(
    benches,
    bench_aead_encrypt,
    bench_aead_decrypt,
    bench_x25519_dh,
    bench_x25519_keygen,
    bench_kem_encap,
    bench_kem_decap,
    bench_hkdf_derive,
    bench_blake2s,
);
criterion_main!(benches);
