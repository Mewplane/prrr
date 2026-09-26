// FRD: specs/frds/FRD-017.md

//! Benchmarks for messaging: Double Ratchet encrypt/decrypt and PQXDH.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use prrr::{
    crypto::x25519,
    messaging::{
        keys::{IdentityKeyPair, PqPrekey, SignedPrekey, generate_prekey_bundle},
        pqxdh,
        ratchet::{RatchetConfig, RatchetState},
    },
};

const KEY_LEN: usize = 32;
const SHARED_SECRET: [u8; KEY_LEN] = [0xAB; KEY_LEN];
const PLAINTEXT_SHORT: &[u8] = b"short message for benchmarking";

fn create_ratchet_pair() -> (RatchetState, RatchetState) {
    let bob_dh = x25519::KeyPair::generate();
    let bob_dh_pub = bob_dh.public_key_bytes();
    let alice = RatchetState::init_alice(SHARED_SECRET, bob_dh_pub, RatchetConfig::default()).expect("alice init");
    let bob = RatchetState::init_bob(SHARED_SECRET, bob_dh, RatchetConfig::default());
    (alice, bob)
}

fn bench_ratchet_encrypt(c: &mut Criterion) {
    let (mut alice, _) = create_ratchet_pair();

    c.bench_function("ratchet_encrypt", |b| b.iter(|| alice.encrypt(black_box(PLAINTEXT_SHORT))));
}

fn bench_ratchet_decrypt(c: &mut Criterion) {
    c.bench_function("ratchet_decrypt", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let (mut alice, mut bob) = create_ratchet_pair();
                let (header, ct) = alice.encrypt(PLAINTEXT_SHORT).expect("encrypt");
                let start = std::time::Instant::now();
                bob.decrypt(black_box(&header), black_box(&ct)).expect("decrypt");
                total += start.elapsed();
            }
            total
        })
    });
}

fn bench_ratchet_alternating(c: &mut Criterion) {
    c.bench_function("ratchet_alternating_10_rounds", |b| {
        b.iter(|| {
            let (mut alice, mut bob) = create_ratchet_pair();
            let rounds: u32 = 10;
            for _ in 0..rounds {
                let (ah, act) = alice.encrypt(black_box(PLAINTEXT_SHORT)).expect("encrypt");
                bob.decrypt(&ah, &act).expect("decrypt");
                let (bh, bct) = bob.encrypt(black_box(PLAINTEXT_SHORT)).expect("encrypt");
                alice.decrypt(&bh, &bct).expect("decrypt");
            }
        })
    });
}

fn bench_pqxdh_initiate(c: &mut Criterion) {
    let alice_ik = IdentityKeyPair::generate();
    let bob_ik = IdentityKeyPair::generate();
    let bob_spk = SignedPrekey::generate(&bob_ik, 1);
    let bob_pq = PqPrekey::generate(&bob_ik, 1);
    let bundle = generate_prekey_bundle(&bob_ik, &bob_spk, None, &bob_pq);

    c.bench_function("pqxdh_initiate_session", |b| {
        b.iter(|| {
            pqxdh::initiate_session(
                black_box(&alice_ik),
                black_box(&bundle),
                black_box(&bob_ik.secret_key_bytes()),
                black_box(PLAINTEXT_SHORT),
            )
        })
    });
}

fn bench_pqxdh_respond(c: &mut Criterion) {
    let alice_ik = IdentityKeyPair::generate();
    let bob_ik = IdentityKeyPair::generate();
    let bob_spk = SignedPrekey::generate(&bob_ik, 1);
    let bob_pq = PqPrekey::generate(&bob_ik, 1);
    let bundle = generate_prekey_bundle(&bob_ik, &bob_spk, None, &bob_pq);

    let result = pqxdh::initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), PLAINTEXT_SHORT).expect("initiate");

    c.bench_function("pqxdh_respond_to_session", |b| {
        b.iter(|| {
            pqxdh::respond_to_session(
                black_box(&bob_ik),
                black_box(&bob_spk),
                None,
                black_box(&bob_pq),
                black_box(&result.initial_message),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_ratchet_encrypt,
    bench_ratchet_decrypt,
    bench_ratchet_alternating,
    bench_pqxdh_initiate,
    bench_pqxdh_respond,
);
criterion_main!(benches);
