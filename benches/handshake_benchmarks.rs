// FRD: specs/frds/FRD-017.md

//! Benchmarks for handshake operations: Noise IK and Hybrid (Noise IK + ML-KEM).

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use prrr::crypto::hybrid_kex::KemKeyPair;
use prrr::handshake::hybrid::{HybridInitiator, HybridResponder};
use prrr::handshake::noise_ik::KeyPair;

fn bench_noise_ik_handshake(c: &mut Criterion) {
    let initiator_kp = KeyPair::generate().expect("initiator keypair");
    let responder_kp = KeyPair::generate().expect("responder keypair");

    c.bench_function("noise_ik_full_handshake", |b| {
        b.iter(|| {
            let init_kp = KeyPair::generate().expect("initiator keypair");
            let resp_kp = KeyPair::generate().expect("responder keypair");

            let mut initiator = prrr::handshake::noise_ik::Initiator::new(&init_kp, resp_kp.public_key()).expect("initiator");
            let mut responder = prrr::handshake::noise_ik::Responder::new(&resp_kp).expect("responder");

            let msg1 = initiator.write_message(b"").expect("write msg1");
            responder.read_message(black_box(&msg1)).expect("read msg1");
            let msg2 = responder.write_message(b"").expect("write msg2");
            initiator.read_message(black_box(&msg2)).expect("read msg2");

            let _i_transport = initiator.into_transport().expect("initiator transport");
            let _r_transport = responder.into_transport().expect("responder transport");
        })
    });

    // Bench just message processing (reusing keys)
    c.bench_function("noise_ik_msg1_write", |b| {
        b.iter(|| {
            let mut initiator = prrr::handshake::noise_ik::Initiator::new(black_box(&initiator_kp), black_box(responder_kp.public_key()))
                .expect("initiator");
            initiator.write_message(b"").expect("write msg1")
        })
    });
}

fn bench_hybrid_handshake(c: &mut Criterion) {
    c.bench_function("hybrid_full_handshake", |b| {
        b.iter(|| {
            let init_noise = KeyPair::generate().expect("initiator noise keypair");
            let resp_noise = KeyPair::generate().expect("responder noise keypair");
            let resp_kem = KemKeyPair::generate();
            let resp_kem_pub = resp_kem.encapsulation_key_bytes();

            let (initiator, msg1) =
                HybridInitiator::new(&init_noise, resp_noise.public_key(), black_box(&resp_kem_pub)).expect("initiator");

            let responder = HybridResponder::new(&resp_noise, resp_kem).expect("responder");
            let (msg2, _resp_result) = responder.finish(black_box(&msg1), b"").expect("responder finish");

            let _init_result = initiator.finish(black_box(&msg2)).expect("initiator finish");
        })
    });
}

fn bench_hybrid_keygen(c: &mut Criterion) {
    c.bench_function("hybrid_keygen_all", |b| {
        b.iter(|| {
            let _noise_kp = KeyPair::generate().expect("noise keypair");
            let _kem_kp = KemKeyPair::generate();
        })
    });
}

criterion_group!(benches, bench_noise_ik_handshake, bench_hybrid_handshake, bench_hybrid_keygen,);
criterion_main!(benches);
