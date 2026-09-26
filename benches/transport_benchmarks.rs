// FRD: specs/frds/FRD-017.md

//! Benchmarks for transport layer: EncryptedChannel send/recv.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use prrr::{crypto::aead::KEY_LEN, transport::encrypted_channel::EncryptedChannel};

const TX_KEY: [u8; KEY_LEN] = [0x01; KEY_LEN];
const RX_KEY: [u8; KEY_LEN] = [0x02; KEY_LEN];

const PAYLOAD_64B: usize = 64;
const PAYLOAD_1KB: usize = 1024;
const PAYLOAD_64KB: usize = 65536;

fn bench_encrypted_channel_send(c: &mut Criterion) {
    let plaintext_64b = vec![0xAB; PAYLOAD_64B];
    let plaintext_1kb = vec![0xAB; PAYLOAD_1KB];
    let plaintext_64kb = vec![0xAB; PAYLOAD_64KB];

    c.bench_function("channel_send_64b", |b| {
        let mut channel = EncryptedChannel::new(TX_KEY, RX_KEY);
        b.iter(|| channel.send(black_box(&plaintext_64b)))
    });

    c.bench_function("channel_send_1kb", |b| {
        let mut channel = EncryptedChannel::new(TX_KEY, RX_KEY);
        b.iter(|| channel.send(black_box(&plaintext_1kb)))
    });

    c.bench_function("channel_send_64kb", |b| {
        let mut channel = EncryptedChannel::new(TX_KEY, RX_KEY);
        b.iter(|| channel.send(black_box(&plaintext_64kb)))
    });
}

fn bench_encrypted_channel_round_trip(c: &mut Criterion) {
    let plaintext_1kb = vec![0xAB; PAYLOAD_1KB];

    c.bench_function("channel_round_trip_1kb", |b| {
        let mut sender = EncryptedChannel::new(TX_KEY, RX_KEY);
        let mut receiver = EncryptedChannel::new(RX_KEY, TX_KEY);
        b.iter(|| {
            let wire = sender.send(black_box(&plaintext_1kb)).expect("send");
            receiver.recv(black_box(&wire)).expect("recv")
        })
    });
}

fn bench_encrypted_channel_throughput(c: &mut Criterion) {
    let plaintext = vec![0xAB; PAYLOAD_1KB];
    let packet_count: usize = 100;

    c.bench_function("channel_100_packets_1kb", |b| {
        b.iter(|| {
            let mut sender = EncryptedChannel::new(TX_KEY, RX_KEY);
            let mut receiver = EncryptedChannel::new(RX_KEY, TX_KEY);
            for _ in 0..packet_count {
                let wire = sender.send(black_box(&plaintext)).expect("send");
                receiver.recv(black_box(&wire)).expect("recv");
            }
        })
    });
}

criterion_group!(
    benches,
    bench_encrypted_channel_send,
    bench_encrypted_channel_round_trip,
    bench_encrypted_channel_throughput,
);
criterion_main!(benches);
