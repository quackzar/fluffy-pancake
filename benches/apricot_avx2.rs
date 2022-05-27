use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use magic_pake::{
    circuit::build_circuit,
    common::raw,
    garble::{self, BinaryEncodingKey},
    ot::apricot_avx2,
    ot::chou_orlandi,
    ot::common::*,
};

use std::thread;

fn run_ot(msg: Vec<[Vec<u8>; 2]>, choices: Vec<bool>) {
    let (s1, r1) = raw::new_local_channel();
    let (s2, r2) = raw::new_local_channel();
    let ch1 = (s1, r2);
    let ch2 = (s2, r1);

    let h1 = thread::Builder::new()
        .name("Sender".to_string())
        .spawn(move || {
            let msg = Message::from_zipped(&msg);
            let sender = apricot_avx2::Sender {
                bootstrap: Box::new(chou_orlandi::Receiver),
            };
            sender.exchange(&msg, &ch1).unwrap();
        });

    let h2 = thread::Builder::new()
        .name("Receiver".to_string())
        .spawn(move || {
            let receiver = apricot_avx2::Receiver {
                bootstrap: Box::new(chou_orlandi::Sender),
            };
            let _ = receiver.exchange(&choices, &ch2).unwrap();
        });

    h1.unwrap().join().unwrap();
    h2.unwrap().join().unwrap();
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("OT|Messages");
    group.sample_size(10);

    // Local
    for i in 8..=20 {
        let n = 1 << i;
        //let name: String = format!("Local, {} messages", n);
        let circuit = build_circuit(n / 2, 0);
        let (_, enc, _) = garble::garble(&circuit);
        let enc = BinaryEncodingKey::from(enc);
        let enc: Vec<_> = enc
            .zipped()
            .iter()
            .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
            .collect();
        let choices = vec![false; n];

        group.throughput(criterion::Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("Apricot", n), &n, |b, _| {
            b.iter(|| run_ot(enc.clone(), choices.clone()))
        });
    }

    // TODO: LAN
    // TODO: WAN

    group.finish();
}

criterion_group!(benches, bench,);
criterion_main!(benches);
