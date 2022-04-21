use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use magic_pake::{
    fpake::build_circuit,
    garble::{self, BinaryEncodingKey},
    ot::apricot::{Receiver, Sender},
    ot::common::*,
};

fn run_ot(msg: Vec<[Vec<u8>; 2]>, choices: Vec<bool>) {
    use magic_pake::ot::chou_orlandi::{OTReceiver, OTSender};
    let (s1, r1) = ductile::new_local_channel();
    let (s2, r2) = ductile::new_local_channel();
    let ch1 = (s1, r2);
    let ch2 = (s2, r1);

    use std::thread;
    let h1 = thread::Builder::new()
        .name("Sender".to_string())
        .spawn(move || {
            let msg = Message::from_zipped(&msg);
            let sender = Sender {
                bootstrap: Box::new(OTReceiver),
            };
            sender.exchange(&msg, &ch1).unwrap();
        });

    let h2 = thread::Builder::new()
        .name("Receiver".to_string())
        .spawn(move || {
            let receiver = Receiver {
                bootstrap: Box::new(OTSender),
            };
            let _ = receiver.exchange(&choices, &ch2).unwrap();
        });

    h1.unwrap().join().unwrap();
    h2.unwrap().join().unwrap();
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Apricot");
    group.sample_size(10);

    // Local
    for i in 8..=24 {
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
        group.throughput(criterion::Throughput::Elements(i));
        group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, _| b.iter(|| run_ot(enc.clone(), choices.clone())));
    }

    // TODO: LAN
    // TODO: WAN

    group.finish();
}

criterion_group!(benches, bench,);
criterion_main!(benches);
