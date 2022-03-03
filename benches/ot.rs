use criterion::{criterion_group, criterion_main, Criterion};
use magic_pake::{
    fpake::build_circuit,
    garble::{self, BinaryEncodingKey},
    ot::*,
};

fn run_one_ot() {
    let m0 = b"Hello, world!".to_vec();
    let m1 = b"Hello, sweden!".to_vec();

    // round 0
    let receiver = ObliviousReceiver::new(&[false]);
    let sender = ObliviousSender::new(&Message::new(&[[m0, m1]]));

    // round 1
    let receiver = receiver.accept(&sender.public());

    // round 2
    let payload = sender.accept(&receiver.public());

    let _ = receiver.receive(&payload);
}

fn run_ot(msg: &[PlaintextPair], choices: &[bool]) {
    // round 0
    let receiver = ObliviousReceiver::new(choices);
    let sender = ObliviousSender::new(&Message::new(msg));

    // round 1
    let receiver = receiver.accept(&sender.public());

    // round 2
    let payload = sender.accept(&receiver.public());

    let _ = receiver.receive(&payload);
}

fn bench_ot_1bit(c: &mut Criterion) {
    c.bench_function("OT 1 bit", |b| b.iter(run_one_ot));
}

fn bench_ot_128bit(c: &mut Criterion) {
    let circuit = build_circuit(128 / 2, 0);
    let (_, enc, _) = garble::garble(&circuit);
    let enc = BinaryEncodingKey::from(enc);
    let enc: Vec<_> = enc
        .zipped()
        .iter()
        .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
        .collect();
    let choices = vec![false; 128];
    c.bench_function("OT 128 bits", |b| b.iter(|| run_ot(&enc, &choices)));
}

fn bench_ot_256bit(c: &mut Criterion) {
    let circuit = build_circuit(256 / 2, 0);
    let (_, enc, _) = garble::garble(&circuit);
    let enc = BinaryEncodingKey::from(enc);
    let enc: Vec<_> = enc
        .zipped()
        .iter()
        .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
        .collect();
    let choices = vec![false; 256];
    c.bench_function("OT 256 bits", |b| b.iter(|| run_ot(&enc, &choices)));
}

fn bench_ot_2048bit(c: &mut Criterion) {
    let circuit = build_circuit(2048 / 2, 0);
    let (_, enc, _) = garble::garble(&circuit);
    let enc = BinaryEncodingKey::from(enc);
    let enc: Vec<_> = enc
        .zipped()
        .iter()
        .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
        .collect();
    let choices = vec![false; 2048];
    c.bench_function("OT 2048 bits", |b| b.iter(|| run_ot(&enc, &choices)));
}

criterion_group!(
    benches,
    bench_ot_1bit,
    bench_ot_128bit,
    bench_ot_256bit,
    bench_ot_2048bit
);
criterion_main!(benches);
