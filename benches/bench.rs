use criterion::{criterion_group, criterion_main, Criterion};

use magic_pake::garble::{encode, evaluate, garble};
use magic_pake::fpake::build_circuit;

fn bench_garble(c: &mut Criterion) {
    const BITS: usize = 16;
    let circuit = build_circuit(BITS, 8);
    c.bench_function("Garble", |b| b.iter(|| garble(&circuit)));
}

fn bench_eval(c: &mut Criterion) {
    const BITS: usize = 16;
    let circuit = build_circuit(BITS, 8);
    let (f, e, _) = garble(&circuit);
    let x = encode(&e, &vec![1; 2 * BITS]);
    c.bench_function("Eval garbled", |b| {
        b.iter(|| evaluate(&circuit, &f, x.clone()))
    });
}

criterion_group!(benches, bench_garble, bench_eval);
criterion_main!(benches);




use magic_pake::ot::*;

fn run_one_ot() {
        let m0 = b"Hello, world!".to_vec();
        let m1 = b"Hello, sweden!".to_vec();

        // round 0
        let receiver = ObliviousReceiver::new([false]);
        let sender = ObliviousSender::new(&Message::new([[m0.clone(), m1.clone()]]));

        // round 1
        let receiver = receiver.accept(&sender.public());

        // round 2
        let payload = sender.accept(&receiver.public());

        let msg = receiver.receive(&payload);
}

fn bench_ot(c: &mut Criterion) {
    c.bench_function("OT 1 bit", |b| b.iter(run_one_ot));
}

criterion_group!(benches, bench_ot);
criterion_main!(benches);
