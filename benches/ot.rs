use criterion::{criterion_group, criterion_main, Criterion};

use magic_pake::ot::*;

fn run_one_ot() {
    let m0 = b"Hello, world!";
    let m1 = b"Hello, sweden!";
    let receiver = ObliviousReceiver::new(false);
    let sender = ObliviousSender::new(m0.to_vec(), m1.to_vec());
    let receiver = receiver.accept(sender.public());
    let sender = sender.accept(receiver.public());
    let (e0, e1) = sender.send();
    let _receiver = receiver.receive(e0, e1);
}

fn bench_ot(c : &mut Criterion) {
    c.bench_function("OT 1 bit", |b| b.iter(run_one_ot));
}


criterion_group!(benches, bench_ot);
criterion_main!(benches);
