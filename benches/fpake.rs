use criterion::{criterion_group, criterion_main, Criterion};
use crossbeam_channel::unbounded;
use magic_pake::fpake::*;
use std::thread;

fn fpake(password: &'static [u8]) {
    let threshold = 0;

    let (s1, r1) = unbounded();
    let (s2, r2) = unbounded();
    let h1 = thread::spawn(move || {
        // Party 1
        let k1 = HalfKey::garbler(password, threshold, &s2, &r1);
        let k2 = HalfKey::evaluator(password, &s2, &r1);
        k1.combine(k2)
    });

    let h2 = thread::spawn(move || {
        // Party 2
        let k2 = HalfKey::evaluator(password, &s1, &r2);
        let k1 = HalfKey::garbler(password, threshold, &s1, &r2);
        k1.combine(k2)
    });

    let _k1 = h1.join().unwrap();
    let _k2 = h2.join().unwrap();
}

fn bench_fpake(c: &mut Criterion) {
    c.bench_function("fPAKE 64bit", |b| b.iter(|| fpake(b"password")));
    c.bench_function("fPAKE 128bit", |b| b.iter(|| fpake(b"passwordpassword")));
}

criterion_group!(benches, bench_fpake);
criterion_main!(benches);
