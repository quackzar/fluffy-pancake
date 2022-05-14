use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use magic_pake::common::mock::new_local_channel;
use magic_pake::fpake::*;
use std::thread;

fn fpake(password_size: usize) {
    let threshold = 0;
    let password1 = vec![42u8; password_size];
    let password2 = vec![42u8; password_size];

    let (s1, r1) = new_local_channel();
    let (s2, r2) = new_local_channel();
    let ch1 = (s2, r1);
    let ch2 = (s1, r2);
    let h1 = thread::spawn(move || {
        // Party 1
        let k1 = HalfKey::garbler(&password1, threshold, &ch1).unwrap();
        let k2 = HalfKey::evaluator(&password1, &ch1).unwrap();
        k1.combine(k2)
    });

    let h2 = thread::spawn(move || {
        // Party 2
        let k2 = HalfKey::evaluator(&password2, &ch2).unwrap();
        let k1 = HalfKey::garbler(&password2, threshold, &ch2).unwrap();
        k1.combine(k2)
    });

    let _k1 = h1.join().unwrap();
    let _k2 = h2.join().unwrap();
}

fn bench_fpake(c: &mut Criterion) {
    let mut group = c.benchmark_group("fPAKE");
    group.sample_size(10);

    for i in 6..=12 {
        let bits = 1 << i;
        let bytes = bits / 8;

        group.throughput(Throughput::Bytes(bytes as u64));
        let id = BenchmarkId::new("Password", bits);
        group.bench_with_input(id, &bits, |b, _| b.iter(|| fpake(bytes)));
    }

    group.finish();
}

criterion_group!(benches, bench_fpake);
criterion_main!(benches);
