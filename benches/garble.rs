use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use magic_pake::circuit::build_circuit;
use magic_pake::garble::{encode, evaluate, garble};

fn bench_garble_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("Garbled Circuits");
    group.sample_size(100);

    for i in 1..=16 {
        let bits = 1 << i;

        let circuit = build_circuit(bits, 8);
        group.throughput(criterion::Throughput::Elements(bits as u64));
        group.bench_with_input(BenchmarkId::new("Garble", bits), &bits, |b, _| {
            b.iter(|| garble(&circuit))
        });

        let (gc, e, _) = garble(&circuit);
        let x = encode(&e, &vec![1; 2 * bits]);
        group.throughput(criterion::Throughput::Elements(bits as u64));
        group.bench_with_input(BenchmarkId::new("Evaluate", bits), &bits, |b, _| {
            b.iter(|| evaluate(&gc, &x))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_garble_eval,);
criterion_main!(benches);
