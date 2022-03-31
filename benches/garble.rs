use criterion::{criterion_group, criterion_main, Criterion};

use magic_pake::fpake::build_circuit;
use magic_pake::garble::{encode, evaluate, garble};

fn bench_garble_eval(c: &mut Criterion) {
    for i in 1..=16 {
        let bits = 1 << i;

        let circuit = build_circuit(bits, 8);
        c.bench_function(&format!("Garble {}-bit Threshold Circuit", bits), |b| b.iter(|| garble(&circuit)));

        let (gc, e, _) = garble(&circuit);
        let x = encode(&e, &vec![1; 2 * bits]);
        c.bench_function(&format!("Evaluate {}-bit Threshold Circuit", bits), |b| b.iter(|| evaluate(&gc, &x)));
    }
}

criterion_group!(
    benches,
    bench_garble_eval,
);
criterion_main!(benches);
