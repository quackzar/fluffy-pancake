use criterion::{criterion_group, criterion_main, Criterion};

use magic_pake::fpake::build_circuit;
use magic_pake::garble::{encode, evaluate, garble};

fn bench_garble(c: &mut Criterion) {
    const BITS: usize = 16;
    let circuit = build_circuit(BITS, 8);
    c.bench_function("Garble", |b| b.iter(|| garble(&circuit)));
}

fn bench_eval(c: &mut Criterion) {
    const BITS: usize = 16;
    let circuit = build_circuit(BITS, 8);
    let (gc, e, _) = garble(&circuit);
    let x = encode(&e, &vec![1; 2 * BITS]);
    c.bench_function("Eval garbled", |b| b.iter(|| evaluate(&gc, &x)));
}

criterion_group!(benches, bench_garble, bench_eval);
criterion_main!(benches);
