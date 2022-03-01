use criterion::{criterion_group, criterion_main, Criterion};

use magic_pake::fpake::build_circuit;
use magic_pake::garble::{encode, evaluate, garble};

fn bench_garble_eval16(c: &mut Criterion) {
    const BITS: usize = 16;
    let circuit = build_circuit(BITS, 8);
    c.bench_function("Garble 16bit", |b| b.iter(|| garble(&circuit)));
    let (gc, e, _) = garble(&circuit);
    let x = encode(&e, &vec![1; 2 * BITS]);
    c.bench_function("Eval garbled 16bit", |b| b.iter(|| evaluate(&gc, &x)));
}


fn bench_garble_eval128(c: &mut Criterion) {
    const BITS: usize = 128;
    let circuit = build_circuit(BITS, 8);
    c.bench_function("Garble 128bit", |b| b.iter(|| garble(&circuit)));
    let (gc, e, _) = garble(&circuit);
    let x = encode(&e, &vec![1; 2 * BITS]);
    c.bench_function("Eval garbled 128bit", |b| b.iter(|| evaluate(&gc, &x)));
}

criterion_group!(benches, bench_garble_eval16, bench_garble_eval128);
criterion_main!(benches);
