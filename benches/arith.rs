use criterion::{criterion_group, criterion_main, Criterion};

use magic_pake::arith::{garble, encode, evaluate};
use magic_pake::fpake::build_circuit;

fn bench_garble(c: &mut Criterion) {
    const SECURITY : u64 = 128;
    const BITS : usize = 16;
    let circuit = build_circuit(BITS, 8);
    c.bench_function("fib 20", |b| b.iter(|| garble(&circuit, SECURITY)));
}


fn bench_eval(c: &mut Criterion) {
    const SECURITY : u64 = 128;
    const BITS : usize = 16;
    let circuit = build_circuit(BITS, 8);
    let (f, e, _) = garble(&circuit, SECURITY);
    let x = encode(&e, &vec![1; 2*BITS]);
    c.bench_function("fib 20", |b| b.iter(|| evaluate(&circuit, &f, x.clone())));
}

criterion_group!(benches, bench_garble, bench_eval);
criterion_main!(benches);
