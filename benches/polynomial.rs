use criterion::{criterion_group, criterion_main, Criterion};
use bitvec::prelude::BitVec;
use magic_pake::{
    ot::bitmatrix::*,
    ot::polynomial::*,
};

fn bench(c: &mut Criterion) {
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const SIZE: usize = 128 / 8;
    let mut rng = ChaCha20Rng::from_entropy();
    let left = BitVec::from_vec((0..SIZE).map(|_| rng.gen::<Block>()).collect());
    let right = BitVec::from_vec((0..SIZE).map(|_| rng.gen::<Block>()).collect());
    let mut result = polynomial_new_bitvec(SIZE * 8);

    // polynomial_mul
    c.bench_function("polynomial_mul_bitvec", |b| b.iter(|| polynomial_mul_bitvec(&mut result, &left, &right)));
    polynomial_zero_bitvec(&mut result);
    c.bench_function("polynomial_mul_bytes", |b| b.iter(|| polynomial_mul_bytes(&mut result, &left, &right)));
    polynomial_zero_bitvec(&mut result);

    // polynomial_acc
    polynomial_zero_bitvec(&mut result);
    c.bench_function("polynomial_acc_bitvec", |b| b.iter(|| polynomial_acc_bitvec(&mut result, &left)));
    polynomial_zero_bitvec(&mut result);
    c.bench_function("polynomial_acc_bytes", |b| b.iter(|| polynomial_acc_bytes(&mut result, &left)));
    polynomial_zero_bitvec(&mut result);
    c.bench_function("polynomial_acc_bytes_sse", |b| b.iter(|| polynomial_acc_bytes_sse(&mut result, &left)));

    // polynomial_eq
    polynomial_zero_bitvec(&mut result);
    c.bench_function("polynomial_eq_bitvec", |b| b.iter(|| polynomial_eq_bitvec(&left, &right)));
    polynomial_zero_bitvec(&mut result);
    c.bench_function("polynomial_eq_bytes", |b| b.iter(|| polynomial_eq_bytes(&left, &right)));

    // polynomial_zero
    polynomial_zero_bitvec(&mut result);
    polynomial_acc_bitvec(&mut result, &left);
    c.bench_function("polynomial_zero_bitvec", |b| b.iter(|| polynomial_zero_bitvec(&mut result)));
    polynomial_zero_bitvec(&mut result);
    polynomial_acc_bitvec(&mut result, &left);
    c.bench_function("polynomial_zero_bytes", |b| b.iter(|| polynomial_zero_bytes(&mut result)));

    // polynomial_new
    c.bench_function("polynomial_new_bitvec", |b| b.iter(|| polynomial_new_bitvec(SIZE * 8)));
    c.bench_function("polynomial_new_bytes", |b| b.iter(|| polynomial_new_bytes(SIZE * 8)));

    // polynomial_mul_acc
    polynomial_zero_bitvec(&mut result);
    let mut acc = polynomial_new_bitvec(SIZE * 8);
    c.bench_function("polynomial_mul_bytes, polynomial_acc_bytes", |b| b.iter(|| {
        polynomial_mul_bytes(&mut acc, &left, &right);
        polynomial_acc_bitvec(&mut result, &acc);
    }));
    polynomial_zero_bitvec(&mut acc);
    polynomial_zero_bitvec(&mut result);
    c.bench_function("polynomial_mul_acc_bytes", |b| b.iter(|| polynomial_mul_acc_bytes(&mut result, &left, &right)));
    polynomial_zero_bitvec(&mut acc);
    polynomial_zero_bitvec(&mut result);
    c.bench_function("polynomial_mul_acc_bytes_alt", |b| b.iter(|| polynomial_mul_acc_bytes_alt(&mut result, &left, &right)));
    polynomial_zero_bitvec(&mut acc);
    polynomial_zero_bitvec(&mut result);
    unsafe {
        c.bench_function("polynomial_mul_acc_fast", |b| b.iter(|| polynomial_mul_acc_fast(&mut result, &left, &right)));
    }

    // polynomial_gf128_mul
    polynomial_zero_bitvec(&mut result);
    unsafe {
        c.bench_function("polynomial_gf128_mul_lower", |b| b.iter(|| polynomial_gf128_mul_lower(&mut result, &left, &right)));
    }
    polynomial_zero_bitvec(&mut result);
    unsafe {
        c.bench_function("polynomial_gf128_mul_ocelot", |b| b.iter(|| polynomial_gf128_mul_ocelot(&mut result, &left, &right)));
    }
    polynomial_zero_bitvec(&mut result);
    unsafe {
        c.bench_function("polynomial_gf128_mul_reduce", |b| b.iter(|| polynomial_gf128_mul_reduce(&mut result, &left, &right)));
    }
}

criterion_group!(
    benches,
    bench,
);
criterion_main!(benches);
