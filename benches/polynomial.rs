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

    const SIZE: usize = 256 / 8;
    let mut rng = ChaCha20Rng::from_entropy();
    let left = BitVec::from_vec((0..SIZE).map(|_| rng.gen::<Block>()).collect());
    let right = BitVec::from_vec((0..SIZE).map(|_| rng.gen::<Block>()).collect());
    let mut result = polynomial_new(SIZE * 8);

    c.bench_function("polynomial_mul", |b| b.iter(|| polynomial_mul(&mut result, &left, &right)));
    polynomial_zero(&mut result);
    c.bench_function("polynomial_mul_raw", |b| b.iter(|| polynomial_mul_raw(&mut result, &left, &right)));
    polynomial_zero(&mut result);
    c.bench_function("polynomial_mul_raw_2", |b| b.iter(|| polynomial_mul_raw_2(&mut result, &left, &right)));
    polynomial_zero(&mut result);
    c.bench_function("polynomial_mul_raw_3", |b| b.iter(|| polynomial_mul_raw_3(&mut result, &left, &right)));
    polynomial_zero(&mut result);
    c.bench_function("polynomial_mul_raw_4", |b| b.iter(|| polynomial_mul_raw_4(&mut result, &left, &right)));
    polynomial_zero(&mut result);
    c.bench_function("polynomial_mul_raw_5", |b| b.iter(|| polynomial_mul_raw_5(&mut result, &left, &right)));

    polynomial_zero(&mut result);
    c.bench_function("polynomial_acc", |b| b.iter(|| polynomial_acc(&mut result, &left)));
    polynomial_zero(&mut result);
    c.bench_function("polynomial_acc_raw", |b| b.iter(|| polynomial_acc_raw(&mut result, &left)));

    polynomial_zero(&mut result);
    c.bench_function("polynomial_eq", |b| b.iter(|| polynomial_eq(&left, &right)));
    polynomial_zero(&mut result);
    c.bench_function("polynomial_eq_raw", |b| b.iter(|| polynomial_eq_raw(&left, &right)));

    polynomial_zero(&mut result);
    polynomial_acc(&mut result, &left);
    c.bench_function("polynomial_zero", |b| b.iter(|| polynomial_zero(&mut result)));
    polynomial_zero(&mut result);
    polynomial_acc(&mut result, &left);
    c.bench_function("polynomial_zero_raw", |b| b.iter(|| polynomial_zero_raw(&mut result)));

    c.bench_function("polynomial_new", |b| b.iter(|| polynomial_new(SIZE * 8)));
    c.bench_function("polynomial_new_raw", |b| b.iter(|| polynomial_new_raw(SIZE * 8)));
}

criterion_group!(
    benches,
    bench,
);
criterion_main!(benches);
