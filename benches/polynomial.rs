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
    let mut result = Polynomial::new(SIZE * 8);

    // polynomial_mul
    c.bench_function("polynomial_mul_bytes", |b| b.iter(|| polynomial_mul_bytes(&mut result.0, &left, &right)));

    // polynomial_acc
    result.zeroize();
    c.bench_function("polynomial_acc_bytes", |b| b.iter(|| polynomial_acc_bytes(&mut result.0, &left)));

    // polynomial_eq
    result.zeroize();
    c.bench_function("polynomial_eq_bytes", |b| b.iter(|| polynomial_eq_bytes(&left, &right)));
    
    // TODO: Redo the others 'sanely'.
}

criterion_group!(
    benches,
    bench,
);
criterion_main!(benches);
