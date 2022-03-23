use criterion::{criterion_group, criterion_main, Criterion};
use bitvec::prelude::BitVec;
use magic_pake::{
    ot::common::*,
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
}

criterion_group!(
    benches,
    bench,
);
criterion_main!(benches);
