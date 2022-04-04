use criterion::{criterion_group, criterion_main, Criterion};
use magic_pake::{ot::bitmatrix::*, ot::polynomial::*};

fn bench(c: &mut Criterion) {
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const SIZE: usize = 128 / 8;
    let mut rng = ChaCha20Rng::from_entropy();
    let left = BitVector::from_vec((0..SIZE).map(|_| rng.gen::<Block>()).collect());
    let right = BitVector::from_vec((0..SIZE).map(|_| rng.gen::<Block>()).collect());
    let mut res = BitVector::from_vec((0..SIZE).map(|_| rng.gen::<Block>()).collect());

    // polynomial_mul
    c.bench_function("polynomial_mul_bytes (generic)", |b| {
        b.iter(|| polynomial_mul_acc_generic(&mut res, &left, &right))
    });

    c.bench_function("polynomial_mul_bytes (intrinsics)", |b| {
        b.iter(|| gf128_mul_acc(&mut res, &left, &right))
    });

    // TODO: Redo the others 'sanely'.
}

criterion_group!(benches, bench,);
criterion_main!(benches);
