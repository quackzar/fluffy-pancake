use criterion::{criterion_group, criterion_main, Criterion};
use magic_pake::{ot::bitmatrix::*, ot::polynomial::*};
use rand_chacha::ChaChaRng;

// For historical reasons.
fn gf128_stupid(result: &mut BitVector, left: &BitVector, right: &BitVector) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();

    let mut intermediate_bytes = [0u8; 128];

    #[allow(clippy::needless_range_loop)]
    for i in 0..size_bytes {
        for j in 0..size_bytes {
            for ib in 0..8 {
                for jb in 0..8 {
                    let ii = i * 8 + ib;
                    let jj = j * 8 + jb;
                    let l = left_bytes[i] & (1 << ib) > 0;
                    let r = right_bytes[j] & (1 << jb) > 0;

                    if l && r {
                        let target = ii + jj;
                        let result_index = target / 8;
                        let result_bit = target % 8;
                        intermediate_bytes[result_index] ^= 1 << result_bit;
                    }
                }
            }
        }
    }

    let result_bytes = result.as_mut_bytes();
    for i in 0..size_bytes {
        result_bytes[i] ^= intermediate_bytes[i];
    }
}

fn bench(c: &mut Criterion) {
    use rand::Rng;
    use rand::SeedableRng;

    let mut rng = ChaChaRng::from_seed([0; 32]);
    let left = BitVector::from_bytes(&rng.gen::<[u8; 16]>());
    let right = BitVector::from_bytes(&rng.gen::<[u8; 16]>());
    let mut res = BitVector::from_bytes(&rng.gen::<[u8; 16]>());

    // polynomial_mul
    c.bench_function("polynomial_mul_bytes (generic)", |b| {
        b.iter(|| polynomial_mul_acc_generic(&mut res, &left, &right))
    });

    c.bench_function("polynomial_mul_bytes (intrinsics)", |b| {
        b.iter(|| gf128_mul_acc(&mut res, &left, &right))
    });

    c.bench_function("polynomial_mul_bytes (old generic)", |b| {
        b.iter(|| gf128_stupid(&mut res, &left, &right))
    });

    // TODO: Redo the others 'sanely'.
}

criterion_group!(benches, bench,);
criterion_main!(benches);
