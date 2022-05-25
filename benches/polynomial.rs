use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use magic_pake::ot::bitmatrix::BitVector;
use magic_pake::ot::polynomial::{Polynomial, polynomial_mul_acc_generic};


fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Polynomial Multiply Reduce");
    group.sample_size(10);

    let mut rng = ChaChaRng::from_seed([0; 32]);
    let a = rng.gen::<[u8; 16]>();
    let b = rng.gen::<[u8; 16]>();
    let a = BitVector::from_bytes(&a);
    let b = BitVector::from_bytes(&b);

    group.bench_function(BenchmarkId::new("Generic Implementation", 1), |bench| {
        bench.iter(|| {
            let mut c1 = BitVector::from_bytes(&[0x00; 16]);
            polynomial_mul_acc_generic(&mut c1, &a, &b);
            let _ = Polynomial::from(c1);
        });
    });

    #[cfg(target_arch = "x86_64")]
    {
        group.bench_function(BenchmarkId::new("x86 Implementation", 1), |bench| {
            bench.iter(|| {
                let mut c1 = BitVector::from_bytes(&[0x00; 16]);
                magic_pake::ot::polynomial::polynomial_mul_acc_x86(&mut c1, &a, &b);
                let _ = Polynomial::from(c1);
            });
        });
    }

    #[cfg(target_arch = "aarch64")]
    {
        group.bench_function(BenchmarkId::new("x86 Implementation", 1), |bench| {
            bench.iter(|| {
                let mut c1 = BitVector::from_bytes(&[0x00; 16]);
                magic_pake::ot::polynomial::polynomial_mul_acc_arm64(&mut c1, &a, &b);
                let _ = Polynomial::from(c1);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench,);
criterion_main!(benches);
