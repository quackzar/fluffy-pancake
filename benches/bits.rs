use bitvec::prelude::*;
use criterion::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};

fn bench_bitvec(c: &mut Criterion) {
    c.bench_function("XOR bitvec u8", |bench| {
        bench.iter(|| {
            let mut rng = thread_rng();
            let a: [u8; 1024] = rng.gen();
            let a = BitVec::<u8, Lsb0>::from_slice(&a);
            let b: [u8; 1024] = rng.gen();
            let b = BitVec::<u8, Lsb0>::from_slice(&b);
            black_box(a ^ b);
        })
    });
}

fn bench_bitvec64(c: &mut Criterion) {
    c.bench_function("XOR bitvec u64", |bench| {
        bench.iter(|| {
            let mut rng = thread_rng();
            let a: [u64; 1024 / 8] = rng.gen();
            let a = BitVec::<u64, Lsb0>::from_slice(&a);
            let b: [u64; 1024 / 8] = rng.gen();
            let b = BitVec::<u64, Lsb0>::from_slice(&b);
            black_box(a ^ b);
        })
    });
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        result.push(a[i] ^ b[i]);
    }
    result
}

fn xor_bytes_arr(a: &[u8], b: &[u8]) -> [u8; 1024] {
    let mut result = [0; 1024];
    for i in 0..a.len() {
        result[i] = a[i] ^ b[i];
    }
    result
}

fn bench_vec_of_bytes(c: &mut Criterion) {
    c.bench_function("XOR bytes", |bench| {
        bench.iter(|| {
            let mut rng = thread_rng();
            let a: [u8; 1024] = rng.gen();
            let b: [u8; 1024] = rng.gen();
            black_box(xor_bytes(&a, &b));
        })
    });
}

fn bench_array_of_bytes(c: &mut Criterion) {
    c.bench_function("XOR array", |bench| {
        bench.iter(|| {
            let mut rng = thread_rng();
            let a: [u8; 1024] = rng.gen();
            let b: [u8; 1024] = rng.gen();
            black_box(xor_bytes_arr(&a, &b));
        })
    });
}

fn xor_bytes_arr_64(a: &[u64], b: &[u64]) -> [u64; 1024 / 8] {
    let mut result = [0; 1024 / 8];
    for i in 0..a.len() {
        result[i] = a[i] ^ b[i];
    }
    result
}

fn bench_array_of_64(c: &mut Criterion) {
    c.bench_function("XOR array 64", |bench| {
        bench.iter(|| {
            let mut rng = thread_rng();
            let a: [u64; 1024 / 8] = rng.gen();
            let b: [u64; 1024 / 8] = rng.gen();
            black_box(xor_bytes_arr_64(&a, &b));
        })
    });
}

fn xor_bytes_arr_128(a: &[u128], b: &[u128]) -> [u128; 1024 / 16] {
    let mut result = [0; 1024 / 16];
    for i in 0..a.len() {
        result[i] = a[i] ^ b[i];
    }
    result
}

fn bench_array_of_128(c: &mut Criterion) {
    c.bench_function("XOR array 128", |bench| {
        bench.iter(|| {
            let mut rng = thread_rng();
            let a: [u128; 1024 / 16] = rng.gen();
            let b: [u128; 1024 / 16] = rng.gen();
            black_box(xor_bytes_arr_128(&a, &b));
        })
    });
}

#[cfg(target_feature = "neon")]
fn xor_simd(a: &[u128], b: &[u128]) -> [u128; 1024 / 16] {
    let mut result = [0; 1024 / 16];
    use std::arch::aarch64::*;
    for i in 0..a.len() {
        result[i] = unsafe { vaddq_p128(a[i], b[i]) };
    }
    result
}

// Maybe do a x86 or portable simd version?
#[cfg(not(target_feature = "neon"))]
fn xor_simd(a: &[u128], b: &[u128]) -> [u128; 1024 / 16] {
    let mut result = [0; 1024 / 16];
    for i in 0..a.len() {
        result[i] = a[i] ^ b[i];
    }
    result
}

fn bench_array_of_simd(c: &mut Criterion) {
    assert!(
        xor_simd(&[0; 1024 / 16], &[0xAA; 1024 / 16])
            == xor_bytes_arr_128(&[0; 1024 / 16], &[0xAA; 1024 / 16])
    );
    c.bench_function("XOR array simd", |bench| {
        bench.iter(|| {
            let mut rng = thread_rng();
            let a: [u128; 1024 / 16] = rng.gen();
            let b: [u128; 1024 / 16] = rng.gen();
            black_box(xor_bytes_arr_128(&a, &b));
        })
    });
}

criterion_group!(
    benches,
    bench_bitvec,
    bench_bitvec64,
    bench_vec_of_bytes,
    bench_array_of_bytes,
    bench_array_of_64,
    bench_array_of_128,
    bench_array_of_simd
);
criterion_main!(benches);
