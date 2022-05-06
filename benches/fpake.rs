use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ductile::new_local_channel;
use magic_pake::fpake::*;
use std::thread;

fn fpake(password_size: usize) {
    let threshold = 0;
    let password1 = vec![42u8; password_size];
    let password2 = vec![42u8; password_size];

    let (s1, r1) = new_local_channel();
    let (s2, r2) = new_local_channel();
    let ch1 = (s2, r1);
    let ch2 = (s1, r2);
    let h1 = thread::spawn(move || {
        // Party 1
        let k1 = HalfKey::garbler(&password1, threshold, &ch1).unwrap();
        let k2 = HalfKey::evaluator(&password1, &ch1).unwrap();
        k1.combine(k2)
    });

    let h2 = thread::spawn(move || {
        // Party 2
        let k2 = HalfKey::evaluator(&password2, &ch2).unwrap();
        let k1 = HalfKey::garbler(&password2, threshold, &ch2).unwrap();
        k1.combine(k2)
    });

    let _k1 = h1.join().unwrap();
    let _k2 = h2.join().unwrap();
}

fn bench_fpake(c: &mut Criterion) {
    let mut group = c.benchmark_group("fPAKE");
    group.sample_size(10);

    for i in 6..=12 {
        let bits = 1 << i;
        let bytes = bits / 8;

        group.throughput(Throughput::Bytes(bytes as u64));
        let id = BenchmarkId::new("Password", bits);
        group.bench_with_input(id, &bits, |b, _| b.iter(|| fpake(bytes)));
    }

    group.finish();
}

const ITERATIONS: u32 = 14;
fn bench_fpake_one_of_many(c: &mut Criterion) {
    let mut group = c.benchmark_group("One-of-many fPAKE");
    group.sample_size(10);

    // v1, v1
    for i in 8..=15u32 {
    //for i in 8..=ITERATIONS {
        let number_of_passwords = (1 << i) as u32;

        group.throughput(criterion::Throughput::Elements(number_of_passwords as u64));
        group.bench_with_input(
            BenchmarkId::new("v1,v1", number_of_passwords),
            &number_of_passwords,
            |b, _| {
                b.iter(|| {
                    let passwords = vec![vec![0u8; 2048 / 8]; number_of_passwords as usize];
                    let passwords_2 = passwords.clone();
                    let index = 1;
                    let password = passwords[index as usize].clone();
                    let password_2 = password.clone();
                    let threshold = 0;

                    // Do the thing
                    let (s1, r1) = new_local_channel();
                    let (s2, r2) = new_local_channel();
                    let ch1 = (s2, r1);
                    let ch2 = (s1, r2);

                    let h1 = thread::spawn(move || {
                        // Party 1
                        let k1 = OneOfManyKey::garbler_server(&passwords, threshold, &ch1).unwrap();
                        let k2 = OneOfManyKey::evaluator_server(&passwords_2, &ch1).unwrap();
                        k1.combine(k2);
                    });

                    let h2 = thread::spawn(move || {
                        // Party 1
                        let k1 = OneOfManyKey::evaluator_client(
                            &password_2,
                            number_of_passwords,
                            index,
                            &ch2,
                        )
                        .unwrap();
                        let k2 = OneOfManyKey::garbler_client(
                            &password,
                            index,
                            number_of_passwords,
                            threshold,
                            &ch2,
                        )
                        .unwrap();
                        k1.combine(k2);
                    });

                    let _k1 = h1.join().unwrap();
                    let _k2 = h2.join().unwrap();
                })
            },
        );
    }

    // v2, v1
    for i in 8..=15u32 {
    //for i in 8..=ITERATIONSu32 {
        let number_of_passwords = (1 << i) as u32;

        group.throughput(criterion::Throughput::Elements(number_of_passwords as u64));
        group.bench_with_input(BenchmarkId::new("v2,v1", number_of_passwords), &number_of_passwords, |b, _| b.iter(|| {
            let passwords = vec![vec![0u8; 2048 / 8]; number_of_passwords as usize];
            let passwords_2 = passwords.clone();
            let index = 1;
            let password = passwords[index as usize].clone();
            let password_2 = password.clone();
            let threshold = 0;

            // Do the thing
            let (s1, r1) = new_local_channel();
            let (s2, r2) = new_local_channel();
            let ch1 = (s2, r1);
            let ch2 = (s1, r2);

            let h1 = thread::spawn(move || {
                // Party 1
                let k1 = OneOfManyKey::garbler_server_v2(&passwords, threshold, &ch1).unwrap();
                let k2 = OneOfManyKey::evaluator_server(&passwords_2, &ch1).unwrap();
                k1.combine(k2);
            });

            let h2 = thread::spawn(move || {
                // Party 1
                let k1 = OneOfManyKey::evaluator_client_v2(&password_2, number_of_passwords, index, &ch2).unwrap();
                let k2 = OneOfManyKey::garbler_client(&password, index, number_of_passwords, threshold, &ch2).unwrap();
                k1.combine(k2);
            });

            let _k1 = h1.join().unwrap();
            let _k2 = h2.join().unwrap();
        }));
    }

    // v1,v2
    for i in 8..=18u32 {
    //for i in 8..=ITERATIONS {
        let number_of_passwords = (1 << i) as u32;

        group.throughput(criterion::Throughput::Elements(number_of_passwords as u64));
        group.bench_with_input(BenchmarkId::new("v1,v2", number_of_passwords), &number_of_passwords, |b, _| b.iter(|| {
            let passwords = vec![vec![0u8; 2048 / 8]; number_of_passwords as usize];
            let passwords_2 = passwords.clone();
            let index = 1;
            let password = passwords[index as usize].clone();
            let password_2 = password.clone();
            let threshold = 0;

            // Do the thing
            let (s1, r1) = new_local_channel();
            let (s2, r2) = new_local_channel();
            let ch1 = (s2, r1);
            let ch2 = (s1, r2);

            let h1 = thread::spawn(move || {
                // Party 1
                let k1 = OneOfManyKey::garbler_server(&passwords, threshold, &ch1).unwrap();
                let k2 = OneOfManyKey::evaluator_server_v2(&passwords_2, &ch1).unwrap();
                k1.combine(k2);
            });

            let h2 = thread::spawn(move || {
                // Party 1
                let k1 = OneOfManyKey::evaluator_client(&password_2, number_of_passwords, index, &ch2).unwrap();
                let k2 = OneOfManyKey::garbler_client_v2(&password, index, number_of_passwords, threshold, &ch2).unwrap();
                k1.combine(k2);
            });

            let _k1 = h1.join().unwrap();
            let _k2 = h2.join().unwrap();
        }));
    }

    // v2,v2
    for i in 8..=22u32 {
    //for i in 8..=ITERATIONS {
        let number_of_passwords = (1 << i) as u32;

        group.throughput(criterion::Throughput::Elements(number_of_passwords as u64));
        group.bench_with_input(
            BenchmarkId::new("v2,v2", number_of_passwords),
            &number_of_passwords,
            |b, _| {
                b.iter(|| {
                    let passwords = vec![vec![0u8; 2048 / 8]; number_of_passwords as usize];
                    let passwords_2 = passwords.clone();
                    let index = 1;
                    let password = passwords[index as usize].clone();
                    let password_2 = password.clone();
                    let threshold = 0;

                    // Do the thing
                    let (s1, r1) = new_local_channel();
                    let (s2, r2) = new_local_channel();
                    let ch1 = (s2, r1);
                    let ch2 = (s1, r2);

                    let h1 = thread::spawn(move || {
                        // Party 1
                        let k1 =
                            OneOfManyKey::garbler_server_v2(&passwords, threshold, &ch1).unwrap();
                        let k2 = OneOfManyKey::evaluator_server_v2(&passwords_2, &ch1).unwrap();
                        k1.combine(k2);
                    });

                    let h2 = thread::spawn(move || {
                        // Party 1
                        let k1 = OneOfManyKey::evaluator_client_v2(
                            &password_2,
                            number_of_passwords,
                            index,
                            &ch2,
                        )
                        .unwrap();
                        let k2 = OneOfManyKey::garbler_client_v2(
                            &password,
                            index,
                            number_of_passwords,
                            threshold,
                            &ch2,
                        )
                        .unwrap();
                        k1.combine(k2);
                    });

                    let _k1 = h1.join().unwrap();
                    let _k2 = h2.join().unwrap();
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_fpake, bench_fpake_one_of_many);
criterion_main!(benches);
