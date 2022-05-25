use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use magic_pake::common::raw::new_local_channel;
use magic_pake::legacy_fpake as legacy;
use magic_pake::many_fpake::*;
use std::thread;

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
                        let k1 = legacy::OneOfManyKey::garbler_server(&passwords, threshold, &ch1)
                            .unwrap();
                        let k2 =
                            legacy::OneOfManyKey::evaluator_server(&passwords_2, &ch1).unwrap();
                        k1.combine(k2);
                    });

                    let h2 = thread::spawn(move || {
                        // Party 1
                        let k1 = legacy::OneOfManyKey::evaluator_client(
                            &password_2,
                            number_of_passwords,
                            index,
                            &ch2,
                        )
                        .unwrap();
                        let k2 = legacy::OneOfManyKey::garbler_client(
                            &password,
                            index,
                            number_of_passwords,
                            threshold,
                            &ch2,
                        )
                        .unwrap();
                        k1.combine(k2);
                    });

                    h1.join().unwrap();
                    h2.join().unwrap();
                })
            },
        );
    }

    // v2, v1
    for i in 8..=15u32 {
        //for i in 8..=ITERATIONSu32 {
        let number_of_passwords = (1 << i) as u32;

        group.throughput(criterion::Throughput::Elements(number_of_passwords as u64));
        group.bench_with_input(
            BenchmarkId::new("v2,v1", number_of_passwords),
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
                            legacy::OneOfManyKey::garbler_server_v2(&passwords, threshold, &ch1)
                                .unwrap();
                        let k2 =
                            legacy::OneOfManyKey::evaluator_server(&passwords_2, &ch1).unwrap();
                        k1.combine(k2);
                    });

                    let h2 = thread::spawn(move || {
                        // Party 1
                        let k1 = legacy::OneOfManyKey::evaluator_client_v2(
                            &password_2,
                            number_of_passwords,
                            index,
                            &ch2,
                        )
                        .unwrap();
                        let k2 = legacy::OneOfManyKey::garbler_client(
                            &password,
                            index,
                            number_of_passwords,
                            threshold,
                            &ch2,
                        )
                        .unwrap();
                        k1.combine(k2);
                    });

                    h1.join().unwrap();
                    h2.join().unwrap();
                })
            },
        );
    }

    // v1,v2
    for i in 8..=18u32 {
        //for i in 8..=ITERATIONS {
        let number_of_passwords = (1 << i) as u32;

        group.throughput(criterion::Throughput::Elements(number_of_passwords as u64));
        group.bench_with_input(
            BenchmarkId::new("v1,v2", number_of_passwords),
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
                        let k1 = legacy::OneOfManyKey::garbler_server(&passwords, threshold, &ch1)
                            .unwrap();
                        let k2 =
                            legacy::OneOfManyKey::evaluator_server_v2(&passwords_2, &ch1).unwrap();
                        k1.combine(k2);
                    });

                    let h2 = thread::spawn(move || {
                        // Party 1
                        let k1 = legacy::OneOfManyKey::evaluator_client(
                            &password_2,
                            number_of_passwords,
                            index,
                            &ch2,
                        )
                        .unwrap();
                        let k2 = legacy::OneOfManyKey::garbler_client_v2(
                            &password,
                            index,
                            number_of_passwords,
                            threshold,
                            &ch2,
                        )
                        .unwrap();
                        k1.combine(k2);
                    });

                    h1.join().unwrap();
                    h2.join().unwrap();
                })
            },
        );
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
                            legacy::OneOfManyKey::garbler_server_v2(&passwords, threshold, &ch1)
                                .unwrap();
                        let k2 =
                            legacy::OneOfManyKey::evaluator_server_v2(&passwords_2, &ch1).unwrap();
                        k1.combine(k2);
                    });

                    let h2 = thread::spawn(move || {
                        // Party 1
                        let k1 = legacy::OneOfManyKey::evaluator_client_v2(
                            &password_2,
                            number_of_passwords,
                            index,
                            &ch2,
                        )
                        .unwrap();
                        let k2 = legacy::OneOfManyKey::garbler_client_v2(
                            &password,
                            index,
                            number_of_passwords,
                            threshold,
                            &ch2,
                        )
                        .unwrap();
                        k1.combine(k2);
                    });

                    h1.join().unwrap();
                    h2.join().unwrap();
                })
            },
        );
    }

    // v3
    for i in 8..=22u32 {
        //for i in 8..=ITERATIONS {
        let number_of_passwords = (1 << i) as u32;

        group.throughput(criterion::Throughput::Elements(number_of_passwords as u64));
        group.bench_with_input(
            BenchmarkId::new("v3", number_of_passwords),
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
                        let (k1, mask) =
                            OneOfManyKey::garbler_server_v3(&passwords, threshold, &ch1).unwrap();
                        let k2 =
                            OneOfManyKey::evaluator_server_v3(&passwords_2, &mask, &ch1).unwrap();
                        k1.combine(k2);
                    });

                    let h2 = thread::spawn(move || {
                        // Party 1
                        let (k1, masked_password) = OneOfManyKey::evaluator_client_v3(
                            &password_2,
                            number_of_passwords,
                            index,
                            &ch2,
                        )
                        .unwrap();
                        let k2 = OneOfManyKey::garbler_client_v3(
                            &password,
                            &masked_password,
                            index,
                            number_of_passwords,
                            threshold,
                            &ch2,
                        )
                        .unwrap();
                        k1.combine(k2);
                    });

                    h1.join().unwrap();
                    h2.join().unwrap();
                })
            },
        );
    }

    // v4
    for i in 8..=22u32 {
        //for i in 8..=ITERATIONS {
        let number_of_passwords = (1 << i) as u32;

        group.throughput(criterion::Throughput::Elements(number_of_passwords as u64));
        group.bench_with_input(
            BenchmarkId::new("v4", number_of_passwords),
            &number_of_passwords,
            |b, _| {
                b.iter(|| {
                    let passwords = vec![vec![0u8; 2048 / 8]; number_of_passwords as usize];
                    let index = 1;
                    let password = passwords[index as usize].clone();
                    let threshold = 0;

                    // Do the thing
                    let (s1, r1) = new_local_channel();
                    let (s2, r2) = new_local_channel();
                    let ch1 = (s2, r1);
                    let ch2 = (s1, r2);

                    let h1 =
                        thread::spawn(move || mfpake_many(&passwords, threshold, &ch1).unwrap());

                    let h2 = thread::spawn(move || {
                        mfpake_single(&password, index, number_of_passwords, threshold, &ch2)
                            .unwrap()
                    });

                    let _k1 = h1.join().unwrap();
                    let _k2 = h2.join().unwrap();
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_fpake_one_of_many);
criterion_main!(benches);
