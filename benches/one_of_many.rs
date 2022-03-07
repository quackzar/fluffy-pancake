use criterion::{criterion_group, criterion_main, Criterion};
use magic_pake::{
    fpake::build_circuit,
    garble::{self, BinaryEncodingKey},
    ot::one_of_many::*,
};

fn bench_1_of_n_ot(c: &mut Criterion) {
    fn log2(x: u16) -> u16 {
        ((std::mem::size_of::<u16>() * 8) as u32 - (x - 1).leading_zeros()) as u16
    }
    let n = 8u16;
    let domain = log2(n);
    let mut messages = Vec::with_capacity(n as usize);
    for i in 0..n {
        messages.push(i.to_be_bytes().to_vec());
    }
    let choice = 4;

    c.bench_function("OT 1-out-of-8 bits", |b| b.iter(|| {
        let (sender, challenge, y) = one_to_n_challenge_create(domain, &messages);
        let (receiver, response) = one_to_n_challenge_respond(domain, choice, &challenge);
        let payload = one_to_n_create_payloads(&sender, &response);
        let _output = one_to_n_choose(domain, choice, &receiver, &payload, &y);
    }));


    let n = 256u16;
    let domain = log2(n);
    let mut messages = Vec::with_capacity(n as usize);
    for i in 0..n {
        messages.push(i.to_be_bytes().to_vec());
    }
    let choice = 4;

    c.bench_function("OT 1-out-of-256", |b| b.iter(|| {
        let (sender, challenge, y) = one_to_n_challenge_create(domain, &messages);
        let (receiver, response) = one_to_n_challenge_respond(domain, choice, &challenge);
        let payload = one_to_n_create_payloads(&sender, &response);
        let _output = one_to_n_choose(domain, choice, &receiver, &payload, &y);
    }));

    let n = 1024u16;
    let domain = log2(n);
    let mut messages = Vec::with_capacity(n as usize);
    for i in 0..n {
        messages.push(i.to_be_bytes().to_vec());
    }
    let choice = 4;

    c.bench_function("OT 1-out-of-1048", |b| b.iter(|| {
        let (sender, challenge, y) = one_to_n_challenge_create(domain, &messages);
        let (receiver, response) = one_to_n_challenge_respond(domain, choice, &challenge);
        let payload = one_to_n_create_payloads(&sender, &response);
        let _output = one_to_n_choose(domain, choice, &receiver, &payload, &y);
    }));



    let n = 1 << 15;
    let domain = log2(n);
    let mut messages = Vec::with_capacity(n as usize);
    for i in 0..n {
        messages.push(i.to_be_bytes().to_vec());
    }
    let choice = 4;

    c.bench_function("OT 1-out-of-32768", |b| b.iter(|| {
        let (sender, challenge, y) = one_to_n_challenge_create(domain, &messages);
        let (receiver, response) = one_to_n_challenge_respond(domain, choice, &challenge);
        let payload = one_to_n_create_payloads(&sender, &response);
        let _output = one_to_n_choose(domain, choice, &receiver, &payload, &y);
    }));
}

criterion_group!(
    benches,
    bench_1_of_n_ot,
);
criterion_main!(benches);
