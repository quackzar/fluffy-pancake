use criterion::{criterion_group, criterion_main, Criterion};
use magic_pake::ot::one_of_many::*;


fn log2(x: u16) -> u16 {
    ((std::mem::size_of::<u16>() * 8) as u32 - (x - 1).leading_zeros()) as u16
}

fn one_of_many(n: u16, domain: u16, messages : Vec<Vec<u8>>) {
    let choice = 4;

    let (s1, r1) = ductile::new_local_channel();
    let (s2, r2) = ductile::new_local_channel();
    let ch1 = (s1, r2);
    let ch2 = (s2, r1);

    use std::thread;
    let h1 = thread::Builder::new()
        .name("Sender".to_string())
        .spawn(move || {
            let sender = ManyOTSender {
                interal_sender: magic_pake::ot::chou_orlandi::OTSender,
            };
            sender.exchange(&messages, domain, &ch1).unwrap();
        });

    let h2 = thread::Builder::new()
        .name("Receiver".to_string())
        .spawn(move || {
            let receiver = ManyOTReceiver {
                interal_receiver: magic_pake::ot::chou_orlandi::OTReceiver,
            };
            receiver.exchange(choice, domain, &ch2).unwrap()
        });

    h1.unwrap().join().unwrap();
    h2.unwrap().join().unwrap();
}


fn bench_1_of_n_ot(c: &mut Criterion) {
    let n = 8u16;
    let domain = log2(n);
    let mut messages = Vec::with_capacity(n as usize);
    for i in 0..n {
        messages.push(i.to_be_bytes().to_vec());
    }
    c.bench_function("OT 1-out-of-8 bits", |b| {
        b.iter(|| {
            one_of_many(n, domain, messages.clone());
        })
    });

    let n = 256u16;
    let domain = log2(n);
    let mut messages = Vec::with_capacity(n as usize);
    for i in 0..n {
        messages.push(i.to_be_bytes().to_vec());
    }
    c.bench_function("OT 1-out-of-256", |b| {
        b.iter(|| {
            one_of_many(n, domain, messages.clone());
        })
    });

    let n = 1024u16;
    let domain = log2(n);
    let mut messages = Vec::with_capacity(n as usize);
    for i in 0..n {
        messages.push(i.to_be_bytes().to_vec());
    }
    c.bench_function("OT 1-out-of-1048", |b| {
        b.iter(|| {
            one_of_many(n, domain, messages.clone());
        })
    });

    let n = 1 << 15;
    let domain = log2(n);
    let mut messages = Vec::with_capacity(n as usize);
    for i in 0..n {
        messages.push(i.to_be_bytes().to_vec());
    }

    c.bench_function("OT 1-out-of-32768", |b| {
        b.iter(|| {
            one_of_many(n, domain, messages.clone());
        })
    });
}

criterion_group!(benches, bench_1_of_n_ot,);
criterion_main!(benches);
