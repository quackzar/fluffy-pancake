use criterion::{criterion_group, criterion_main, Criterion};
use magic_pake::{
    fpake::build_circuit,
    garble::{self, BinaryEncodingKey},
    ot::apricot_avx2::{Receiver, Sender},
    ot::common::*,
};

fn run_ot(msg: &Message, choices: &[bool]) {
    use magic_pake::ot::chou_orlandi::{OTReceiver, OTSender};
    let (s1, r1) = ductile::new_local_channel();
    let (s2, r2) = ductile::new_local_channel();
    let ch1 = (s1, r2);
    let ch2 = (s2, r1);
    let msg = msg.clone();
    let choices = choices.to_vec();

    use std::thread;
    let h1 = thread::Builder::new()
        .name("Sender".to_string())
        .spawn(move || {
            let sender = Sender {
                bootstrap: Box::new(OTReceiver),
            };
            sender.exchange(&msg, &ch1).unwrap();
        });

    let h2 = thread::Builder::new()
        .name("Receiver".to_string())
        .spawn(move || {
            let receiver = Receiver {
                bootstrap: Box::new(OTSender),
            };
            let _ = receiver.exchange(&choices, &ch2).unwrap();
        });

    h1.unwrap().join().unwrap();
    h2.unwrap().join().unwrap();
}

fn bench(c: &mut Criterion) {
    const N: usize = 1048 * 8;
    let name: String = format!("Apricot AVX-2 with {}", N);
    let circuit = build_circuit(N / 2, 0);
    let (_, enc, _) = garble::garble(&circuit);
    let enc = BinaryEncodingKey::from(enc);
    let enc: Vec<_> = enc
        .zipped()
        .iter()
        .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
        .collect();
    let choices = vec![false; N];
    let msg = Message::new2(&enc);
    c.bench_function(&name, |b| b.iter(|| run_ot(&msg, &choices)));
}

criterion_group!(benches, bench,);
criterion_main!(benches);
