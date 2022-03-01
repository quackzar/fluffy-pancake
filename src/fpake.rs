use crate::circuit::*;
use crate::garble::*;
use crate::ot::*;
use crate::util::*;
use crate::wires::*;

// TODO: fPAKE protocol

pub fn build_circuit(bitsize: usize, threshold: u16) -> Circuit {
    let mut gates: Vec<Gate> = Vec::new();
    let comparison_domain = bitsize as u16 / 2 + 1;
    let bitdomain = 2;

    // xor gates
    for i in 0..bitsize {
        let gate = Gate {
            inputs: vec![i, i + bitsize],
            output: i + 2 * bitsize,
            kind: GateKind::Add,
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // proj gates
    for i in 0..bitsize {
        let gate = Gate {
            inputs: vec![i + 2 * bitsize],
            output: i + 3 * bitsize,
            kind: GateKind::Proj(ProjKind::Map(comparison_domain)),
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // sum
    let gate = Gate {
        kind: GateKind::Add,
        inputs: (3 * bitsize..4 * bitsize).collect(),
        output: 4 * bitsize,
        domain: bitsize as u16,
    };
    gates.push(gate);

    // comparison
    let gate = Gate {
        kind: GateKind::Proj(ProjKind::Less(threshold + 1)),
        inputs: vec![4 * bitsize],
        output: 4 * bitsize + 1,
        domain: comparison_domain,
    };
    gates.push(gate);
    Circuit {
        gates,
        num_inputs: bitsize * 2,
        num_outputs: 1,
        num_wires: 4 * bitsize + 2,
        input_domains: vec![bitdomain; bitsize * 2],
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct HalfKey([u8; LENGTH]);
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Key([u8; LENGTH]);

use crossbeam_channel::{Receiver, Sender};

pub enum Event {
    OTInit(Public),
    OTRequest(Public),
    OTResponse(Payload),
    GCCircuit(GarbledCircuit),
    GCInput(Vec<Wire>),
}

impl HalfKey {
    pub fn garbler(
        password: &[u8],
        threshold: u16,
        s: &Sender<Event>,
        r: &Receiver<Event>,
    ) -> HalfKey {
        let password = u8_vec_to_bool_vec(password);
        let n = password.len();

        // Building circuit
        let circuit = build_circuit(n, threshold);
        let (gc, e, d) = garble(&circuit);

        let e = BinaryEncodingKey::from(e).zipped();
        let e_own = e[..n].to_vec(); //.iter().map(|[w0, w1]| [w0.as_ref(), w1.as_ref()]).collect();
        let e_theirs = e[n..].to_vec(); // encoding for receiver's password'
        let e_theirs: Vec<_> = e_theirs
            .iter()
            .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
            .collect();

        let msg = Message::new(&e_theirs);
        let sender = ObliviousSender::new(&msg);
        // send OT public key and receive their public.
        s.send(Event::OTInit(sender.public())).unwrap();

        let public = match r.recv() {
            Ok(Event::OTRequest(p)) => p,
            _ => panic!("expected OTResponse"),
        };
        let payload = sender.accept(&public);
        // send payload.
        s.send(Event::OTResponse(payload)).unwrap();

        // send garbled circuit.
        s.send(Event::GCCircuit(gc)).unwrap();

        let e_own = BinaryEncodingKey::unzipped(&e_own);
        let enc_password = e_own.encode(&password);
        // send garbled password.
        s.send(Event::GCInput(enc_password)).unwrap();

        HalfKey(d.hashes[0][1])
    }

    pub fn evaluator(password: &[u8], s: &Sender<Event>, r: &Receiver<Event>) -> Self {
        let password = u8_vec_to_bool_vec(password);
        let receiver = ObliviousReceiver::<Init>::new(&password);
        // receive ot public key.
        let public = match r.recv() {
            Ok(Event::OTInit(p)) => p,
            _ => panic!("expected OTInit"),
        };
        let receiver = receiver.accept(&public);
        s.send(Event::OTRequest(receiver.public())).unwrap();
        // receive ot payload.
        let payload = match r.recv() {
            Ok(Event::OTResponse(p)) => p,
            _ => panic!("expected OTResponse"),
        };
        let enc_password = receiver.receive(&payload);
        let enc_password: Vec<Wire> = enc_password
            .iter()
            .map(|b| to_array(b))
            .map(|b: [u8; 32]| Wire::from_bytes(b, Domain::Binary))
            .collect();

        let our_password = enc_password;
        // receive garbled circuit.
        let gc = match r.recv() {
            Ok(Event::GCCircuit(gc)) => gc,
            _ => panic!("expected GCCircuit"),
        };
        // receive garbled password.
        let their_password: Vec<Wire> = match r.recv() {
            Ok(Event::GCInput(p)) => p,
            _ => panic!("expected GCInput"),
        };

        // eval circuit
        let mut input = Vec::<Wire>::new();
        input.extend(their_password);
        input.extend(our_password);
        let output = evaluate(&gc, &input);
        HalfKey(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        ))
    }

    pub fn combine(self, other: Self) -> Key {
        Key(xor(self.0, other.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fpake_api() {
        use crossbeam_channel::unbounded;
        use std::thread;

        let password = b"password";
        let threshold = 0;

        let (s1, r1) = unbounded();
        let (s2, r2) = unbounded();
        let h1 = thread::spawn(move || {
            // Party 1
            let k1 = HalfKey::garbler(password, threshold, &s2, &r1);
            let k2 = HalfKey::evaluator(password, &s2, &r1);
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 2
            let k2 = HalfKey::evaluator(password, &s1, &r2);
            let k1 = HalfKey::garbler(password, threshold, &s1, &r2);
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    fn garble_encode_eval_decode(c: &Circuit, x: &Vec<u16>) -> Vec<u16> {
        let (gc, e, d) = garble(c);
        let x = encode(&e, x);
        let z = evaluate(&gc, &x);
        decode(&d, z).unwrap()
    }

    #[test]
    fn simple_test() {
        let circuit = build_circuit(16, 2);
        println!("{:?}", circuit);
        let x = vec![
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 0,
        ];
        let res = garble_encode_eval_decode(&circuit, &x);
        assert!(res[0] == 1);
    }

    #[test]
    fn ot_encode_test() {
        let circuit = build_circuit(8, 2);
        let x = vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        assert!(x.len() == 16);
        let (gc, e, d) = garble(&circuit);
        let x_enc = encode(&e, &x);
        let x: Vec<bool> = x.iter().map(|x| (*x) != 0).collect();

        // encoding OT.
        let e = BinaryEncodingKey::from(e);
        let msg: Vec<PlaintextPair> =
            e.0.iter()
                .zip(e.1)
                .map(|(w0, w1)| [w0.as_ref().to_vec(), (&w1).as_ref().to_vec()])
                .collect();
        println!("msg len: {}", msg.len());
        let msg = Message::new(&msg);
        // ot protocol
        let sender = ObliviousSender::new(&msg);
        let receiver = ObliviousReceiver::<Init>::new(&x);
        let receiver = receiver.accept(&sender.public());
        let payload = sender.accept(&receiver.public());
        let x_gb = receiver.receive(&payload);
        let x_gb: Vec<Wire> = x_gb
            .iter()
            .map(|b| to_array(b))
            .map(|b: [u8; 32]| Wire::from_bytes(b, Domain::Binary))
            .collect();

        // expected input
        assert!(x_enc == x_gb);

        let res = evaluate(&gc, &x_gb);
        let res = d.decode(&res).expect("Error at decode");
        assert!(res[0] == 1);
    }

    #[test]
    fn test_ot_wire() {
        let wire1 = &Wire::new(2);
        let wire2 = &Wire::new(2);
        let msg = Message::new(&[[wire1.as_ref().to_vec(), wire2.as_ref().to_vec()]]);

        // ot protocol
        let sender = ObliviousSender::new(&msg);
        let receiver = ObliviousReceiver::<Init>::new(&[true]);
        let receiver = receiver.accept(&sender.public());
        let payload = sender.accept(&receiver.public());
        let wire = &receiver.receive(&payload)[0];
        let wire = Wire::from_bytes(to_array(wire), Domain::Binary);
        println!("{:?}", wire);
        println!("{:?}", wire2);
        assert!(&wire == wire2);
    }

    #[test]
    fn fpake() {
        let pwsd_a = vec![1, 1, 1, 1];
        let pwsd_b = vec![1, 1, 1, 0];

        // Alice's garbled circuit and Bob's eval
        let (out_b, one_a) = {
            // Round 1
            let circuit = build_circuit(4, 2);
            let (gc, e, d) = garble(&circuit);
            let e = BinaryEncodingKey::from(e).zipped();
            let e_sender = e[..4].to_vec(); //.iter().map(|[w0, w1]| [w0.as_ref(), w1.as_ref()]).collect();
            let e_receiver = e[4..].to_vec(); // encoding for receiver's password'

            // --- OT start ---
            let e_receiver: Vec<_> = e_receiver
                .iter()
                .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
                .collect();

            // sender sender, receiver receiver.
            let msg = Message::new(&e_receiver);
            let sender = ObliviousSender::new(&msg);
            let x: Vec<bool> = pwsd_b.iter().map(|&x| x == 1).collect();
            let receiver = ObliviousReceiver::<Init>::new(&x);
            let receiver = receiver.accept(&sender.public());
            let payload = sender.accept(&receiver.public());
            let x_receiver = receiver.receive(&payload);
            let x_receiver: Vec<Wire> = x_receiver
                .iter()
                .map(|b| to_array(b))
                .map(|b: [u8; 32]| Wire::from_bytes(b, Domain::Binary))
                .collect();
            // --- OT stop ---

            // sender encoding
            let e_sender = BinaryEncodingKey::unzipped(&e_sender);
            let sender_input: Vec<bool> = pwsd_a.iter().map(|&x| x == 1).collect();
            let x_sender = e_sender.encode(&sender_input);

            // combine input
            let mut input = Vec::<Wire>::new();

            input.extend(x_receiver); // Provided by OT
            input.extend(x_sender);
            let out = evaluate(&gc, &input)[0].clone();
            (
                hash!(
                    (circuit.num_wires - 1).to_be_bytes(),
                    1u16.to_be_bytes(),
                    &out
                ),
                d.hashes[0][1],
            )
        };

        // Bob's garbled circuit and Alice's eval
        let (out_a, one_b) = {
            // Round 2
            let circuit = build_circuit(4, 2);
            let (gc, e, d) = garble(&circuit);
            let e = BinaryEncodingKey::from(e).zipped();
            let e_sender = e[..4].to_vec(); //.iter().map(|[w0, w1]| [w0.as_ref(), w1.as_ref()]).collect();
            let e_receiver = e[4..].to_vec(); // encoding for receiver's password'

            // --- OT start ---
            let e_receiver: Vec<_> = e_receiver
                .iter()
                .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
                .collect();

            // sender sender, receiver receiver.
            let msg = Message::new(&e_receiver);
            let sender = ObliviousSender::new(&msg);
            let x: Vec<bool> = pwsd_a.iter().map(|&x| x == 1).collect();
            let receiver = ObliviousReceiver::<Init>::new(&x);
            let receiver = receiver.accept(&sender.public());
            let payload = sender.accept(&receiver.public());
            let x_receiver = receiver.receive(&payload);
            let x_receiver: Vec<Wire> = x_receiver
                .iter()
                .map(|b| to_array(b))
                .map(|b: [u8; 32]| Wire::from_bytes(b, Domain::Binary))
                .collect();
            // --- OT stop ---

            // sender encoding
            let e_sender = BinaryEncodingKey::unzipped(&e_sender);
            let sender_input: Vec<bool> = pwsd_b.iter().map(|&x| x == 1).collect();
            let x_sender = e_sender.encode(&sender_input);

            // combine input
            let mut input = Vec::<Wire>::new();

            input.extend(x_receiver); // Provided by OT
            input.extend(x_sender);
            let out = evaluate(&gc, &input)[0].clone();
            (
                hash!(
                    (circuit.num_wires - 1).to_be_bytes(),
                    1u16.to_be_bytes(),
                    &out
                ),
                d.hashes[0][1],
            )
        };
        let key_a = xor(out_a, one_a);
        let key_b = xor(out_b, one_b);
        assert_eq!(key_a, key_b)
    }
}
