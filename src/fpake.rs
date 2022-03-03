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
pub struct HalfKey(WireBytes);
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Key(WireBytes);

use crate::util;
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

    pub fn evaluator(password: &[u8], s: &Sender<Event>, r: &Receiver<Event>) -> HalfKey {
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct OneOfManyKey(WireBytes);

pub enum OneOfManyEvent {
    // Server garbles, client evaluates
    GCCircuit(GarbledCircuit),

    OTKeyChallenge(Public),
    OTKeyResponse(Public),
    OTKeyPayload(Payload),

    OTChallenge(Public, Vec<Vec<u8>>),
    OTResponse(Public),
    OTPayload(Payload),

    // Server evaluates, client garbles
    GCCircuitWithInput(GarbledCircuit, Vec<Wire>),

    OTChallenges(Vec<Public>),
    OTResponses(Vec<Public>),
    OTPayloads(Vec<Payload>),
}

fn wires_from_bytes(bytes: &[u8], domain: Domain) -> Vec<Wire> {
    let mut wires = Vec::with_capacity(bytes.len() / LENGTH);
    for chunk in bytes.chunks_exact(LENGTH) {
        wires.push(Wire::from_bytes(util::to_array(chunk), domain));
    }

    return wires;
}

// Bob / server is Garbler
impl OneOfManyKey {
    pub fn garbler_server(
        passwords: &[Vec<u8>],
        threshold: u16,
        evaluator: &Sender<OneOfManyEvent>,
        garbler: &Receiver<OneOfManyEvent>,
    ) -> OneOfManyKey {
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit
        let circuit = build_circuit(password_bits, threshold);
        let (gc, encoding, decoding) = garble(&circuit);
        let encoding = BinaryEncodingKey::from(encoding).zipped();
        evaluator.send(OneOfManyEvent::GCCircuit(gc));

        // 2. Use regular OT to get the encoded password for the evaluator
        let mut key = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            key.push([
                encoding[i][0].to_bytes().to_vec(),
                encoding[i][1].to_bytes().to_vec(),
            ])
        }
        let key_message = Message::new(key.as_slice());
        let key_sender = ObliviousSender::new(&key_message);
        evaluator.send(OneOfManyEvent::OTKeyChallenge(key_sender.public()));

        // 3. Receive response back from OT
        let key_response = match garbler.recv() {
            Ok(OneOfManyEvent::OTKeyResponse(public)) => public,
            _ => panic!("Invalid message received from evaluator!"),
        };
        let key_payload = key_sender.accept(&key_response);
        evaluator.send(OneOfManyEvent::OTKeyPayload(key_payload));

        // 4. Encode all passwords
        let domain = log2(passwords.len()) as u16;
        let mut encodings: Vec<Vec<u8>> = Vec::with_capacity(passwords.len());
        let e_theirs = encoding[password_bits..].to_vec(); // encoding for receiver's password'
        let e_theirs: Vec<_> = e_theirs
            .iter()
            .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
            .collect();
        for password in passwords {
            let mut encoding = Vec::with_capacity(password_bits);
            for i in 0..password_bytes {
                for j in 0..8 {
                    let bit_index = (i * 8 + j) as usize;
                    let bit = (((password[i] >> j) & 1) == 1) as usize;

                    let encoded = &e_theirs[bit_index][bit];
                    encoding.extend(encoded);
                }
            }

            encodings.push(encoding);
        }

        // 5. Send 1-to-n challenge and Y to evaluator and get response
        let (sender, challenge, y) = one_to_n_challenge_create(domain, &encodings);
        evaluator.send(OneOfManyEvent::OTChallenge(challenge, y));
        let challenge_response = match garbler.recv() {
            Ok(OneOfManyEvent::OTResponse(public)) => public,
            _ => panic!("Invalid message received from evaluator!"),
        };
        let payload = one_to_n_create_payloads(&sender, &challenge_response);
        evaluator.send(OneOfManyEvent::OTPayload(payload));

        //
        // At this point the evaluator should have an encoding of both their own version and the servers version of the password.
        //

        return OneOfManyKey(decoding.hashes[0][1]);
    }

    pub fn evaluator_client(
        password: &[u8],
        domain: u16,
        index: u16,
        evaluator: &Sender<OneOfManyEvent>,
        garbler: &Receiver<OneOfManyEvent>,
    ) -> OneOfManyKey {
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Receive the garbled circuit from the other party
        let gc = match garbler.recv() {
            Ok(OneOfManyEvent::GCCircuit(circuit)) => circuit,
            _ => panic!("Invalid message received from garbler!"),
        };

        // 2. Respond to the OT challenge for the encoding of our copy of the key
        let mut choices = Vec::with_capacity(password_bits);
        for i in 0..password_bytes {
            for j in 0..8 {
                let bit = ((password[i] >> j) & 1) == 1;
                choices.push(bit)
            }
        }
        let key_receiver = ObliviousReceiver::new(choices.as_slice());
        let key_challenge = match garbler.recv() {
            Ok(OneOfManyEvent::OTKeyChallenge(public)) => public,
            _ => panic!("Invalid message received from garbler!"),
        };
        let key_receiver = key_receiver.accept(&key_challenge);
        evaluator.send(OneOfManyEvent::OTKeyResponse(key_receiver.public()));

        // 3. Chose our encoding from the payload
        let key_payload = match garbler.recv() {
            Ok(OneOfManyEvent::OTKeyPayload(payload)) => payload,
            _ => panic!("Invalid message received from garbler!"),
        };
        let key_encoding = &key_receiver.receive(&key_payload);
        let input_encoding = key_encoding
            .iter()
            .map(|k| Wire::from_bytes(util::to_array(k), Domain::Binary));

        // 4. Receive and respond to the 1-to-n challenge from the garbler
        let (challenge, y) = match garbler.recv() {
            Ok(OneOfManyEvent::OTChallenge(public, y)) => (public, y),
            _ => panic!("Invalid message received from garbler!"),
        };
        let (receiver, response) = one_to_n_challenge_respond(domain, index, &challenge);
        evaluator.send(OneOfManyEvent::OTResponse(response));

        // 5: Receive payload for 1-to-n and choose
        let payload = match garbler.recv() {
            Ok(OneOfManyEvent::OTPayload(payload)) => payload,
            _ => panic!("Invalid message received from garbler!"),
        };
        let encoding_bytes = one_to_n_choose(domain, index, &receiver, &payload, &y);
        let database_encoding = wires_from_bytes(encoding_bytes.as_slice(), Domain::Binary);

        //
        // By now the evaluator should have both the encoding of their own version of their password and the encoding of the servers version of their password
        //

        // 6. Evaluate the circuit
        let mut input = Vec::<Wire>::new();
        input.extend(database_encoding);
        input.extend(input_encoding);
        let output = evaluate(&gc, &input);
        return OneOfManyKey(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        ));
    }

    pub fn garbler_client(
        password: &[u8],
        index: u16,
        number_of_passwords: u16,
        threshold: u16,
        evaluator: &Sender<OneOfManyEvent>,
        garbler: &Receiver<OneOfManyEvent>,
    ) -> OneOfManyKey {
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit and encode our password
        let circuit = build_circuit(password_bits, threshold);
        let (gc, encoding, decoding) = garble(&circuit);
        let encoding = BinaryEncodingKey::from(encoding).zipped();

        let mut evaluator_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            let bit_encoding = [
                encoding[password_bits + i][0].to_bytes().to_vec(),
                encoding[password_bits + i][1].to_bytes().to_vec(),
            ];
            evaluator_encoding.push(bit_encoding);
        }

        let mut encoded_password = Vec::with_capacity(password_bits);
        for i in 0..password_bytes {
            for j in 0..8 {
                let bit_index = (i * 8 + j) as usize;
                let bit = (((password[i] >> j) & 1) == 1) as usize;

                let encoded = &encoding[bit_index][bit];
                encoded_password.push(encoded.clone());
            }
        }

        evaluator.send(OneOfManyEvent::GCCircuitWithInput(gc, encoded_password));

        // We now need to do a series of OTs for each possible password in the database for the so
        // that the server/evaluator can obtain an encoding of the password they have in their
        // database corresponding to the client, without knowing who the client is.

        // 2. Prepare keys needed to mask values
        let mut random_keys = Vec::with_capacity(number_of_passwords as usize - 1);
        let mut cancelling_key = vec![vec![0u8; LENGTH]; password_bits];
        for _ in 0..(number_of_passwords - 2) {
            let mut keys = Vec::with_capacity(password_bits);
            for j in 0..password_bits {
                let mut key = vec![0u8; LENGTH];
                random_bytes(&mut key);

                cancelling_key[j] = xor_bytes(&cancelling_key[j], &key);
                keys.push(key);
            }

            random_keys.push(keys);
        }
        random_keys.push(cancelling_key);

        let magic = vec![vec![0u8; LENGTH]; password_bits];

        let mut random_key = random_keys.iter();
        let mut keys = Vec::with_capacity(number_of_passwords as usize);
        for i in 0..number_of_passwords {
            let mut keys_for_password = Vec::with_capacity(password_bits);

            if i == index {
                for j in 0..password_bits {
                    keys_for_password.push([
                        evaluator_encoding[j][0].clone(),
                        evaluator_encoding[j][1].clone(),
                    ]);
                }
            } else {
                let random = random_key.next().unwrap();
                for j in 0..password_bits {
                    keys_for_password.push([random[j].clone(), random[j].clone()]);
                }
            }

            keys.push(keys_for_password);
        }

        // 3. Initiate the OTs for each of the passwords
        let mut senders = Vec::with_capacity(number_of_passwords as usize);
        let mut challenges = Vec::with_capacity(number_of_passwords as usize);
        for i in 0..(number_of_passwords as usize) {
            let message = Message::new(&keys[i]);
            let sender = ObliviousSender::new(&message);

            challenges.push(sender.public());
            senders.push(sender);
        }
        evaluator.send(OneOfManyEvent::OTChallenges(challenges));

        // 4. Get responses and send payloads
        let responses = match garbler.recv() {
            Ok(OneOfManyEvent::OTResponses(public)) => public,
            _ => panic!("Invalid message received from garbler!"),
        };
        debug_assert_eq!(number_of_passwords as usize, responses.len());

        let mut payloads = Vec::with_capacity(number_of_passwords as usize);
        for i in 0..(number_of_passwords as usize) {
            let sender = &senders[i];
            let payload = sender.accept(&responses[i]);
            payloads.push(payload);
        }
        evaluator.send(OneOfManyEvent::OTPayloads(payloads));

        //
        // At this point the evaluator should have encodings of both inputs and should evaluate the garbled circuit to retrieve their version of they key.
        //

        return OneOfManyKey(decoding.hashes[0][1]);
    }

    pub fn evaluator_server(
        passwords: &[Vec<u8>],
        evaluator: &Sender<OneOfManyEvent>,
        garbler: &Receiver<OneOfManyEvent>,
    ) -> OneOfManyKey {
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Get the garbled circuit and input from the client
        let (gc, input_encoding) = match garbler.recv() {
            Ok(OneOfManyEvent::GCCircuitWithInput(circuit, input)) => (circuit, input),
            _ => panic!("Invalid message received from garbler!"),
        };

        // 2. Respond to OT challenges
        let mut receivers = Vec::with_capacity(passwords.len());
        let mut responses = Vec::with_capacity(passwords.len());
        let challenges = match garbler.recv() {
            Ok(OneOfManyEvent::OTChallenges(public)) => public,
            _ => panic!("Invalid message received from garbler!"),
        };
        debug_assert_eq!(passwords.len(), challenges.len());

        for i in 0..passwords.len() {
            let mut choices = Vec::with_capacity(password_bits);
            for j in 0..password_bytes {
                for k in 0..8 {
                    let bit = ((&passwords[i][j] >> k) & 1) == 1;
                    choices.push(bit)
                }
            }

            let receiver = ObliviousReceiver::new(&choices);
            let receiver = receiver.accept(&challenges[i]);
            responses.push(receiver.public());
            receivers.push(receiver);
        }
        evaluator.send(OneOfManyEvent::OTResponses(responses));

        // 3. Receive payloads and choose
        let payloads = match garbler.recv() {
            Ok(OneOfManyEvent::OTPayloads(payloads)) => payloads,
            _ => panic!("Invalid message received from garbler!"),
        };
        debug_assert_eq!(passwords.len(), payloads.len());

        let mut results = Vec::with_capacity(passwords.len());
        for i in 0..passwords.len() {
            let receiver = &receivers[i];
            let payload = &payloads[i];
            let result = receiver.receive(payload);
            results.push(result);
        }

        // 4. Compute the encoding for the input from the result
        let mut encoding_bytes = vec![vec![0u8; LENGTH]; password_bits];
        for i in 0..passwords.len() {
            let result = &results[i];
            for j in 0..password_bits {
                encoding_bytes[j] = xor_bytes(&encoding_bytes[j], &result[j])
            }
        }

        let mut database_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            let bytes = &encoding_bytes[i];
            let wire = Wire::from_bytes(util::to_array(bytes), Domain::Binary);
            database_encoding.push(wire);
        }

        //
        // By now the evaluator should have both the encoding of the users password from the database and the encoding of the password they input
        //

        // 6. Evaluate the circuit
        let mut input = Vec::<Wire>::new();
        input.extend(database_encoding);
        input.extend(input_encoding);
        let output = evaluate(&gc, &input);
        return OneOfManyKey(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        ));
    }

    pub fn combine(self, other: Self) -> Key {
        Key(xor(self.0, other.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fpake_one_of_many_server_garbler() {
        use crossbeam_channel::unbounded;
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let index = 2u16;
        let domain = log2(passwords.len()) as u16;
        let password = passwords[index as usize].clone();
        let threshold = 0;

        // Do the thing
        let (s1, r1) = unbounded();
        let (s2, r2) = unbounded();
        let h1 = thread::spawn(move || {
            // Party 1
            let k1 = OneOfManyKey::garbler_server(&passwords, threshold, &s2, &r1);
            k1
        });

        let h2 = thread::spawn(move || {
            // Party 1
            let k2 = OneOfManyKey::evaluator_client(&password, domain, index, &s1, &r2);
            k2
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_client_garbler() {
        use crossbeam_channel::unbounded;
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let number_of_passwords = passwords.len() as u16;
        let index = 1u16;
        let password = passwords[index as usize].clone();
        let threshold = 0;

        // Do the thing
        let (s1, r1) = unbounded();
        let (s2, r2) = unbounded();
        let h1 = thread::spawn(move || {
            // Party 1
            let k1 = OneOfManyKey::garbler_client(
                &password,
                index,
                number_of_passwords,
                threshold,
                &s2,
                &r1,
            );
            k1
        });

        let h2 = thread::spawn(move || {
            // Party 1
            let k2 = OneOfManyKey::evaluator_server(&passwords, &s1, &r2);
            k2
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

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

    fn garble_encode_eval_decode(c: &Circuit, x: &[u16]) -> Vec<u16> {
        let (gc, e, d) = garble(c);
        let x = encode(&e, x);
        let z = evaluate(&gc, &x);
        decode(&d, &z).unwrap()
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
