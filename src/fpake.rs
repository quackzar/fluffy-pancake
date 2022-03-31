use crate::circuit::*;
use crate::garble::*;
use crate::ot::chou_orlandi::{OTReceiver, OTSender};
use crate::ot::common::*;
use crate::ot::common::Message as MessagePair;
use crate::ot::one_of_many::*;
use crate::util::*;
use crate::wires::*;
use crate::common::*;

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


impl HalfKey {
    pub fn garbler(
        password: &[u8],
        threshold: u16,
        ch: &Channel<Vec<u8>>,
    ) -> Result<HalfKey, Error> {
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

        let msg = MessagePair::new2(&e_theirs);
        let ot = OTSender;
        ot.exchange(&msg, ch)?;
        let (s,_) = ch;

        // send garbled circuit.
        s.send(bincode::serialize(&gc)?)?;

        let e_own = BinaryEncodingKey::unzipped(&e_own);
        let enc_password = e_own.encode(&password);
        // send garbled password.
        s.send(bincode::serialize(&enc_password)?)?;

        Ok(HalfKey(d.hashes[0][1]))
    }

    pub fn evaluator(password: &[u8], ch: &Channel<Vec<u8>>) -> Result<HalfKey, Error> {
        let password = u8_vec_to_bool_vec(password);
        let ot = OTReceiver;
        let enc_password = ot.exchange(&password, ch)?;
        let (_,r) = ch;

        let enc_password: Vec<Wire> = enc_password
            .iter()
            .map(|b| to_array(b))
            .map(|b: [u8; 32]| Wire::from_bytes(b, Domain::Binary))
            .collect();

        let our_password = enc_password;
        // receive garbled circuit.
        let gc = bincode::deserialize(&r.recv()?)?;
        // receive garbled password.
        let their_password : Vec<Wire> = bincode::deserialize(&r.recv()?)?;

        // eval circuit
        let mut input = Vec::<Wire>::new();
        input.extend(their_password);
        input.extend(our_password);
        let output = evaluate(&gc, &input);
        Ok(HalfKey(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    pub fn combine(self, other: Self) -> Key {
        Key(xor(self.0, other.0))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct OneOfManyKey(WireBytes);


fn wires_from_bytes(bytes: &[u8], domain: Domain) -> Vec<Wire> {
    let mut wires = Vec::with_capacity(bytes.len() / LENGTH);
    for chunk in bytes.chunks_exact(LENGTH) {
        wires.push(Wire::from_bytes(util::to_array(chunk), domain));
    }

    wires
}

// Bob / server is Garbler
impl OneOfManyKey {
    pub fn garbler_server(
        passwords: &[Vec<u8>],
        threshold: u16,
        ch: &Channel<Vec<u8>>,
    ) -> Result<OneOfManyKey, Error> {
        let (s,_r) = ch;
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit
        let circuit = build_circuit(password_bits, threshold);
        let (gc, encoding, decoding) = garble(&circuit);
        let encoding = BinaryEncodingKey::from(encoding).zipped();
        s.send(bincode::serialize(&gc)?)?;

        // 2. Use regular OT to get the encoded password for the s
        let mut key = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            key.push([
                encoding[i][0].to_bytes().to_vec(),
                encoding[i][1].to_bytes().to_vec(),
            ])
        }
        let key_message = MessagePair::new2(key.as_slice());
        let key_sender = OTSender;
        key_sender.exchange(&key_message, ch)?;

        // 4. Encode all passwords
        let domain = log2(passwords.len());
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

        // 5. Send 1-to-n challenge and Y to s and get response
        let many_sender = ManyOTSender { interal_sender: OTSender };
        many_sender.exchange(&encodings, domain, ch)?;
        //
        // At this point the s should have an encoding of both their own version and the servers version of the password.
        //

        Ok(OneOfManyKey(decoding.hashes[0][1]))
    }

    pub fn evaluator_client(
        password: &[u8],
        number_of_password: u16,
        index: u32,
        ch: &Channel<Vec<u8>>,
    ) -> Result<OneOfManyKey, Error> {
        let (_s,r) = ch;
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Receive the garbled circuit from the other party
        let gc = bincode::deserialize(&r.recv()?)?;

        // 2. Respond to the OT challenge for the encoding of our copy of the key
        let mut choices = Vec::with_capacity(password_bits);
        for i in 0..password_bytes {
            for j in 0..8 {
                let bit = ((password[i] >> j) & 1) == 1;
                choices.push(bit)
            }
        }
        let key_receiver = OTReceiver;
        let key_encoding = key_receiver.exchange(&choices, ch)?;

        let input_encoding = key_encoding
            .iter()
            .map(|k| Wire::from_bytes(util::to_array(k), Domain::Binary));

        // 4. Receive and respond to the 1-to-n challenge from the r
        let many_receiver = ManyOTReceiver { interal_receiver: OTReceiver };
        let domain = log2(number_of_password);
        let encodings = many_receiver.exchange(index, domain, ch)?;
        let database_encoding = wires_from_bytes(encodings.as_slice(), Domain::Binary);

        //
        // By now the s should have both the encoding of their own version of their password and the encoding of the servers version of their password
        //

        // 6. Evaluate the circuit
        let mut input = Vec::<Wire>::new();
        input.extend(database_encoding);
        input.extend(input_encoding);
        let output = evaluate(&gc, &input);
        Ok(OneOfManyKey(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    pub fn garbler_client(
        password: &[u8],
        index: u16,
        number_of_passwords: u16,
        threshold: u16,
        ch: &Channel<Vec<u8>>,
    ) -> Result<OneOfManyKey, Error> {
        let (s,_r) = ch;
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

        s.send(bincode::serialize(&gc)?)?;
        s.send(bincode::serialize(&encoded_password)?)?;

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

        let _magic = vec![vec![0u8; LENGTH]; password_bits];

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
        for i in 0..(number_of_passwords as usize) {
            let msg = MessagePair::new2(&keys[i]);
            let sender = OTSender;
            sender.exchange(&msg, ch)?;
        }

        //
        // At this point the evaluator should have encodings of both inputs and should evaluate the garbled circuit to retrieve their version of they key.
        //

        Ok(OneOfManyKey(decoding.hashes[0][1]))
    }

    pub fn evaluator_server(
        passwords: &[Vec<u8>],
        ch: &Channel<Vec<u8>>,
    ) -> Result<OneOfManyKey, Error> {
        let (_,r) = ch;
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Get the garbled circuit and input from the client
        let gc = bincode::deserialize(&r.recv()?)?;
        let input_encoding : Vec<Wire> = bincode::deserialize(&r.recv()?)?;

        let mut results = Vec::with_capacity(passwords.len());
        for i in 0..passwords.len() {
            let mut choices = Vec::with_capacity(password_bits);
            for j in 0..password_bytes {
                for k in 0..8 {
                    let bit = ((&passwords[i][j] >> k) & 1) == 1;
                    choices.push(bit)
                }
            }

            let receiver = OTReceiver;
            let res = receiver.exchange(&choices, ch)?;
            results.push(res)

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
        Ok(OneOfManyKey(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    pub fn combine(self, other: Self) -> Key {
        Key(xor(self.0, other.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ductile::new_local_channel;

    #[test]
    fn test_fpake_one_of_many_server_garbler() {
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let index = 2u16;
        let password = passwords[index as usize].clone();
        let number_of_passwords = passwords.len() as u16;
        let threshold = 0;

        // Do the thing
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s2, r1);
        let ch2 = (s1, r2);
        let h1 = thread::spawn(move || {
            // Party 1

            OneOfManyKey::garbler_server(&passwords, threshold, &ch1).unwrap()
        });

        let h2 = thread::spawn(move || {
            // Party 1

            OneOfManyKey::evaluator_client(&password, number_of_passwords, index, &ch2).unwrap()
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_client_garbler() {
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let number_of_passwords = passwords.len() as u16;
        let index = 1u16;
        let password = passwords[index as usize].clone();
        let threshold = 0;

        // Do the thing
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s2, r1);
        let ch2 = (s1, r2);
        let h1 = thread::spawn(move || {
            // Party 1

            OneOfManyKey::garbler_client(&password, index, number_of_passwords, threshold, &ch1).unwrap()
        });

        let h2 = thread::spawn(move || {
            // Party 1

            OneOfManyKey::evaluator_server(&passwords, &ch2).unwrap()
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many() {
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let passwords_2 = passwords.clone();
        let number_of_passwords = passwords.len() as u16;
        let index = 1u16;
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
            let k2 = OneOfManyKey::garbler_client(
                &password,
                index,
                number_of_passwords,
                threshold,
                &ch1
            ).unwrap();
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 1
            let k1 =
                OneOfManyKey::evaluator_client(&password_2, number_of_passwords, index, &ch2).unwrap();
            let k2 = OneOfManyKey::evaluator_server(&passwords_2, &ch2).unwrap();
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_api() {
        use std::thread;

        let password = b"password";
        let threshold = 0;

        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s2, r1);
        let ch2 = (s1, r2);
        let h1 = thread::spawn(move || {
            // Party 1
            let k1 = HalfKey::garbler(password, threshold, &ch1).unwrap();
            let k2 = HalfKey::evaluator(password, &ch1).unwrap();
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 2
            let k2 = HalfKey::evaluator(password, &ch2).unwrap();
            let k1 = HalfKey::garbler(password, threshold, &ch2).unwrap();
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

}
