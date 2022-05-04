use crate::circuit::*;
use crate::common::*;
use crate::garble::*;
use crate::instrument;
use crate::instrument::{E_COMP_COLOR, E_FUNC_COLOR, E_PROT_COLOR, E_RECV_COLOR, E_SEND_COLOR};
use crate::ot::apricot_avx2::{Receiver, Sender};
use crate::ot::chou_orlandi::{OTReceiver, OTSender};
use crate::ot::common::Message as MessagePair;
use crate::ot::common::*;
use crate::ot::one_of_many::*;
use crate::util::*;
use crate::wires::*;

pub fn build_circuit(bitsize: usize, threshold: u16) -> Circuit {
    let mut gates: Vec<Gate> = Vec::new();
    let comparison_domain = bitsize as u16 + 1;
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
        domain: comparison_domain,
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

// Inputs for the circuit: masked password, mask, other password
pub fn build_circuit_v2(bitsize: usize, threshold: u16) -> Circuit {
    let mut gates: Vec<Gate> = Vec::new();
    let comparison_domain = bitsize as u16 + 1;
    let bitdomain = 2;

    // xor: unmask
    for i in 0..bitsize {
        let gate = Gate {
            inputs: vec![i, i + bitsize],
            output: i + 3 * bitsize,
            kind: GateKind::Add,
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // xor: compare
    for i in 0..bitsize {
        let gate = Gate {
            inputs: vec![i + 2 * bitsize, i + 3 * bitsize],
            output: i + 4 * bitsize,
            kind: GateKind::Add,
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // proj gates
    for i in 0..bitsize {
        let gate = Gate {
            inputs: vec![i + 4 * bitsize],
            output: i + 5 * bitsize,
            kind: GateKind::Proj(ProjKind::Map(comparison_domain)),
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // sum
    let gate = Gate {
        kind: GateKind::Add,
        inputs: (5 * bitsize..6 * bitsize).collect(),
        output: 6 * bitsize,
        domain: comparison_domain,
    };
    gates.push(gate);

    // comparison
    let gate = Gate {
        kind: GateKind::Proj(ProjKind::Less(threshold + 1)),
        inputs: vec![6 * bitsize],
        output: 6 * bitsize + 1,
        domain: comparison_domain,
    };
    gates.push(gate);
    Circuit {
        gates,
        num_inputs: bitsize * 3,
        num_outputs: 1,
        num_wires: 6 * bitsize + 2,
        input_domains: vec![bitdomain; bitsize * 3],
    }
}

// Inputs for the circuit: masked password, mask, other password
pub fn build_circuit_v3(bitsize: usize, threshold: u16) -> Circuit {
    let mut gates: Vec<Gate> = Vec::new();
    let comparison_domain = bitsize as u16 + 1;
    let bitdomain = 2;

    // xor: unmask & compare
    for i in 0..bitsize {
        let gate = Gate {
            inputs: vec![i, i + bitsize, i + 2 * bitsize],
            output: i + 3 * bitsize,
            kind: GateKind::Add,
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // proj gates
    for i in 0..bitsize {
        let gate = Gate {
            inputs: vec![i + 3 * bitsize],
            output: i + 4 * bitsize,
            kind: GateKind::Proj(ProjKind::Map(comparison_domain)),
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // sum
    let gate = Gate {
        kind: GateKind::Add,
        inputs: (4 * bitsize..5 * bitsize).collect(),
        output: 5 * bitsize,
        domain: comparison_domain,
    };
    gates.push(gate);

    // comparison
    let gate = Gate {
        kind: GateKind::Proj(ProjKind::Less(threshold + 1)),
        inputs: vec![5 * bitsize],
        output: 5 * bitsize + 1,
        domain: comparison_domain,
    };
    gates.push(gate);
    Circuit {
        gates,
        num_inputs: bitsize * 3,
        num_outputs: 1,
        num_wires: 5 * bitsize + 2,
        input_domains: vec![bitdomain; bitsize * 3],
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct HalfKey(WireBytes);
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Key(WireBytes);

use crate::util;

impl HalfKey {
    pub fn garbler(password: &[u8], threshold: u16, ch: &Channel<Vec<u8>>) -> Result<Self, Error> {
        instrument::begin("Garbler", E_PROT_COLOR);

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

        let msg = MessagePair::from_zipped(&e_theirs);
        let ot = Sender {
            bootstrap: Box::new(OTReceiver),
        };
        ot.exchange(&msg, ch)?;
        let (s, _) = ch;

        // send garbled circuit.
        s.send(bincode::serialize(&gc)?)?;

        let e_own = BinaryEncodingKey::unzipped(&e_own);
        let enc_password = e_own.encode(&password);
        // send garbled password.
        s.send(bincode::serialize(&enc_password)?)?;

        instrument::end();
        Ok(Self(d.hashes[0][1]))
    }

    pub fn evaluator(password: &[u8], ch: &Channel<Vec<u8>>) -> Result<Self, Error> {
        instrument::begin("Evaluator", E_PROT_COLOR);

        let password = u8_vec_to_bool_vec(password);
        let ot = Receiver {
            bootstrap: Box::new(OTSender),
        };
        let enc_password = ot.exchange(&password, ch)?;
        let (_, r) = ch;

        let enc_password: Vec<Wire> = enc_password
            .iter()
            .map(|b| to_array(b))
            .map(|b: [u8; 32]| Wire::from_array(b, Domain::Binary))
            .collect();

        let our_password = enc_password;
        // receive garbled circuit.
        let gc = bincode::deserialize(&r.recv()?)?;
        // receive garbled password.
        let their_password: Vec<Wire> = bincode::deserialize(&r.recv()?)?;

        // eval circuit
        let mut input = Vec::<Wire>::new();
        input.extend(their_password);
        input.extend(our_password);
        let output = evaluate(&gc, &input);

        instrument::end();
        Ok(Self(hash!(
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
        wires.push(Wire::from_array(util::to_array(chunk), domain));
    }

    wires
}

// Bob / server is Garbler
impl OneOfManyKey {
    pub fn garbler_server(
        passwords: &[Vec<u8>],
        threshold: u16,
        ch: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("garbler_server", E_FUNC_COLOR);

        let (s, _r) = ch;
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit
        instrument::begin("Build Circuit", E_COMP_COLOR);
        let circuit = build_circuit(password_bits, threshold);
        instrument::end();

        instrument::begin("Garble circuit", E_PROT_COLOR);
        let (gc, encoding, decoding) = garble(&circuit);
        let encoding = BinaryEncodingKey::from(encoding).zipped();
        instrument::end();

        instrument::begin("Send garbled circuit", E_SEND_COLOR);
        s.send(bincode::serialize(&gc)?)?;
        instrument::end();

        // 2. Use regular OT to get the encoded password for the server
        instrument::begin("Build message for OT", E_COMP_COLOR);
        let mut key = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            key.push([
                encoding[i][0].to_bytes().to_vec(),
                encoding[i][1].to_bytes().to_vec(),
            ])
        }
        let key_message = MessagePair::from_zipped(key.as_slice());
        let key_sender = Sender {
            bootstrap: Box::new(OTReceiver),
        };
        instrument::end();

        instrument::begin("OT Sender", E_PROT_COLOR);
        key_sender.exchange(&key_message, ch)?;
        instrument::end();

        // 4. Encode all passwords
        instrument::begin("Encode all passwords", E_COMP_COLOR);
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
        instrument::end();

        // 5. Send 1-to-n challenge and Y to s and get response
        instrument::begin("1-to-n OT Sender", E_PROT_COLOR);
        let many_sender = ManyOTSender {
            interal_sender: OTSender,
        };
        many_sender.exchange(&encodings, domain, ch)?;
        instrument::end();
        //
        // At this point the s should have an encoding of both their own version and the servers version of the password.
        //

        instrument::end();
        Ok(Self(decoding.hashes[0][1]))
    }

    pub fn evaluator_client(
        password: &[u8],
        number_of_password: u32,
        index: u32,
        ch: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("evaluator_client", E_FUNC_COLOR);

        let (_s, r) = ch;
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Receive the garbled circuit from the other party
        instrument::begin("Receive gc", E_RECV_COLOR);
        let gc = bincode::deserialize(&r.recv()?)?;
        instrument::end();

        // 2. Respond to the OT challenge for the encoding of our copy of the key
        instrument::begin("Build response for OT", E_COMP_COLOR);
        let mut choices = Vec::with_capacity(password_bits);
        for i in 0..password_bytes {
            for j in 0..8 {
                let bit = ((password[i] >> j) & 1) == 1;
                choices.push(bit)
            }
        }
        instrument::end();

        instrument::begin("OT Receiver", E_PROT_COLOR);
        let key_receiver = Receiver {
            bootstrap: Box::new(OTSender),
        };
        let key_encoding = key_receiver.exchange(&choices, ch)?;
        instrument::end();

        instrument::begin("Compute encoded server password", E_COMP_COLOR);
        let input_encoding = key_encoding
            .iter()
            .map(|k| Wire::from_array(util::to_array(k), Domain::Binary))
            .collect();
        instrument::end();

        // 4. Receive and respond to the 1-to-n challenge from the r
        instrument::begin("1-to-n OT Receiver", E_PROT_COLOR);
        let many_receiver = ManyOTReceiver {
            internal_receiver: OTReceiver,
        };
        let domain = log2(number_of_password);
        let encodings = many_receiver.exchange(index, domain, ch)?;
        instrument::end();

        instrument::begin("Encode server version of password", E_COMP_COLOR);
        let database_encoding = wires_from_bytes(encodings.as_slice(), Domain::Binary);
        let input = [database_encoding, input_encoding].concat();
        instrument::end();

        //
        // By now the s should have both the encoding of their own version of their password and the encoding of the servers version of their password
        //

        // 6. Evaluate the circuit
        instrument::begin("Evaluate circuit", E_PROT_COLOR);
        let output = evaluate(&gc, &input);
        instrument::end();

        instrument::end();
        Ok(Self(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    // First (and slower) implementation of garbler_client and evaluator_server
    pub fn garbler_client(password: &[u8], index: u32, number_of_passwords: u32, threshold: u16, channel: &Channel<Vec<u8>>) -> Result<Self, Error> {
        instrument::begin("garbler_client", E_FUNC_COLOR);

        let (sender, _r) = channel;
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit and encode our password
        instrument::begin("Build circuit", E_COMP_COLOR);
        let circuit = build_circuit(password_bits, threshold);
        instrument::end();

        instrument::begin("Garble circuit", E_PROT_COLOR);
        let (gc, encoding, decoding) = garble(&circuit);
        instrument::end();

        instrument::begin("Encode client password", E_COMP_COLOR);
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
        instrument::end();

        instrument::begin("Send garbled circuit", E_SEND_COLOR);
        sender.send(bincode::serialize(&gc)?)?;
        instrument::end();

        instrument::begin("Send encoded password", E_SEND_COLOR);
        sender.send(bincode::serialize(&encoded_password)?)?;
        instrument::end();

        // We now need to do a series of OTs for each possible password in the database for the so
        // that the server/evaluator can obtain an encoding of the password they have in their
        // database corresponding to the client, without knowing who the client is.

        // 2. Prepare keys needed to mask values
        instrument::begin("Prepare keys", E_COMP_COLOR);
        let mut random_keys = Vec::with_capacity(number_of_passwords as usize - 1);
        let mut cancelling_keys = vec![vec![0u8; LENGTH]; password_bits];
        for _ in 0..(number_of_passwords - 2) {
            let mut keys = Vec::with_capacity(password_bits);

            for j in 0..password_bits {
                let mut key = vec![0u8; LENGTH];
                random_bytes(&mut key);

                let cancelling_key = cancelling_keys[j].as_mut_slice();
                xor_bytes_inplace(cancelling_key, &key);

                keys.push(key);
            }

            random_keys.push(keys);
        }
        random_keys.push(cancelling_keys);

        let mut random_key = random_keys.iter();
        let mut keys = Vec::with_capacity(number_of_passwords as usize);
        for i in 0..number_of_passwords {
            if i == index {
                for j in 0..password_bits {
                    keys.push([
                        evaluator_encoding[j][0].clone(),
                        evaluator_encoding[j][1].clone(),
                    ]);
                }
            } else {
                let random = random_key.next().unwrap();
                for j in 0..password_bits {
                    keys.push([random[j].clone(), random[j].clone()]);
                }
            }
        }
        instrument::end();

        // 3. Initiate the OTs for all of the passwords
        instrument::begin("OT Server passwords", E_PROT_COLOR);
        let message = MessagePair::from_zipped(keys.as_slice());
        let sender = Sender {
            bootstrap: Box::new(OTReceiver),
        };
        sender.exchange(&message, channel)?;
        instrument::end();

        //
        // At this point the evaluator should have encodings of both inputs and should evaluate the garbled circuit to retrieve their version of they key.
        //

        instrument::end();
        Ok(Self(decoding.hashes[0][1]))
    }

    pub fn evaluator_server(passwords: &[Vec<u8>], channel: &Channel<Vec<u8>>) -> Result<Self, Error> {
        instrument::begin("evaluator_server", E_FUNC_COLOR);

        let (_, r) = channel;
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Get the garbled circuit and input from the client
        instrument::begin("Receive garbled circuit", E_RECV_COLOR);
        let gc = bincode::deserialize(&r.recv()?)?;
        instrument::end();

        instrument::begin("Receive encoded client password", E_RECV_COLOR);
        let input_encoding: Vec<Wire> = bincode::deserialize(&r.recv()?)?;
        instrument::end();

        instrument::begin("Build vec of choices", E_COMP_COLOR);
        let mut choices = Vec::with_capacity(password_bits * passwords.len());
        for i in 0..passwords.len() {
            for j in 0..password_bytes {
                for k in 0..8 {
                    let bit = ((&passwords[i][j] >> k) & 1) == 1;
                    choices.push(bit)
                }
            }
        }
        instrument::end();

        instrument::begin("OT Server passwords", E_PROT_COLOR);
        let receiver = Receiver {
            bootstrap: Box::new(OTSender),
        };
        let result = receiver.exchange(&choices, channel)?;
        instrument::end();

        // 4. Compute the encoding for the input from the result
        instrument::begin("Compute encoding for server password", E_COMP_COLOR);
        // TODO: Allocate flat, don't push to vec
        let mut encoding_bytes = vec![vec![0u8; LENGTH]; password_bits];
        for i in 0..passwords.len() {
            for j in 0..password_bits {
                xor_bytes_inplace(&mut encoding_bytes[j], &result[i * password_bits + j])
            }
        }

        let mut database_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            let bytes = &encoding_bytes[i];
            let wire = Wire::from_bytes(bytes, Domain::Binary);
            database_encoding.push(wire);
        }
        instrument::end();

        //
        // By now the evaluator should have both the encoding of the users password from the database and the encoding of the password they input
        //

        // 6. Evaluate the circuit
        instrument::begin("Evaluate circuit", E_PROT_COLOR);
        let input = [database_encoding, input_encoding].concat();
        let output = evaluate(&gc, &input);
        instrument::end();

        instrument::end();
        Ok(Self(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    // Second (faster) implementation of garbler_client and evaluator_server
    pub fn garbler_client_v2(password: &[u8], index: u32, number_of_passwords: u32, threshold: u16, channel: &Channel<Vec<u8>>) -> Result<Self, Error> {
        instrument::begin("garbler_client", E_FUNC_COLOR);

        let (sender, _r) = channel;
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit and encode our password
        instrument::begin("Build circuit", E_COMP_COLOR);
        let circuit = build_circuit_v3(password_bits, threshold);
        instrument::end();

        instrument::begin("Garble circuit", E_PROT_COLOR);
        let (gc, encoding, decoding) = garble(&circuit);
        instrument::end();

        instrument::begin("Encode client password", E_COMP_COLOR);
        let encoding = BinaryEncodingKey::from(encoding).zipped();
        let mut garbler_input = Vec::with_capacity(password_bits);
        for i in 0..password_bytes {
            for j in 0..8 {
                let bit_index = (i * 8 + j) as usize;
                let bit = (((password[i] >> j) & 1) == 1) as usize;

                let encoded = &encoding[password_bits * 2 + bit_index][bit];
                garbler_input.push(encoded.clone());
            }
        }
        instrument::end();

        instrument::begin("Send garbled circuit", E_SEND_COLOR);
        sender.send(bincode::serialize(&gc)?)?;
        instrument::end();

        instrument::begin("Send encoded password", E_SEND_COLOR);
        sender.send(bincode::serialize(&garbler_input)?)?;
        instrument::end();

        // 2. OT Encoding of the mask
        instrument::begin("OT Encoding of mask", E_PROT_COLOR);
        let mut mask_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            let bit_encoding = [
                encoding[password_bits + i][0].to_bytes().to_vec(),
                encoding[password_bits + i][1].to_bytes().to_vec(),
            ];
            mask_encoding.push(bit_encoding);
        }

        let message = MessagePair::from_zipped(mask_encoding.as_slice());
        let ot = Sender {
            bootstrap: Box::new(OTReceiver),
        };
        ot.exchange(&message, channel)?;
        instrument::end();

        // 3. Do a 1-to-n OT to get a masked version of the servers password corresponding to this client
        instrument::begin("1-to-n OT Masked password", E_COMP_COLOR);
        let many_receiver = ManyOTReceiver {
            internal_receiver: OTReceiver,
        };
        let domain = log2(number_of_passwords);
        let masked_password = many_receiver.exchange(index, domain, channel)?;
        instrument::end();

        instrument::begin("Encode Masked password", E_COMP_COLOR);
        let encoding_length = encoding[0][0].to_bytes().len();
        let mut evaluator_encoding = vec![0u8; password_bits * encoding_length];
        for i in 0..password_bits {
            let byte = masked_password[i / 8];
            let bit = (byte >> i % 8) & 1;

            let encoded_row = unsafe { vector_row_mut(&mut evaluator_encoding, i, encoding_length) };
            xor_bytes_inplace(encoded_row, encoding[i][bit as usize].to_bytes().as_slice());
        }
        instrument::end();

        instrument::begin("Send encoding of masked password", E_SEND_COLOR);
        sender.send_raw(evaluator_encoding.as_slice())?;
        instrument::end();

        instrument::end();
        Ok(Self(decoding.hashes[0][1]))
    }

    pub fn evaluator_server_v2(passwords: &[Vec<u8>], channel: &Channel<Vec<u8>>) -> Result<Self, Error> {
        instrument::begin("evaluator_server", E_FUNC_COLOR);

        let (_, r) = channel;
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Get the garbled circuit and input from the client
        instrument::begin("Receive garbled circuit", E_RECV_COLOR);
        let gc = bincode::deserialize(&r.recv()?)?;
        instrument::end();

        instrument::begin("Receive encoded client password", E_RECV_COLOR);
        let client_encoding: Vec<Wire> = bincode::deserialize(&r.recv()?)?;
        instrument::end();

        // 3. Mask all server passwords and get encoding of mask
        instrument::begin("Generate mask", E_COMP_COLOR);
        let mut mask = vec![0u8; password_bytes];
        random_bytes(&mut mask);

        let mut mask_choices = vec![false; password_bits];
        for i in 0..password_bytes {
            let byte = mask[i];
            for b in 0..8 {
                let choice = ((byte >> b) & 1) == 1;
                mask_choices[i * 8 + b] = choice;
            }
        }
        instrument::end();

        instrument::begin("Mask server passwords", E_COMP_COLOR);
        let mut masked_passwords = vec![vec![0u8; password_bytes]; passwords.len()];
        for i in 0..passwords.len() {
            let masked_password = masked_passwords[i].as_mut_slice();
            xor_bytes_inplace(masked_password, mask.as_slice());

            let password = passwords[i].as_slice();
            xor_bytes_inplace(masked_password, password);
        }
        instrument::end();

        instrument::begin("OT Mask", E_PROT_COLOR);
        let ot = Receiver {
            bootstrap: Box::new(OTSender)
        };
        let encoded_mask = ot.exchange(mask_choices.as_slice(), channel)?;
        instrument::end();

        // 4. 1-to-n OT the masked password to the client
        instrument::begin("1-to-n OT of Masked password", E_PROT_COLOR);
        let many_sender = ManyOTSender {
            interal_sender: OTSender
        };
        let domain = log2(passwords.len());
        many_sender.exchange(masked_passwords.as_slice(), domain, channel)?;
        instrument::end();

        instrument::begin("Receive encoded client password", E_RECV_COLOR);
        let server_encoded = r.recv_raw()?;
        instrument::end();

        //
        // By now the evaluator should have both the encoding of the users password from the database and the encoding of the password they input
        //

        instrument::begin("Build encodings from data", E_COMP_COLOR);
        let mut mask_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            let encoded_bytes = &encoded_mask[i];
            mask_encoding.push(Wire::from_bytes(encoded_bytes, Domain::Binary));
        }

        let encoding_length = encoded_mask[0].len();
        let mut server_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            let encoded_bytes = unsafe { vector_row(&server_encoded, i, encoding_length)};
            server_encoding.push(Wire::from_bytes(encoded_bytes, Domain::Binary));
        }
        instrument::end();

        // 6. Evaluate the circuit
        instrument::begin("Evaluate circuit", E_PROT_COLOR);
        let input = [server_encoding, mask_encoding, client_encoding].concat();
        let output = evaluate(&gc, &input);
        instrument::end();

        instrument::end();
        Ok(Self(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    pub fn combine(self, other: Self) -> Key {
        Key(xor(self.0, other.0))
    }
}

fn print_bytes(bytes: &[u8], newline: bool) {
    for i in 0..bytes.len() {
        print!("{:02X} ", bytes[i]);
    }

    if newline
    {
        println!();
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
        let index = 2u32;
        let password = passwords[index as usize].clone();
        let number_of_passwords = passwords.len() as u32;
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
        let number_of_passwords = passwords.len() as u32;
        let index = 1u32;
        let password = passwords[index as usize].clone();
        let threshold = 0;

        // Do the thing
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s2, r1);
        let ch2 = (s1, r2);
        let h1 = thread::spawn(move || {
            // Party 1

            OneOfManyKey::garbler_client(&password, index, number_of_passwords, threshold, &ch1)
                .unwrap()
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
    fn test_fpake_one_of_many_client_garbler_v2() {
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let number_of_passwords = passwords.len() as u32;
        let index = 1u32;
        let password = passwords[index as usize].clone();
        let threshold = 2;

        // Do the thing
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let client_channel = (s2, r1);
        let server_channel = (s1, r2);

        let client = thread::spawn(move || {
            OneOfManyKey::garbler_client_v2(&password, index, number_of_passwords, threshold, &client_channel).unwrap()
        });

        let server = thread::spawn(move || {
            OneOfManyKey::evaluator_server_v2(&passwords, &server_channel).unwrap()
        });

        let k1 = client.join().unwrap();
        let k2 = server.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many() {
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let passwords_2 = passwords.clone();
        let number_of_passwords = passwords.len() as u32;
        let index = 1u32;
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
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 1
            let k1 = OneOfManyKey::evaluator_client(&password_2, number_of_passwords, index, &ch2).unwrap();
            let k2 = OneOfManyKey::garbler_client(
                &password,
                index,
                number_of_passwords,
                threshold,
                &ch2,
            ).unwrap();
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_fuzzy() {
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let passwords_2 = passwords.clone();
        let number_of_passwords = passwords.len() as u32;
        let index = 1u32;
        let mut password = passwords[index as usize].clone();
        let mut password_2 = password.clone();

        // Flip 2 bits in each copy of the client password
        password[0] ^= 0x88;
        password_2[0] ^= 0x88;

        let threshold = 2;

        // Do the thing
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s2, r1);
        let ch2 = (s1, r2);
        let h1 = thread::spawn(move || {
            // Party 1
            let k1 = OneOfManyKey::garbler_server(&passwords, threshold, &ch1).unwrap();
            let k2 = OneOfManyKey::evaluator_server(&passwords_2, &ch1).unwrap();
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 1
            let k1 = OneOfManyKey::evaluator_client(&password_2, number_of_passwords, index, &ch2).unwrap();
            let k2 = OneOfManyKey::garbler_client(
                &password,
                index,
                number_of_passwords,
                threshold,
                &ch2,
            ).unwrap();
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    fn test_masking_circuit() {
        use rand::Rng;
        let rng = &mut rand::thread_rng();
        let p0 : [bool; 16] = rng.gen();
        let p1 : [bool; 16] = p0.clone();

        let mask : [bool; 16] = rng.gen();

        let masked_p0 : [bool; 16] = itertools::izip!(p0, mask.clone())
            .map(|(a,b)| a^b)
            .collect::<Vec<bool>>()
            .try_into().unwrap();

        let circuit = build_circuit_v3(16, 1);
        let (gc, enc, dec) = garble(&circuit);

        let input = &[p1, masked_p0, mask].concat();
        let enc =  BinaryEncodingKey::from(enc);
        let input = enc.encode(input);
        let res = evaluate(&gc, &input);
        let res = decode(&dec, &res).unwrap();

        println!("{:?}", res);
        assert_eq!(res[0], 1);
    }

    #[test]
    fn test_fpake_one_of_many_v2() {
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let passwords_2 = passwords.clone();
        let number_of_passwords = passwords.len() as u32;
        let index = 1u32;
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
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 1
            let k1 = OneOfManyKey::evaluator_client(&password_2, number_of_passwords, index, &ch2).unwrap();
            let k2 = OneOfManyKey::garbler_client_v2(
                &password,
                index,
                number_of_passwords,
                threshold,
                &ch2,
            ).unwrap();
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
