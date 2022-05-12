use crate::circuit::*;
use crate::common::*;
use crate::fpake::{HalfKey, Key};
use crate::garble::*;
use crate::instrument;
use crate::instrument::{E_COMP_COLOR, E_FUNC_COLOR, E_PROT_COLOR, E_RECV_COLOR, E_SEND_COLOR};
use crate::ot::apricot_avx2::{Receiver, Sender};
use crate::ot::chou_orlandi::Receiver as OTReceiver;
use crate::ot::chou_orlandi::Sender as OTSender;
use crate::ot::common::Message as MessagePair;
use crate::ot::common::*;
use crate::ot::one_of_many::*;
use crate::util;
use crate::util::*;
use crate::wires::*;

#[inline]
fn payload_to_encoding(payload: Payload, bit_count: usize) -> Vec<Wire> {
    let mut encoding = Vec::with_capacity(bit_count);
    for i in 0..bit_count {
        let encoded_bytes = &payload[i];
        encoding.push(Wire::from_bytes(encoded_bytes, Domain::Binary));
    }

    return encoding;
}

#[inline]
fn bytes_to_encoding(bytes: &[u8], bit_count: usize, encoded_size: usize) -> Vec<Wire> {
    let mut encoding = Vec::with_capacity(bit_count);
    for i in 0..bit_count {
        let encoded_bytes = unsafe { vector_row(&bytes, i, encoded_size) };
        encoding.push(Wire::from_bytes(encoded_bytes, Domain::Binary));
    }

    return encoding;
}

fn print_bytes(bytes: &[u8], newline: bool) {
    for i in 0..bytes.len() {
        print!("{:02X} ", bytes[i]);
    }

    if newline {
        println!();
    }
}

fn wires_from_bytes(bytes: &[u8], domain: Domain) -> Vec<Wire> {
    let mut wires = Vec::with_capacity(bytes.len() / LENGTH);
    for chunk in bytes.chunks_exact(LENGTH) {
        wires.push(Wire::from_array(util::to_array(chunk), domain));
    }

    wires
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct OneOfManyKey(WireBytes);

impl OneOfManyKey {
    // First (and slow) implementation of garbler_server and evaluator_client
    pub fn garbler_server(
        passwords: &[Vec<u8>],
        threshold: u16,
        channel: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("Garbler: Server", E_FUNC_COLOR);

        let (sender, _) = channel;
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit
        instrument::begin("Build Circuit", E_COMP_COLOR);
        let circuit = build_circuit(password_bits, threshold);
        instrument::end();

        instrument::begin("Garble circuit", E_PROT_COLOR);
        let (garbled_circuit, encoding, decoding) = garble(&circuit);
        let encoding = BinaryEncodingKey::from(encoding).zipped();
        instrument::end();

        instrument::begin("S: Garbled circuit", E_SEND_COLOR);
        sender.send_raw(&bincode::serialize(&garbled_circuit)?)?;
        instrument::end();

        // 2. Use regular OT to get the encoded password for the server
        instrument::begin("Encoding key for client password", E_COMP_COLOR);
        let mut client_password_key = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            client_password_key.push([
                encoding[i][0].to_bytes().to_vec(),
                encoding[i][1].to_bytes().to_vec(),
            ])
        }
        instrument::end();

        instrument::begin("OT: Client password", E_PROT_COLOR);
        let client_password_message = MessagePair::from_zipped(client_password_key.as_slice());
        let client_password_ot = Sender {
            bootstrap: Box::new(OTReceiver),
        };
        client_password_ot.exchange(&client_password_message, channel)?;
        instrument::end();

        // 4. Encode all passwords
        instrument::begin("Encode passwords", E_COMP_COLOR);
        let domain = log2(passwords.len());
        let mut server_encodings: Vec<Vec<u8>> = Vec::with_capacity(passwords.len());
        let encoding_key: Vec<_> = encoding[password_bits..]
            .to_vec()
            .iter()
            .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
            .collect();
        for password in passwords {
            let mut encoding = Vec::with_capacity(password_bits);
            for i in 0..password_bytes {
                for j in 0..8 {
                    let bit_index = (i * 8 + j) as usize;
                    let bit = (((password[i] >> j) & 1) == 1) as usize;

                    let encoded = &encoding_key[bit_index][bit];
                    encoding.extend(encoded);
                }
            }

            server_encodings.push(encoding);
        }
        instrument::end();

        // 5. Send 1-to-n challenge and Y to s and get response
        instrument::begin("1-to-n OT: Server password", E_PROT_COLOR);
        let server_password_ot = ManyOTSender {
            interal_sender: OTSender,
        };
        server_password_ot.exchange(&server_encodings, domain, channel)?;
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
        channel: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("Evaluator: Client", E_FUNC_COLOR);

        let (_, receiver) = channel;
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Receive the garbled circuit from the other party
        instrument::begin("R: Garbled circuit", E_RECV_COLOR);
        let garbled_circuit = bincode::deserialize(&receiver.recv_raw()?)?;
        instrument::end();

        // 2. Respond to the OT challenge for the encoding of our copy of the key
        instrument::begin("OT: Client password", E_PROT_COLOR);
        let mut choices = Vec::with_capacity(password_bits);
        for i in 0..password_bytes {
            for j in 0..8 {
                let bit = ((password[i] >> j) & 1) == 1;
                choices.push(bit)
            }
        }

        let client_password_ot = Receiver {
            bootstrap: Box::new(OTSender),
        };
        let client_password = client_password_ot.exchange(&choices, channel)?;
        instrument::end();

        // 4. Receive and respond to the 1-to-n challenge from the r
        instrument::begin("1-to-n OT: Server password", E_PROT_COLOR);
        let many_receiver = ManyOTReceiver {
            internal_receiver: OTReceiver,
        };
        let domain = log2(number_of_password);
        let server_password_ot = many_receiver.exchange(index, domain, channel)?;
        instrument::end();

        instrument::begin("Build encodings", E_COMP_COLOR);
        let client_encoding = client_password
            .iter()
            .map(|k| Wire::from_array(util::to_array(k), Domain::Binary))
            .collect();
        let server_encoding = wires_from_bytes(server_password_ot.as_slice(), Domain::Binary);
        let input = [server_encoding, client_encoding].concat();
        instrument::end();

        //
        // By now the s should have both the encoding of their own version of their password and the encoding of the servers version of their password
        //

        // 6. Evaluate the circuit
        instrument::begin("Evaluate circuit", E_PROT_COLOR);
        let output = evaluate(&garbled_circuit, &input);
        instrument::end();

        instrument::end();
        Ok(Self(hash!(
            (garbled_circuit.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    // Second (faster) implementation of garbler_server and evaluator_client
    pub fn garbler_server_v2(
        passwords: &[Vec<u8>],
        threshold: u16,
        channel: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("Garbler: Server v2", E_FUNC_COLOR);

        let (sender, _s) = channel;
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit
        instrument::begin("Build circuit", E_COMP_COLOR);
        let circuit = build_circuit_v2(password_bits, threshold);
        instrument::end();

        instrument::begin("Garble circuit", E_PROT_COLOR);
        let (garbled_circuit, encoding, decoding) = garble(&circuit);
        let encoding = BinaryEncodingKey::from(encoding).zipped();
        instrument::end();

        instrument::begin("S: garbled circuit", E_SEND_COLOR);
        sender.send_raw(&bincode::serialize(&garbled_circuit)?)?;
        instrument::end();

        // 2. OT for encoding of client password
        instrument::begin("Encode client password", E_COMP_COLOR);
        let mut client_password_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            client_password_encoding.push([
                encoding[i][0].to_bytes().to_vec(),
                encoding[i][1].to_bytes().to_vec(),
            ])
        }
        let client_encoding_message = MessagePair::from_zipped(client_password_encoding.as_slice());
        let client_encoding_ot = Sender {
            bootstrap: Box::new(OTReceiver),
        };
        instrument::end();

        instrument::begin("OT: Client password", E_PROT_COLOR);
        client_encoding_ot.exchange(&client_encoding_message, channel)?;
        instrument::end();

        // 3. Generate and encode the mask
        instrument::begin("Generate mask", E_COMP_COLOR);
        let mut mask = vec![0u8; password_bytes];
        random_bytes(&mut mask);
        instrument::end();

        instrument::begin("Encode mask", E_COMP_COLOR);
        let mut encoded_mask = vec![0u8; password_bits * LENGTH];
        for i in 0..password_bytes {
            let mask_byte = mask[i];
            for b in 0..8 {
                let bit_idx = i * 8 + b;
                let mask_bit = ((mask_byte >> b) & 1) as usize;
                let key = &encoding[password_bits + bit_idx][mask_bit].to_bytes();

                let mut encoded = unsafe { vector_row_mut(&mut encoded_mask, bit_idx, LENGTH) };
                xor_bytes_inplace(&mut encoded, key);
            }
        }
        instrument::end();

        instrument::begin("S: Encoded mask", E_SEND_COLOR);
        sender.send_raw(&encoded_mask)?;
        instrument::end();

        // 4. Mask all passwords
        instrument::begin("Mask passwords", E_COMP_COLOR);
        let password_count = passwords.len();
        let domain = log2(password_count);
        let mut masked_passwords = vec![vec![0u8; password_bytes]; password_count];
        for i in 0..password_count {
            xor_bytes_inplace(&mut masked_passwords[i], &mask);
            xor_bytes_inplace(&mut masked_passwords[i], &passwords[i]);
        }
        instrument::end();

        // 5. 1-n-OT masked server password to client
        instrument::begin("OT: Masked password", E_PROT_COLOR);
        let masked_passwords_ot = ManyOTSender {
            interal_sender: OTSender,
        };
        masked_passwords_ot.exchange(&masked_passwords, domain, channel)?;
        instrument::end();

        // 6. OT For encoding of masked server password
        instrument::begin("Encode masked password", E_COMP_COLOR);
        let mut masked_password_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            masked_password_encoding.push([
                encoding[password_bits * 2 + i][0].to_bytes().to_vec(),
                encoding[password_bits * 2 + i][1].to_bytes().to_vec(),
            ])
        }
        let masked_encoding_message = MessagePair::from_zipped(masked_password_encoding.as_slice());
        let masked_encoding_ot = Sender {
            bootstrap: Box::new(OTReceiver),
        };
        instrument::end();

        instrument::begin("OT: Encoded masked password", E_PROT_COLOR);
        masked_encoding_ot.exchange(&masked_encoding_message, channel)?;
        instrument::end();

        //
        // At this point the s should have an encoding of both their own version and the servers version of the password.
        //

        instrument::end();
        Ok(Self(decoding.hashes[0][1]))
    }
    pub fn evaluator_client_v2(
        password: &[u8],
        number_of_password: u32,
        index: u32,
        channel: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("Evaluator: Client v2", E_FUNC_COLOR);

        let (_, receiver) = channel;
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Receive the garbled circuit from the other party
        instrument::begin("R: garbled circuit", E_RECV_COLOR);
        let gc = bincode::deserialize(&receiver.recv_raw()?)?;
        instrument::end();

        // 2. OT Encoding of client password
        instrument::begin("OT: Client password", E_PROT_COLOR);
        let mut password_choices = Vec::with_capacity(password_bits);
        for i in 0..password_bytes {
            for j in 0..8 {
                let bit = ((password[i] >> j) & 1) == 1;
                password_choices.push(bit)
            }
        }

        let password_receiver = Receiver {
            bootstrap: Box::new(OTSender),
        };
        let client_encoding = password_receiver.exchange(&password_choices, channel)?;
        instrument::end();

        // 3. Receive encoded mask
        instrument::begin("Receive encoded mask", E_RECV_COLOR);
        let encoded_mask_bytes = receiver.recv_raw()?;
        instrument::end();

        // 4. Receive masked server password
        instrument::begin("OT: Masked password", E_PROT_COLOR);
        let many_receiver = ManyOTReceiver {
            internal_receiver: OTReceiver,
        };
        let domain = log2(number_of_password);
        let masked_password = many_receiver.exchange(index, domain, channel)?;
        instrument::end();

        // 5. Encode masked password
        instrument::begin("OT: Encoded masked password", E_PROT_COLOR);
        let mut masked_choices = Vec::with_capacity(password_bits);
        for i in 0..password_bytes {
            for j in 0..8 {
                let bit = ((masked_password[i] >> j) & 1) == 1;
                masked_choices.push(bit)
            }
        }

        let password_receiver = Receiver {
            bootstrap: Box::new(OTSender),
        };
        let masked_encoding = password_receiver.exchange(&masked_choices, channel)?;
        instrument::end();

        //
        // By now the s should have both the encoding of their own version of their password and the encoding of the servers version of their password
        //

        // 7. Build encodings
        instrument::begin("Building encodings", E_COMP_COLOR);
        let encoded_row_length = masked_encoding[0].len();
        let client_encoding = payload_to_encoding(client_encoding, password_bits);
        let mask_encoding =
            bytes_to_encoding(&encoded_mask_bytes, password_bits, encoded_row_length);
        let server_encoding = payload_to_encoding(masked_encoding, password_bits);
        instrument::end();

        // 6. Evaluate the circuit
        instrument::begin("Evaluate circuit", E_PROT_COLOR);
        let input = [client_encoding, mask_encoding, server_encoding].concat();
        let output = evaluate(&gc, &input);
        instrument::end();

        instrument::end();
        Ok(Self(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    // First (and slow) implementation of garbler_client and evaluator_server
    pub fn garbler_client(
        password: &[u8],
        index: u32,
        number_of_passwords: u32,
        threshold: u16,
        channel: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("Garbler: Client", E_FUNC_COLOR);

        let (sender, _) = channel;
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit and encode our password
        instrument::begin("Build circuit", E_COMP_COLOR);
        let circuit = build_circuit(password_bits, threshold);
        instrument::end();

        instrument::begin("Garble circuit", E_PROT_COLOR);
        let (garbled_circuit, encoding, decoding) = garble(&circuit);
        instrument::end();

        instrument::begin("Encode password", E_COMP_COLOR);
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

        instrument::begin("S: Garbled circuit", E_SEND_COLOR);
        sender.send_raw(&bincode::serialize(&garbled_circuit)?)?;
        instrument::end();

        instrument::begin("S: Encoded password", E_SEND_COLOR);
        sender.send_raw(&bincode::serialize(&encoded_password)?)?;
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
        instrument::begin("OT: Server passwords", E_PROT_COLOR);
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
    pub fn evaluator_server(
        passwords: &[Vec<u8>],
        channel: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("Evaluator: Server", E_FUNC_COLOR);

        let (_, receiver) = channel;
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Get the garbled circuit and input from the client
        instrument::begin("R: Garbled circuit", E_RECV_COLOR);
        let garbled_circuit = bincode::deserialize(&receiver.recv_raw()?)?;
        instrument::end();

        instrument::begin("R: Client password", E_RECV_COLOR);
        let input_encoding: Vec<Wire> = bincode::deserialize(&receiver.recv_raw()?)?;
        instrument::end();

        instrument::begin("OT: Server passwords", E_PROT_COLOR);
        let mut choices = Vec::with_capacity(password_bits * passwords.len());
        for i in 0..passwords.len() {
            for j in 0..password_bytes {
                for k in 0..8 {
                    let bit = ((&passwords[i][j] >> k) & 1) == 1;
                    choices.push(bit)
                }
            }
        }

        let server_password_ot = Receiver {
            bootstrap: Box::new(OTSender),
        };
        let result = server_password_ot.exchange(&choices, channel)?;
        instrument::end();

        // 4. Compute the encoding for the input from the result
        instrument::begin("Encode server password", E_COMP_COLOR);
        // TODO: Allocate flat, don't push to vec
        let mut encoding_bytes = vec![vec![0u8; LENGTH]; password_bits];
        for i in 0..passwords.len() {
            for j in 0..password_bits {
                xor_bytes_inplace(&mut encoding_bytes[j], &result[i * password_bits + j])
            }
        }

        let mut server_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            let bytes = &encoding_bytes[i];
            let wire = Wire::from_bytes(bytes, Domain::Binary);
            server_encoding.push(wire);
        }
        instrument::end();

        //
        // By now the evaluator should have both the encoding of the users password from the database and the encoding of the password they input
        //

        // 6. Evaluate the circuit
        instrument::begin("Evaluate circuit", E_PROT_COLOR);
        let input = [server_encoding, input_encoding].concat();
        let output = evaluate(&garbled_circuit, &input);
        instrument::end();

        instrument::end();
        Ok(Self(hash!(
            (garbled_circuit.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    // Second (faster) implementation of garbler_client and evaluator_server
    pub fn garbler_client_v2(
        password: &[u8],
        index: u32,
        number_of_passwords: u32,
        threshold: u16,
        channel: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("Garbler: Client v2", E_FUNC_COLOR);

        let (sender, _) = channel;
        let password_bytes = password.len();
        let password_bits = password_bytes * 8;

        // 1. Garble the circuit and encode our password
        instrument::begin("Build circuit", E_COMP_COLOR);
        let circuit = build_circuit_v2(password_bits, threshold);
        instrument::end();

        instrument::begin("Garble circuit", E_PROT_COLOR);
        let (garbled_circuit, encoding, decoding) = garble(&circuit);
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

        instrument::begin("S: garbled circuit", E_SEND_COLOR);
        sender.send_raw(&bincode::serialize(&garbled_circuit)?)?;
        instrument::end();

        instrument::begin("S: Encoded password", E_SEND_COLOR);
        sender.send_raw(&bincode::serialize(&garbler_input)?)?;
        instrument::end();

        // 2. OT Encoding of the mask
        instrument::begin("Encode mask", E_COMP_COLOR);
        let mut mask_encoding = Vec::with_capacity(password_bits);
        for i in 0..password_bits {
            let bit_encoding = [
                encoding[password_bits + i][0].to_bytes().to_vec(),
                encoding[password_bits + i][1].to_bytes().to_vec(),
            ];
            mask_encoding.push(bit_encoding);
        }
        instrument::end();

        instrument::begin("OT: Encoded Mask", E_PROT_COLOR);
        let message = MessagePair::from_zipped(mask_encoding.as_slice());
        let ot = Sender {
            bootstrap: Box::new(OTReceiver),
        };
        ot.exchange(&message, channel)?;
        instrument::end();

        // 3. Do a 1-to-n OT to get a masked version of the servers password corresponding to this client
        instrument::begin("1-to-n OT: Masked password", E_COMP_COLOR);
        let many_receiver = ManyOTReceiver {
            internal_receiver: OTReceiver,
        };
        let domain = log2(number_of_passwords);
        let masked_password = many_receiver.exchange(index, domain, channel)?;
        instrument::end();

        instrument::begin("Encode masked password", E_COMP_COLOR);
        let encoding_length = encoding[0][0].to_bytes().len();
        let mut evaluator_encoding = vec![0u8; password_bits * encoding_length];
        for i in 0..password_bits {
            let byte = masked_password[i / 8];
            let bit = (byte >> i % 8) & 1;

            let encoded_row =
                unsafe { vector_row_mut(&mut evaluator_encoding, i, encoding_length) };
            xor_bytes_inplace(encoded_row, encoding[i][bit as usize].to_bytes().as_slice());
        }
        instrument::end();

        instrument::begin("S: Masked password", E_SEND_COLOR);
        sender.send_raw(evaluator_encoding.as_slice())?;
        instrument::end();

        instrument::end();
        Ok(Self(decoding.hashes[0][1]))
    }
    pub fn evaluator_server_v2(
        passwords: &[Vec<u8>],
        channel: &Channel<Vec<u8>>,
    ) -> Result<Self, Error> {
        instrument::begin("Evaluator: Server v2", E_FUNC_COLOR);

        let (_, receiver) = channel;
        let password_bytes = passwords[0].len();
        let password_bits = password_bytes * 8;

        // 1. Get the garbled circuit and input from the client
        instrument::begin("R: Garbled circuit", E_RECV_COLOR);
        let garbled_circuit = bincode::deserialize(&receiver.recv_raw()?)?;
        instrument::end();

        instrument::begin("R: Client password", E_RECV_COLOR);
        let client_encoding: Vec<Wire> = bincode::deserialize(&receiver.recv_raw()?)?;
        instrument::end();

        // 3. Mask all server passwords and get encoding of mask
        instrument::begin("Generate mask", E_COMP_COLOR);
        let mut mask = vec![0u8; password_bytes];
        random_bytes(&mut mask);

        // TODO: Move this into a function, we can reuse it!
        let mut mask_choices = vec![false; password_bits];
        for i in 0..password_bytes {
            let byte = mask[i];
            for b in 0..8 {
                let choice = ((byte >> b) & 1) == 1;
                mask_choices[i * 8 + b] = choice;
            }
        }
        instrument::end();

        instrument::begin("Mask passwords", E_COMP_COLOR);
        let mut masked_passwords = vec![vec![0u8; password_bytes]; passwords.len()];
        for i in 0..passwords.len() {
            let masked_password = masked_passwords[i].as_mut_slice();
            xor_bytes_inplace(masked_password, mask.as_slice());

            let password = passwords[i].as_slice();
            xor_bytes_inplace(masked_password, password);
        }
        instrument::end();

        instrument::begin("OT: Encoded Mask", E_PROT_COLOR);
        let encoded_mask_ot = Receiver {
            bootstrap: Box::new(OTSender),
        };
        let encoded_mask = encoded_mask_ot.exchange(mask_choices.as_slice(), channel)?;
        instrument::end();

        // 4. 1-to-n OT the masked password to the client
        instrument::begin("1-to-n OT: Masked password", E_PROT_COLOR);
        let many_sender = ManyOTSender {
            interal_sender: OTSender,
        };
        let domain = log2(passwords.len());
        many_sender.exchange(masked_passwords.as_slice(), domain, channel)?;
        instrument::end();

        instrument::begin("R: Encoded masked password", E_RECV_COLOR);
        let server_encoded = receiver.recv_raw()?;
        instrument::end();

        //
        // By now the evaluator should have both the encoding of the users password from the database and the encoding of the password they input
        //

        instrument::begin("Build encodings", E_COMP_COLOR);
        let encoded_row_length = encoded_mask[0].len();
        let mask_encoding = payload_to_encoding(encoded_mask, password_bits);
        let server_encoding = bytes_to_encoding(&server_encoded, password_bits, encoded_row_length);
        instrument::end();

        // 6. Evaluate the circuit
        instrument::begin("Evaluate circuit", E_PROT_COLOR);
        let input = [server_encoding, mask_encoding, client_encoding].concat();
        let output = evaluate(&garbled_circuit, &input);
        instrument::end();

        instrument::end();
        instrument::end();
        Ok(Self(hash!(
            (garbled_circuit.circuit.num_wires - 1).to_be_bytes(),
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
    fn test_fpake_one_of_many_server_garbler_v2() {
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
            OneOfManyKey::garbler_server_v2(&passwords, threshold, &ch1).unwrap()
        });

        let h2 = thread::spawn(move || {
            // Party 1
            OneOfManyKey::evaluator_client_v2(&password, number_of_passwords, index, &ch2).unwrap()
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
            OneOfManyKey::garbler_client_v2(
                &password,
                index,
                number_of_passwords,
                threshold,
                &client_channel,
            )
            .unwrap()
        });

        let server = thread::spawn(move || {
            OneOfManyKey::evaluator_server_v2(&passwords, &server_channel).unwrap()
        });

        let k1 = client.join().unwrap();
        let k2 = server.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_v1() {
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
            let k1 = OneOfManyKey::evaluator_client(&password_2, number_of_passwords, index, &ch2)
                .unwrap();
            let k2 = OneOfManyKey::garbler_client(
                &password,
                index,
                number_of_passwords,
                threshold,
                &ch2,
            )
            .unwrap();
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_v1_fuzzy() {
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
            let k1 = OneOfManyKey::evaluator_client(&password_2, number_of_passwords, index, &ch2)
                .unwrap();
            let k2 = OneOfManyKey::garbler_client(
                &password,
                index,
                number_of_passwords,
                threshold,
                &ch2,
            )
            .unwrap();
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_v1_v2() {
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
            let k1 = OneOfManyKey::evaluator_client(&password_2, number_of_passwords, index, &ch2)
                .unwrap();
            let k2 = OneOfManyKey::garbler_client_v2(
                &password,
                index,
                number_of_passwords,
                threshold,
                &ch2,
            )
            .unwrap();
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_v2_v1() {
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
            let k1 = OneOfManyKey::garbler_server_v2(&passwords, threshold, &ch1).unwrap();
            let k2 = OneOfManyKey::evaluator_server(&passwords_2, &ch1).unwrap();
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 1
            let k1 =
                OneOfManyKey::evaluator_client_v2(&password_2, number_of_passwords, index, &ch2)
                    .unwrap();
            let k2 = OneOfManyKey::garbler_client(
                &password,
                index,
                number_of_passwords,
                threshold,
                &ch2,
            )
            .unwrap();
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
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
            let k1 = OneOfManyKey::garbler_server_v2(&passwords, threshold, &ch1).unwrap();
            let k2 = OneOfManyKey::evaluator_server_v2(&passwords_2, &ch1).unwrap();
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 1
            let k1 =
                OneOfManyKey::evaluator_client_v2(&password_2, number_of_passwords, index, &ch2)
                    .unwrap();
            let k2 = OneOfManyKey::garbler_client_v2(
                &password,
                index,
                number_of_passwords,
                threshold,
                &ch2,
            )
            .unwrap();
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_masking_circuit() {
        use rand::Rng;
        let rng = &mut rand::thread_rng();
        let p0: [bool; 16] = rng.gen();
        let p1: [bool; 16] = p0.clone();

        let mask: [bool; 16] = rng.gen();

        let masked_p0: [bool; 16] = itertools::izip!(p0, mask.clone())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<bool>>()
            .try_into()
            .unwrap();

        let circuit = build_circuit_v2(16, 1);
        let (gc, enc, dec) = garble(&circuit);

        let input = &[p1, masked_p0, mask].concat();
        let enc = BinaryEncodingKey::from(enc);
        let input = enc.encode(input);
        let res = evaluate(&gc, &input);
        let res = decode(&dec, &res).unwrap();

        println!("{:?}", res);
        assert_eq!(res[0], 1);
    }
}
