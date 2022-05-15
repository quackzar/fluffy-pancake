use crate::circuit::*;
use crate::common::*;
use crate::fpake::{HalfKey, Key};
use crate::garble::*;
use crate::instrument;
use crate::instrument::{E_COMP_COLOR, E_FUNC_COLOR, E_PROT_COLOR, E_RECV_COLOR, E_SEND_COLOR};
use crate::ot::apricot_avx2::{Receiver, Sender};
use crate::ot::chou_orlandi;
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

// Bob / server is Garbler
impl OneOfManyKey {
    // Third (and slightly faster) implementation of garbelr_server and evaluator_client
    pub fn garbler_server_v3(
        passwords: &[Vec<u8>],
        threshold: u16,
        channel: &TChannel,
    ) -> Result<(Self, Vec<u8>), Error> {
        instrument::begin("Garbler: Server v3", E_FUNC_COLOR);

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
            bootstrap: Box::new(chou_orlandi::Receiver),
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
            interal_sender: chou_orlandi::Sender,
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
            bootstrap: Box::new(chou_orlandi::Receiver),
        };
        instrument::end();

        instrument::begin("OT: Encoded masked password", E_PROT_COLOR);
        masked_encoding_ot.exchange(&masked_encoding_message, channel)?;
        instrument::end();

        //
        // At this point the s should have an encoding of both their own version and the servers version of the password.
        //

        instrument::end();
        let result = (Self(decoding.hashes[0][1]), mask);
        Ok(result)
    }
    pub fn evaluator_client_v3(
        password: &[u8],
        number_of_password: u32,
        index: u32,
        channel: &TChannel,
    ) -> Result<(Self, Vec<u8>), Error> {
        instrument::begin("Evaluator: Client v3", E_FUNC_COLOR);

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
            bootstrap: Box::new(chou_orlandi::Sender),
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
            internal_receiver: chou_orlandi::Receiver,
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
            bootstrap: Box::new(chou_orlandi::Sender),
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
        let hash = hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        );
        let result = (Self(hash), masked_password);
        Ok(result)
    }
    // Third (and slightly faster) implementation of garbler_client and evaluator_server
    pub fn garbler_client_v3(
        password: &[u8],
        masked_password: &[u8],
        index: u32,
        number_of_passwords: u32,
        threshold: u16,
        channel: &TChannel,
    ) -> Result<Self, Error> {
        instrument::begin("Garbler: Client v3", E_FUNC_COLOR);

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
            bootstrap: Box::new(chou_orlandi::Receiver),
        };
        ot.exchange(&message, channel)?;
        instrument::end();

        // 3. Encode the masked password
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
    pub fn evaluator_server_v3(
        passwords: &[Vec<u8>],
        mask: &[u8],
        channel: &TChannel,
    ) -> Result<Self, Error> {
        instrument::begin("Evaluator: Server v3", E_FUNC_COLOR);

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

        // 3. Get encoding of mask
        instrument::begin("OT: Encoded Mask", E_PROT_COLOR);
        let mut mask_choices = vec![false; password_bits];
        for i in 0..password_bytes {
            let byte = mask[i];
            for b in 0..8 {
                let choice = ((byte >> b) & 1) == 1;
                mask_choices[i * 8 + b] = choice;
            }
        }
        let encoded_mask_ot = Receiver {
            bootstrap: Box::new(chou_orlandi::Sender),
        };
        let encoded_mask = encoded_mask_ot.exchange(mask_choices.as_slice(), channel)?;
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

// Fourth (and faster, but with restrictions) implementation of one of many fPAKE, does not
// require two passes like the other 3 implementations. This version only works on distance
// functions homomorphic under XOR

/// Client version of (one-out-of)-many-fpake,
/// supplying a single key and an index.
pub fn mfpake_single(
    password: &[u8],
    index: u32,
    number_of_passwords: u32,
    threshold: u16,
    channel: &TChannel,
) -> Result<Key, Error> {
    instrument::begin("Client v4", E_FUNC_COLOR);

    let (_, receiver) = channel;

    // 1. OT The a masked version of the servers version of our password
    instrument::begin("1-to-n OT: Masked password", E_COMP_COLOR);
    let many_receiver = ManyOTReceiver {
        internal_receiver: chou_orlandi::Receiver,
    };
    let domain = log2(number_of_passwords);
    let mut masked_password = many_receiver.exchange(index, domain, channel)?;
    instrument::end();

    // 2. Double mask the password and use it for fPAKE
    instrument::begin("fPAKE with double mask", E_PROT_COLOR);
    xor_bytes_inplace(masked_password.as_mut_slice(), password);

    let k1 = HalfKey::evaluator(&masked_password, channel)?;
    let k2 = HalfKey::garbler(&masked_password, threshold, channel)?;
    let key = k1.combine(k2);
    instrument::end();

    instrument::end();

    return Ok(key);
}

/// Server version of (one-out-of)-many-fpake.
/// Supplying a key list and an index.
pub fn mfpake_many(
    passwords: &[Vec<u8>],
    threshold: u16,
    channel: &TChannel,
) -> Result<Key, Error> {
    instrument::begin("Server v4", E_FUNC_COLOR);

    let (sender, _) = channel;
    let password_bytes = passwords[0].len();

    // 1. Mask the passwords
    instrument::begin("Generate mask", E_COMP_COLOR);
    let mut mask = vec![0u8; password_bytes];
    random_bytes(&mut mask);
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

    // 2. OT the masked password(s) to the client
    instrument::begin("1-to-n OT: Masked password", E_PROT_COLOR);
    let many_sender = ManyOTSender {
        interal_sender: chou_orlandi::Sender,
    };
    let domain = log2(passwords.len());
    many_sender.exchange(masked_passwords.as_slice(), domain, channel)?;
    instrument::end();

    // 3. fPAKE with our "random" input  with the client
    instrument::begin("fPAKE with double mask", E_PROT_COLOR);
    let k1 = HalfKey::garbler(&mask, threshold, channel)?;
    let k2 = HalfKey::evaluator(&mask, channel)?;
    let key = k1.combine(k2);
    instrument::end();

    instrument::end();

    return Ok(key);
}

#[cfg(test)]
mod tests {
    use super::*;
    use raw::new_local_channel;

    #[test]
    fn test_fpake_one_of_many_server_garbler_v3() {
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
            OneOfManyKey::garbler_server_v3(&passwords, threshold, &ch1).unwrap()
        });

        let h2 = thread::spawn(move || {
            // Party 1
            OneOfManyKey::evaluator_client_v3(&password, number_of_passwords, index, &ch2).unwrap()
        });

        let (k1, _) = h1.join().unwrap();
        let (k2, _) = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_client_garbler_v3() {
        use std::thread;

        // Setup for client / server
        let passwords = [vec![0u8; 8], vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]];
        let number_of_passwords = passwords.len() as u32;
        let index = 1u32;
        let password = passwords[index as usize].clone();
        let threshold = 2;

        let mask = vec![42u8; 8];
        let masked_password = vec![password[0] ^ mask[0]; 8];

        // Do the thing
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let client_channel = (s2, r1);
        let server_channel = (s1, r2);

        let client = thread::spawn(move || {
            OneOfManyKey::garbler_client_v3(
                &password,
                &masked_password,
                index,
                number_of_passwords,
                threshold,
                &client_channel,
            )
            .unwrap()
        });

        let server = thread::spawn(move || {
            OneOfManyKey::evaluator_server_v3(&passwords, &mask, &server_channel).unwrap()
        });

        let k1 = client.join().unwrap();
        let k2 = server.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_v3() {
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
            let (k1, mask) = OneOfManyKey::garbler_server_v3(&passwords, threshold, &ch1).unwrap();
            let k2 = OneOfManyKey::evaluator_server_v3(&passwords_2, &mask, &ch1).unwrap();
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 1
            let (k1, masked_password) =
                OneOfManyKey::evaluator_client_v3(&password_2, number_of_passwords, index, &ch2)
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
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fpake_one_of_many_v4() {
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

        let h1 = thread::spawn(move || mfpake_many(&passwords, threshold, &ch1).unwrap());

        let h2 = thread::spawn(move || {
            mfpake_single(&password, index, number_of_passwords, threshold, &ch2).unwrap()
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }
}
