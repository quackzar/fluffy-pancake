use crate::common::{Channel, Error};
use crate::instrument;
use crate::instrument::{E_COMP_COLOR, E_FUNC_COLOR, E_PROT_COLOR, E_RECV_COLOR, E_SEND_COLOR};
use crate::ot::chou_orlandi::{OTReceiver, OTSender};
use crate::ot::common::*;
use crate::util::*;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

#[inline]
fn array<const N: usize>(vector: &Vec<u8>) -> [u8; N] {
    return vector.as_slice().try_into().unwrap();
}

// 1-to-n extensions for OT :D
// https://dl.acm.org/doi/pdf/10.1145/301250.301312
fn fk(key: &[u8], choice: u32, length: usize, buffer: &mut [u8]) {
    let mut hasher = Sha256::new();
    hasher.update(choice.to_be_bytes());
    hasher.update(key);
    let seed = array(&hasher.finalize().to_vec());

    let mut prg = ChaCha20Rng::from_seed(seed);
    prg.fill_bytes(buffer);
}

pub struct ManyOTSender {
    pub interal_sender: OTSender,
}

impl ManyOTSender {
    pub fn exchange(
        &self,
        messages: &[Vec<u8>],
        domain: u32,
        ch: &Channel<Vec<u8>>,
    ) -> Result<(), Error> {
        instrument::begin("1-to-n OT Sender", E_FUNC_COLOR);
        let byte_length = messages[0].len();

        // 1. B: Prepare random keys
        let l = domain as usize;

        instrument::begin("Generate keys", E_COMP_COLOR);
        let mut keys: Vec<[Vec<u8>; 2]> = Vec::with_capacity(l);
        for _i in 0..l {
            let mut left = vec![0u8; SECURITY_PARAM / 8];
            let mut right = vec![0u8; SECURITY_PARAM / 8];

            random_bytes(&mut left);
            random_bytes(&mut right);

            keys.push([left, right]);
        }
        instrument::end();

        instrument::begin("Compute y", E_COMP_COLOR);
        let domain_max = 1 << domain; // 2^domain
        let mut y = vec![0u8; domain_max * byte_length];

        // In this case is does not make sense to multi-thread when the number of rows in y is
        // relatively small, if this is the case we do it the "single-threaded" way instead.
        if domain <= 2 {
            let mut hash = vec![0u8; byte_length];
            for i in 0..domain_max {
                let y_value = unsafe { vector_row_mut(&mut y, i, byte_length) };
                xor_bytes_inplace(y_value, messages[i].as_slice());

                for j in 0..domain {
                    let bit = (i >> j) & 1;
                    fk(&keys[j as usize][bit as usize], i as u32, byte_length, &mut hash);
                    xor_bytes_inplace(y_value, &hash);
                }
            }
        } else {
            let desired_thread_count = num_cpus::get();
            let actual_thread_count = if domain_max <= desired_thread_count { domain_max as usize } else { desired_thread_count };
            debug_assert_eq!(0, domain_max % actual_thread_count);

            let rows_in_chunk = domain_max / actual_thread_count;
            let bytes_in_chunk = rows_in_chunk * byte_length;

            // NOTE: This is slightly slower for very small domain, but the difference shouldn't matter
            rayon::scope(|s| {
                let keys = &keys;

                let y_chunks = y.chunks_mut(bytes_in_chunk);
                for (chunk_idx, chunk) in y_chunks.enumerate() {
                    let handle = s.spawn(move |_| {
                        instrument::begin("Compute y - worker", E_COMP_COLOR);

                        let mut hash = vec![0u8; byte_length];

                        for i in 0..rows_in_chunk {
                            let y_value = unsafe { vector_row_mut(chunk, i, byte_length) };
                            let domain_index = rows_in_chunk * chunk_idx + i;
                            xor_bytes_inplace(y_value, messages[domain_index].as_slice());

                            for j in 0..domain {
                                let bit = (domain_index >> j) & 1;
                                fk(&keys[j as usize][bit as usize], domain_index as u32, byte_length, &mut hash);
                                xor_bytes_inplace(y_value, &hash);
                            }
                        }

                        instrument::end();
                        ()
                    });
                }

                instrument::end();
            });
        }

        let (s, _r) = ch;
        instrument::begin("Send y", E_SEND_COLOR);
        s.send_raw(y.as_mut_slice())?;
        instrument::end();

        // 2. Initiate 1-out-of-2 OTs by sending challenges
        instrument::begin("Build boostrap messages", E_COMP_COLOR);
        let mut messages = Vec::with_capacity(l);
        for i in 0..l {
            let m0 = keys[i as usize][0].to_vec();
            let m1 = keys[i as usize][1].to_vec();
            messages.push([m0, m1]);
        }
        let message = Message::from_zipped(messages.as_slice());
        instrument::end();

        instrument::begin("Boostrap", E_PROT_COLOR);
        self.interal_sender.exchange(&message, ch)?;
        instrument::end();

        instrument::end();

        Ok(())
    }
}

pub struct ManyOTReceiver {
    pub internal_receiver: OTReceiver,
}

impl ManyOTReceiver {
    pub fn exchange(
        &self,
        choice: u32,
        domain: u32,
        ch: &Channel<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        instrument::begin("1-to-n OT Receiver", E_FUNC_COLOR);
        let l = domain as usize;

        // construct choices
        instrument::begin("Build choices", E_COMP_COLOR);
        let mut choices: Vec<bool> = Vec::with_capacity(l);
        for i in 0..l {
            let bit = (choice & (1 << i)) >> i;
            choices.push(bit == 1);
        }
        instrument::end();

        let (_s, r) = ch;
        instrument::begin("Receive y", E_RECV_COLOR);
        let mut y: Vec<u8> = r.recv_raw()?;
        instrument::end();

        instrument::begin("Bootstrap", E_PROT_COLOR);
        let messages = self.internal_receiver.exchange(&choices, ch)?;
        instrument::end();

        // convert payload to keys
        instrument::begin("Convert payload to keys", E_COMP_COLOR);
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(l);
        for i in 0..l {
            let message = &messages[i];
            debug_assert_eq!(message.len() % LENGTH, 0);

            let mut key = Vec::with_capacity(message.len());
            for j in 0..message.len() {
                key.push(message[j]);
            }

            keys.push(key);
        }
        instrument::end();

        // reconstruct x from choice and keys
        instrument::begin("Reconstruct value", E_COMP_COLOR);
        let byte_length = y.len() / (1 << domain);
        let x = unsafe { vector_row_mut(&mut y, choice as usize, byte_length) };
        let mut hash = vec![0u8; byte_length];
        for i in 0..domain {
            fk(&keys[i as usize], choice, byte_length, &mut hash);
            xor_bytes_inplace(x, &hash);
        }
        instrument::end();

        instrument::end();
        Ok(x.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{log2, LENGTH};

    #[test]
    fn test_channel_1_to_n() {
        let n = 8u8;
        let domain = log2(n) as u32;
        let mut messages = Vec::with_capacity(n as usize);
        for i in 0u8..n {
            messages.push(vec![i; LENGTH]);
        }
        let choice = 4;

        let (s1, r1) = ductile::new_local_channel();
        let (s2, r2) = ductile::new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);

        let orig_msg = messages.clone();
        use std::thread;
        let h1 = thread::Builder::new()
            .name("Sender".to_string())
            .spawn(move || {
                let sender = ManyOTSender {
                    interal_sender: crate::ot::chou_orlandi::OTSender,
                };
                sender.exchange(&messages, domain, &ch1).unwrap();
            });

        let h2 = thread::Builder::new()
            .name("Receiver".to_string())
            .spawn(move || {
                let receiver = ManyOTReceiver {
                    internal_receiver: crate::ot::chou_orlandi::OTReceiver,
                };
                receiver.exchange(choice, domain, &ch2).unwrap()
            });

        h1.unwrap().join().unwrap();
        let output = h2.unwrap().join().unwrap();

        for i in 0..LENGTH {
            assert_eq!(orig_msg[choice as usize][i], output[i]);
        }
    }
}
