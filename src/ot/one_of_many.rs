use crate::common::{Channel, Error};
// Library for fast OT.
// use curve25519_dalek::edwards;
use crate::ot::common::*;
use crate::{
    ot::chou_orlandi::*,
    util::{random_bytes, xor_bytes, LENGTH},
};
use sha2::{Digest, Sha256};
// 1-to-n extensions for OT :D
// https://dl.acm.org/doi/pdf/10.1145/301250.301312
fn fk(key: &[u8], choice: u32) -> Vec<u8> {
    let chunks = key.len() / 32;
    let excess = key.len() % 32;
    let mut result = Vec::with_capacity(key.len());

    // Fill in the excess first
    let mut hasher = Sha256::new();
    hasher.update(choice.to_be_bytes());
    hasher.update(key);
    let intermediate = hasher.finalize().to_vec();
    for i in 0..excess {
        result.push(intermediate[i]);
    }

    // Fill in the chunks
    for _ in 0..chunks {
        let mut hasher = Sha256::new();
        hasher.update(&result);
        let intermediate = hasher.finalize().to_vec();

        for j in 0..32 {
            result.push(intermediate[j]);
        }
    }

    debug_assert!(key.len() == result.len());
    return result;
}

pub struct ManyOTSender {
    pub interal_sender: OTSender,
}

impl ManyOTSender {
    pub fn exchange(&self, messages : &[Vec<u8>], domain: u32, ch: &Channel<Vec<u8>>) -> Result<(), Error> {
        let byte_length = messages[0].len();

        // 1. B: Prepare random keys
        let l = messages.len();
        debug_assert!(l == (1 << domain));

        let mut keys: Vec<[Vec<u8>; 2]> = Vec::with_capacity(l);
        for _i in 0..l {
            let mut left = vec![0u8; byte_length];
            let mut right = vec![0u8; byte_length];

            random_bytes(&mut left);
            random_bytes(&mut right);

            keys.push([left, right]);
        }

        let domain_max = 1 << domain; // 2^domain
        let mut y = Vec::with_capacity(domain_max);
        for i in 0..domain_max {
            let mut value = messages[i].to_vec();
            for j in 0..domain {
                let bit = (i & (1 << j)) >> j;
                let hash = fk(&keys[j as usize][bit as usize], i as u32);
                value = xor_bytes(&value, &hash);
            }

            y.push(value.to_vec());
        }

        // 2. Initiate 1-out-of-2 OTs by sending challenges
        let mut messages = Vec::with_capacity(l);
        for i in 0..l {
            let m0 = keys[i as usize][0].to_vec();
            let m1 = keys[i as usize][1].to_vec();
            messages.push([m0, m1]);
        }

        let message = Message::new2(messages.as_slice());
        self.interal_sender.exchange(&message, ch)?;
        let (s, _r) = ch;
        s.send(bincode::serialize(&y)?)?;
        Ok(())
    }
}

pub struct ManyOTReceiver {
    pub interal_receiver: OTReceiver,
}

impl ManyOTReceiver {
    pub fn exchange(&self, choice : u32, domain: u32, ch: &Channel<Vec<u8>>) -> Result<Vec<u8>, Error> {
        let l = 1 << domain;

        // construct choices
        let mut choices: Vec<bool> = Vec::with_capacity(l);
        for i in 0..l {
            let bit = (choice & (1 << i)) >> i;
            choices.push(bit == 1);
        }

        let messages = self.interal_receiver.exchange(&choices, ch)?;

        // convert payload to keys
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

        let (_s, r) = ch;
        let y: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;

        // reconstruct x from choice and keys
        let mut x = y[choice as usize].to_vec();
        for i in 0..domain {
            let hash = fk(&keys[i as usize], choice);
            x = xor_bytes(&x, &hash);
        }

        Ok(x)
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
                    interal_receiver: crate::ot::chou_orlandi::OTReceiver,
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
