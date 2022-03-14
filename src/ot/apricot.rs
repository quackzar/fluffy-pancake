// https://eprint.iacr.org/2015/546.pdf

use crate::util::*;

use crate::ot::common::*;
use itertools::{izip, Itertools};

/// The computational security paramter (k)
const COMP_SEC: usize = 256;
/// The statistical security paramter (s)
const STAT_SEC: usize = 128;

struct Sender {
    bootstrap: Box<dyn ObliviousReceiver>,
}

struct Receiver {
    bootstrap: Box<dyn ObliviousSender>,
}

fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}

fn transpose_sse(_m: Vec<Vec<u8>>) -> Vec<Vec<bool>> {
    // TODO: Use SSE.
    todo!()
}

impl ObliviousSender for Sender {
    fn exchange(&self, msg: &Message, channel: &Channel<Vec<u8>>) -> Result<(), Error> {
        assert!(msg.len() % 8 == 0, "Message length must be a multiple of 8");
        let l = msg.len() / 8; // 8 bits stored in a byte.

        // The parameter kappa.
        const K: usize = COMP_SEC / 8;

        // COTe
        use rand::Rng;
        use rand::SeedableRng;

        // receiver:
        // sample k pairs of k-bit seeds.
        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::from_entropy();

        // INITIALIZATION
        let delta: [u8; K] = rng.gen();

        // do OT.
        let payload = self
            .bootstrap
            .exchange(&u8_vec_to_bool_vec(&delta), channel)?;
        let mut seed = [[0u8; K]; COMP_SEC];
        for (i, p) in payload.iter().enumerate() {
            seed[i].copy_from_slice(p);
        }

        // EXTENSION
        let t: Vec<Vec<u8>> = seed
            .iter()
            .map(|&s| {
                let mut prg = ChaCha20Rng::from_seed(s);
                (0..l).map(|_| prg.gen::<u8>()).collect()
            })
            .collect();

        let (_, r) = channel;
        let u: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;

        let mut q = Vec::with_capacity(K);
        for i in 0..K {
            let delta = u8_vec_to_bool_vec(&delta);
            if delta[i] {
                q.push(xor_bytes(&u[i], &t[i]));
            } else {
                q.push(t[i].clone());
            }
        }

        // Sender outputs `q_j`

        // -- Check correlation --
        // TODO: this

        // -- Randomize --
        let q = transpose(q);

        let v0: Vec<Vec<u8>> = q
            .iter()
            .enumerate()
            .map(|(j, q)| hash!(j.to_be_bytes(), q).to_vec())
            .collect();
        let v1: Vec<Vec<u8>> = q
            .iter()
            .enumerate()
            .map(|(j, q)| hash!(j.to_be_bytes(), xor_bytes(q, &delta)).to_vec())
            .collect();

        // -- DeROT --
        use aes_gcm::aead::{Aead, NewAead};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        let (d0, d1): (Vec<Vec<u8>>, Vec<Vec<u8>>) = izip!(&msg.0, v0, v1)
            .map(|([m0, m1], v0, v1)| {
                // encrypt the messages.
                dbg!(&v0);
                dbg!(&v1);
                let nonce = Nonce::from_slice(b"unique nonce");
                let cipher = Aes256Gcm::new(Key::from_slice(&v0));
                let c0 = cipher.encrypt(nonce, m0.as_slice()).unwrap();
                let cipher = Aes256Gcm::new(Key::from_slice(&v1));
                let c1 = cipher.encrypt(nonce, m1.as_slice()).unwrap();
                (c0, c1)
            })
            .unzip();

        let (s, _) = channel;
        let d0 = bincode::serialize(&d0)?;
        let d1 = bincode::serialize(&d1)?;
        s.send(d0)?;
        s.send(d1)?;

        Ok(())
    }
}

impl ObliviousReceiver for Receiver {
    fn exchange(&self, choices: &[bool], channel: &Channel<Vec<u8>>) -> Result<Payload, Error> {
        let l = choices.len();
        const K: usize = COMP_SEC / 8;

        // COTe

        // receiver:
        // sample k pairs of k-bit seeds.
        use rand::Rng;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::from_entropy();

        // INITIALIZATION
        let seed0: [u8; COMP_SEC * K] = rng.gen();
        let seed1: [u8; COMP_SEC * K] = rng.gen();
        // do OT.
        let seed0: [[u8; K]; COMP_SEC] = unsafe { std::mem::transmute(seed0) };
        let seed1: [[u8; K]; COMP_SEC] = unsafe { std::mem::transmute(seed1) };

        let msg = Message::new(&seed0, &seed1);
        self.bootstrap.exchange(&msg, channel)?;

        // EXTENSION

        let x: Vec<Vec<u8>> = choices
            .iter()
            .map(|b| if *b { vec![0x00u8; K] } else { vec![0xFFu8; K] })
            .collect();
        let t0: Vec<Vec<u8>> = seed0
            .iter()
            .map(|&s| {
                let mut prg = ChaCha20Rng::from_seed(s);
                (0..l).map(|_| prg.gen::<u8>()).collect()
            })
            .collect();

        let t1: Vec<Vec<u8>> = seed0
            .iter()
            .map(|&s| {
                let mut prg = ChaCha20Rng::from_seed(s);
                (0..l).map(|_| prg.gen::<u8>()).collect()
            })
            .collect();

        let mut u: Vec<Vec<u8>> = Vec::with_capacity(K);
        for i in 0..K {
            let mut vec = Vec::with_capacity(l);
            for j in 0..l {
                vec.push(t0[i][j] ^ t1[i][j] ^ x[j][i]);
            }
            u.push(vec);
        }

        let (s, _) = channel;
        let u = bincode::serialize(&u)?;
        s.send(u)?;

        // Receiver outputs `t_j`

        // -- Check correlation --
        // TODO: this
        // let chi : Vec<_> = (0..128).map(|_| rng.gen::<[u8; COMP_SEC/8]>()).collect();

        // let xsum = izip!(x, chi).map(|(x,chi)| x * chi).sum();

        // -- Randomize --
        let t0 = t0.iter().map(|v| u8_vec_to_bool_vec(v)).collect();
        let t0 = transpose(t0);
        let t0: Vec<Vec<u8>> = t0.iter().map(|v| bool_vec_to_u8_vec(v)).collect();
        let v: Vec<Vec<u8>> = t0
            .iter()
            .enumerate()
            .map(|(j, t)| hash!(j.to_be_bytes(), t).to_vec())
            .collect();

        // -- DeROT --
        use aes_gcm::aead::{Aead, NewAead};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        let (_, r) = channel;
        let d0: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let d1: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let y = izip!(v, choices, d0, d1)
            .map(|(v, c, d0, d1)| {
                let nonce = Nonce::from_slice(b"unique nonce");
                let cipher = Aes256Gcm::new(Key::from_slice(&v));
                dbg!(&v);
                let d = if !*c { d1 } else { d0 };
                let c = cipher.decrypt(nonce, d.as_slice()).unwrap();
                c
            })
            .collect();
        Ok(y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ot_receiver() {
        use crate::ot::chou_orlandi::{OTReceiver, OTSender};
        let (s1, r1) = ductile::new_local_channel();
        let (s2, r2) = ductile::new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);

        use std::thread;
        let h1 = thread::Builder::new()
            .name("Sender".to_string())
            .spawn(move || {
                let sender = Sender {
                    bootstrap: Box::new(OTReceiver),
                };
                let msg = Message::new(&[b"Hello"; 8], &[b"World"; 8]);
                sender.exchange(&msg, &ch1).unwrap();
            });

        let h2 = thread::Builder::new()
            .name("Receiver".to_string())
            .spawn(move || {
                let receiver = Receiver {
                    bootstrap: Box::new(OTSender),
                };
                let choices = [true];
                let msg = receiver.exchange(&choices, &ch2).unwrap();
                assert_eq!(msg[0], b"World");
            });

        h1.unwrap().join().unwrap();
        h2.unwrap().join().unwrap();
    }
}
