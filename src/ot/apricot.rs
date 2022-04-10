// https://eprint.iacr.org/2015/546.pdf

use crate::ot::coinflip::coinflip_receiver;
use crate::ot::coinflip::coinflip_sender;
use crate::util::*;

use crate::common::*;
use crate::ot::bitmatrix::*;
use crate::ot::common::*;
use crate::ot::polynomial::*;
use itertools::izip;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;

/// The computational security paramter (k)
const COMP_SEC: usize = 128;
/// The statistical security paramter (s)
const STAT_SEC: usize = 64;

pub struct Sender {
    pub bootstrap: Box<dyn ObliviousReceiver>,
}

pub struct Receiver {
    pub bootstrap: Box<dyn ObliviousSender>,
}

impl Sender {
    #[inline]
    pub fn new(bootstrap: Box<dyn ObliviousReceiver>) -> Self {
        Self { bootstrap }
    }

    #[inline(always)]
    fn cote(&self, l: usize, channel: &Channel<Vec<u8>>) -> Result<(BitMatrix, BitVector), Error> {
        const K: usize = COMP_SEC; // kappa
        const S: usize = STAT_SEC;

        // sample k pairs of k-bit seeds.
        let mut rng = ChaCha20Rng::from_entropy();

        // INITIALIZATION
        let delta: [Block; K / BLOCK_SIZE] = rng.gen();
        let delta = BitVector::from_vec(delta.to_vec());

        // do OT.
        let payload = self
            .bootstrap
            .exchange(&u8_vec_to_bool_vec(delta.as_bytes()), channel)?;
        let mut seed = [[0u8; 32]; K];
        for (i, p) in payload.iter().enumerate() {
            seed[i].copy_from_slice(p);
        }

        // EXTENSION
        let t: BitMatrix = seed
            .par_iter()
            .map(|&s| {
                let mut prg = ChaCha20Rng::from_seed(s);
                let v = (0..l / BLOCK_SIZE).map(|_| prg.gen::<Block>()).collect();
                BitVector::from_vec(v)
            })
            .collect();

        let (_, r) = channel;
        let u: BitMatrix = bincode::deserialize(&r.recv_raw()?)?;

        let q: BitMatrix = u8_vec_to_bool_vec(delta.as_bytes())
            .into_par_iter()
            .enumerate()
            .map(|(i, d)| if d { &u[i] ^ &t[i] } else { t[i].clone() })
            .collect();

        let q = q.transpose();
        Ok((q, delta))
    }

    #[inline(always)]
    fn correlation_check(
        &self,
        l: usize,
        q: &BitMatrix,
        delta: &BitVector,
        channel: &Channel<Vec<u8>>,
    ) -> Result<(), Error> {
        const K: usize = COMP_SEC; // kappa
        const S: usize = STAT_SEC;
        let (_, r) = channel;
        let seed = coinflip_receiver::<32>(channel)?;
        let mut prg = ChaCha20Rng::from_seed(seed);
        let chi: BitMatrix = (0..l)
            .map(|_| {
                let v: [Block; K / BLOCK_SIZE] = prg.gen();
                BitVector::from_vec(v.to_vec())
            })
            .collect();
        let mut q_sum = Polynomial::new();
        for (q, chi) in izip!(q, &chi) {
            let q = <&Polynomial>::from(q);
            let chi = <&Polynomial>::from(chi);

            q_sum.mul_add_assign(q, chi);
        }
        let x_sum: Polynomial = bincode::deserialize(&r.recv_raw()?)?;
        let t_sum: Polynomial = bincode::deserialize(&r.recv_raw()?)?;
        let delta_ = <&Polynomial>::from(delta);
        q_sum.mul_add_assign(&x_sum, delta_);

        if t_sum != q_sum {
            return Err(Box::new(OTError::PolychromaticInput()));
        }
        Ok(())
    }

    #[inline(always)]
    fn de_rot(
        &self,
        q: BitMatrix,
        delta: &BitVector,
        msg: &Message,
        channel: &Channel<Vec<u8>>,
    ) -> Result<(), Error> {
        // -- Randomize --
        let (v0, v1): (Vec<Vec<u8>>, Vec<Vec<u8>>) = q[..msg.len()]
            .par_iter()
            .enumerate()
            .map(|(j, q)| {
                let v0 = hash!(j.to_le_bytes(), q.as_bytes()).to_vec();
                let q = q ^ delta;
                let v1 = hash!(j.to_le_bytes(), q.as_bytes()).to_vec();
                (v0, v1)
            })
            .unzip();

        // -- DeROT --
        // TODO: parallelize
        let (d0, d1): (Vec<Vec<u8>>, Vec<Vec<u8>>) = izip!(&msg.0, v0, v1)
            .map(|([m0, m1], v0, v1)| {
                // encrypt the messages.
                let size = m0.len();
                let mut rng = ChaCha8Rng::from_seed(v0.try_into().unwrap());
                let cipher: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect();
                let c0 = xor_bytes(m0, &cipher);

                let size = m1.len();
                let mut rng = ChaCha8Rng::from_seed(v1.try_into().unwrap());
                let cipher: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect();
                let c1 = xor_bytes(m1, &cipher);

                (c0, c1)
            })
            .unzip();

        let (s, _) = channel;
        let d0 = bincode::serialize(&d0)?;
        let d1 = bincode::serialize(&d1)?;
        s.send_raw(&d0)?;
        s.send_raw(&d1)?;

        Ok(())
    }
}

impl Receiver {
    #[inline]
    pub fn new(bootstrap: Box<dyn ObliviousSender>) -> Self {
        Self { bootstrap }
    }

    #[inline(always)]
    fn cote(&self, choices: &[bool], channel: &Channel<Vec<u8>>) -> Result<BitMatrix, Error> {
        const K: usize = COMP_SEC; // kappa
        const S: usize = STAT_SEC;
        let l = choices.len();
        let mut rng = ChaCha20Rng::from_entropy();
        let seed0: [[u8; 32]; K] = rng.gen();
        let seed1: [[u8; 32]; K] = rng.gen();

        let msg = Message::new(&seed0, &seed1);
        self.bootstrap.exchange(&msg, channel)?;

        // EXTENSION

        let x = BitMatrix::monochrome(choices, K);

        let t0: BitMatrix = seed0
            .par_iter()
            .map(|&s| {
                let mut prg = ChaCha20Rng::from_seed(s);
                let v = (0..l / BLOCK_SIZE).map(|_| prg.gen::<Block>()).collect();
                BitVector::from_vec(v)
            })
            .collect();

        let t1: BitMatrix = seed1
            .par_iter()
            .map(|&s| {
                let mut prg = ChaCha20Rng::from_seed(s);
                let v = (0..l / BLOCK_SIZE).map(|_| prg.gen::<Block>()).collect();
                BitVector::from_vec(v)
            })
            .collect();

        let u: BitMatrix = izip!(x, &t0, &t1)
            .map(|(x, t0, t1)| {
                let mut u = x;
                u ^= t0;
                u ^= t1;
                u
            })
            .collect();

        let (s, _) = channel;
        let u = bincode::serialize(&u)?;
        s.send_raw(&u)?;

        let t = t0.transpose();
        Ok(t)
    }

    #[inline(always)]
    fn correlation_check(
        &self,
        t: &BitMatrix,
        choices: &[bool],
        channel: &Channel<Vec<u8>>,
    ) -> Result<(), Error> {
        const K: usize = COMP_SEC; // kappa
        let (s, _) = channel;
        let l = choices.len();
        let seed = coinflip_sender::<32>(channel)?;
        let mut prg = ChaCha20Rng::from_seed(seed);
        let chi: BitMatrix = (0..l)
            .map(|_| {
                let v: [Block; K / BLOCK_SIZE] = prg.gen();
                BitVector::from_vec(v.to_vec())
            })
            .collect();

        let mut x_sum = Polynomial::new();
        let mut t_sum = Polynomial::new();
        // PERF: Parallelize.
        for (x, t, chi) in izip!(choices, t, &chi) {
            let t = <&Polynomial>::from(t);
            let chi = <&Polynomial>::from(chi);
            if *x {
                x_sum += chi
            }

            // PERF: Reduce last.
            t_sum.mul_add_assign(t, chi);
        }

        s.send_raw(&bincode::serialize(&x_sum)?)?;
        s.send_raw(&bincode::serialize(&t_sum)?)?;
        Ok(())
    }

    #[inline(always)]
    fn de_rot(
        &self,
        choices: &[bool],
        t: BitMatrix,
        channel: &Channel<Vec<u8>>,
    ) -> Result<Payload, Error> {
        let v: Vec<Vec<u8>> = t
            .into_par_iter()
            .enumerate()
            .map(|(j, t)| hash!(j.to_le_bytes(), t.as_bytes()).to_vec())
            .collect();

        // -- DeROT --
        let (_, r) = channel;
        let d0: Vec<Vec<u8>> = bincode::deserialize(&r.recv_raw()?)?;
        let d1: Vec<Vec<u8>> = bincode::deserialize(&r.recv_raw()?)?;

        // PERF: parallelize
        let y = izip!(v, choices, d0, d1)
            .map(|(v, c, d0, d1)| {
                let d = if *c { d1 } else { d0 };
                let size = d.len();
                let mut rng = ChaCha8Rng::from_seed(v.try_into().unwrap());
                let cipher: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect();
                xor_bytes(&d, &cipher)
            })
            .collect();
        Ok(y)
    }
}

impl ObliviousSender for Sender {
    fn exchange(&self, msg: &Message, channel: &Channel<Vec<u8>>) -> Result<(), Error> {
        const K: usize = COMP_SEC; // kappa
        const S: usize = STAT_SEC;
        assert!(
            msg.len() >= BLOCK_SIZE,
            "Message length must be larger than {BLOCK_SIZE}"
        );
        assert!(
            msg.len() % BLOCK_SIZE == 0,
            "Message length must be a multiple of {BLOCK_SIZE}"
        );
        let pb = TransactionProperties {
            msg_size: msg.len(),
            protocol: "Apricot".to_string(),
        };
        validate_properties(&pb, channel)?;

        let l = msg.len();
        let l = l + K + S; // refit with security padding
        let (q, delta) = self.cote(l, channel)?;
        self.correlation_check(l, &q, &delta, channel)?;
        self.de_rot(q, &delta, msg, channel)
    }
}

impl ObliviousReceiver for Receiver {
    fn exchange(&self, choices: &[bool], channel: &Channel<Vec<u8>>) -> Result<Payload, Error> {
        let pb = TransactionProperties {
            msg_size: choices.len(),
            protocol: "Apricot".to_string(),
        };
        validate_properties(&pb, channel)?;
        assert!(
            choices.len() >= BLOCK_SIZE,
            "Message length must be larger than {BLOCK_SIZE}"
        );
        assert!(
            choices.len() % BLOCK_SIZE == 0,
            "Message length must be a multiple of {BLOCK_SIZE}"
        );
        const K: usize = COMP_SEC;
        const S: usize = STAT_SEC;
        let mut rng = ChaCha20Rng::from_entropy();
        let bonus: [bool; K + S] = rng.gen();
        let padded_choices = [choices, &bonus].concat();

        let t = self.cote(&padded_choices, channel)?;
        self.correlation_check(&t, &padded_choices, channel)?;
        self.de_rot(choices, t, channel)
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
        const N: usize = 8 << 12;
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);
        println!("N = {}", N);

        use std::thread;
        let h1 = thread::Builder::new()
            .name("Sender".to_string())
            .spawn(move || {
                let sender = Sender {
                    bootstrap: Box::new(OTReceiver),
                };
                let msg = Message::new(&[b"Hello"; N], &[b"World"; N]);
                sender.exchange(&msg, &ch1).unwrap();
            });

        let h2 = thread::Builder::new()
            .name("Receiver".to_string())
            .spawn(move || {
                let receiver = Receiver {
                    bootstrap: Box::new(OTSender),
                };
                let choices = [true; N];
                let msg = receiver.exchange(&choices, &ch2).unwrap();
                assert_eq!(msg[0], b"World");
            });

        h1.unwrap().join().unwrap();
        h2.unwrap().join().unwrap();
    }
}
