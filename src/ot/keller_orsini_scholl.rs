// https://eprint.iacr.org/2015/546.pdf

use aes_gcm::aead::generic_array::functional::FunctionalSequence;
use rayon::iter::IndexedParallelIterator;

use crate::util::*;

use itertools::izip;
use crate::ot::util::*;

/// The computational security paramter (k)
const COMP_SEC : usize = 256;
/// The statistical security paramter (s)
const STAT_SEC : usize = 128;


struct Sender {
    bootstrap: dyn ObliviousReceiver,
}

struct Receiver {
    bootstrap: dyn ObliviousSender,
}


struct Matrix {
    rows: usize,
    cols: usize,
    data: Vec<Vec<u8>>,
}



impl ObliviousSender for Sender {
    fn exchange(&self, msg: &Message, channel: &Channel<Vec<u8>>) -> Result<(), Error> {
        let l = msg.len();
        const K : usize = COMP_SEC / 8;

        // COTe
        use rand::SeedableRng;
        use rand::Rng;

        // receiver:
        // sample k pairs of k-bit seeds.
        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::from_entropy();


        // INITIALIZATION
        let delta : [u8; K] = rng.gen();

        // do OT.
        let payload = self.bootstrap.exchange(&u8_vec_to_bool_vec(&delta), channel)?;
        let mut seed = [[0u8; K]; COMP_SEC];
        for (i,p) in payload.iter().enumerate() {
            seed[i].copy_from_slice(p);
        }

        // EXTENSION
        let t : Vec<Vec<u8>> = seed.iter().map(|&s| {
            let mut prg = ChaCha20Rng::from_seed(s);
            (0..l).map(|_| prg.gen::<u8>()).collect()
        }).collect();

        let (_,r) = channel;
        let u : Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;

        let q : Vec<_> = u8_vec_to_bool_vec(&delta).iter().enumerate().map(
            |(i,&d)| if d {
                xor_bytes(&u[i],&t[i])
            } else {
                t[i].clone()
            }
        ).collect();

        // Sender outputs `q_j`

        // -- Check correlation --
        // TODO: this

        // -- Randomize --
        let v0 : Vec<Vec<u8>> = q.iter().enumerate().map(|(j,q)|
            hash!(j.to_be_bytes(), q).to_vec()
        ).collect();
        let v1 : Vec<Vec<u8>> = q.iter().enumerate().map(|(j,q)|
            hash!(j.to_be_bytes(), xor_bytes(q, &delta)).to_vec()
        ).collect();

        // -- DeROT --
        let (d0, d1) : (Vec<Vec<u8>>, Vec<Vec<u8>>) = izip!(&msg.0, v0, v1).map(|([m0, m1],v0, v1)| {
            (xor_bytes(&m0, &v0), xor_bytes(&m1, &v1))
        }).unzip();

        let (s,_) = channel;
        for d0 in d0 {
            s.send(d0)?;
        }
        for d1 in d1 {
            s.send(d1)?;
        }
        Ok(())
    }
}

impl ObliviousReceiver for Receiver {
    fn exchange(&self, choices: &[bool], channel: &Channel<Vec<u8>>)
        -> Result<Payload, Error> {
        let l = choices.len();
        const K : usize = COMP_SEC / 8;

        // COTe

        // receiver:
        // sample k pairs of k-bit seeds.
        use rand_chacha::ChaCha20Rng;
        use rand::Rng;
        use rand::SeedableRng;
        let mut rng = ChaCha20Rng::from_entropy();


        // INITIALIZATION
        let seeds0 : [u8; COMP_SEC * K] = rng.gen();
        let seeds1 : [u8; COMP_SEC * (COMP_SEC)/8] = rng.gen();
        let seeds = (seeds0, seeds1);
        // do OT.
        let seed0 : [[u8; (COMP_SEC)/8]; COMP_SEC] = unsafe { std::mem::transmute(seeds.0) };
        let seed1 : [[u8; (COMP_SEC)/8]; COMP_SEC] = unsafe { std::mem::transmute(seeds.1) };

        let msg = Message::new(&seed0, &seed1);
        self.bootstrap.exchange(&msg, channel)?;

        // EXTENSION

        let x = vec![vec![0u8; l]; COMP_SEC]; // TODO: The u128 type should probably be a u8 array or vector.
        let t0 : Vec<Vec<u8>> = seed0.iter().map(|&s| {
            let mut prg = ChaCha20Rng::from_seed(s);
            (0..l).map(|_| prg.gen::<u8>()).collect()
        }).collect();

        let t1 : Vec<Vec<u8>> = seed0.iter().map(|&s| {
            let mut prg = ChaCha20Rng::from_seed(s);
            (0..l).map(|_| prg.gen::<u8>()).collect()
        }).collect();

        let u : Vec<Vec<u8>> = izip!(&t0, &t1, x).map(|(t0,t1,x)|
            izip!(t0,t1,x).map(|(t0,t1,x)| t0 ^ t1 ^ x).collect()
        ).collect();
        
        let (s,_) = channel;
        let u = bincode::serialize(&u)?;
        s.send(u)?;

        
        // Receiver outputs `t_j`
        
        // -- Check correlation --
        // TODO: this
        // let chi : Vec<_> = (0..128).map(|_| rng.gen::<[u8; COMP_SEC/8]>()).collect();

        // let xsum = izip!(x, chi).map(|(x,chi)| x * chi).sum();


        // -- Randomize --
        let v : Vec<Vec<u8>> = t0.iter().enumerate().map(|(j,t)|
            hash!(j.to_be_bytes(), t).to_vec()
        ).collect();

        // -- DeROT --
        let (_,r) = channel;
        let d0 = (0..l).map(|_| r.recv().unwrap());
        let d1 = (0..l).map(|_| r.recv().unwrap());
        let y = izip!(v, choices, d0, d1).map(|(v,c,d0,d1)| {
            xor_bytes(&v, if *c {&d1} else {&d0})
        }).collect();
        Ok(y)
    }
}


#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use super::*;
    use crate::ot::chou_orlandi::*;


    #[test]
    fn correlated_ot_with_errors() {
        // COTe
        use rand::Rng;
        use crate::ot::chou_orlandi::{Sender, Receiver};

        // receiver:
        // sample k pairs of k-bit seeds.
        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::from_entropy();


        // INITIALIZATION
        let seeds0 : [u8; COMP_SEC * (COMP_SEC)/8] = rng.gen();
        let seeds1 : [u8; COMP_SEC * (COMP_SEC)/8] = rng.gen();
        let seeds = (seeds0, seeds1);
        // sender:
        let delta = [0u8; COMP_SEC/8];
    
        // do OT.
        let seed0 : [[u8; (COMP_SEC)/8]; COMP_SEC] = unsafe { std::mem::transmute(seeds.0) };
        let seed1 : [[u8; (COMP_SEC)/8]; COMP_SEC] = unsafe { std::mem::transmute(seeds.1) };

        let msg = Message::new(&seed0, &seed1);
        let sender = Sender::new(&msg);

        let receiver = Receiver::new(&u8_vec_to_bool_vec(&delta));

        let receiver = receiver.accept(&sender.public());

        let payload = sender.accept(&receiver.public());
        let payload = receiver.receive(&payload);
        let mut seed = [[0u8; (COMP_SEC)/8]; COMP_SEC];
        for (i,p) in payload.iter().enumerate() {
            seed[i].copy_from_slice(p);
        }

        // Sender has `seed` and `delta`
        // Receiver has `seeds` being `seed0` and `seed1`.

        // EXTENSION

        // receiver
        let x = vec![0u128; COMP_SEC]; // TODO: The u128 type should probably be a u8 array or vector.
        let t0 : Vec<_> = seed0.iter().map(|&s| {
            let mut prg = ChaCha20Rng::from_seed(s);
            prg.gen::<u128>()
        }).collect();

        let t1 : Vec<_> = seed0.iter().map(|&s| {
            let mut prg = ChaCha20Rng::from_seed(s);
            prg.gen::<u128>()
        }).collect();

        // sender
        let t : Vec<_> = seed.iter().map(|&s| {
            let mut prg = ChaCha20Rng::from_seed(s);
            prg.gen::<u128>()
        }).collect();

        // receiver
        use std::num::Wrapping;
        use itertools::izip;
        let u : Vec<_> = izip!(t0, t1, x).map(|(t0,t1,x)| Wrapping(t0) + Wrapping(t1) + Wrapping(x)).map(|r| r.0).collect();
        
        // sender

        let delta = u8_vec_to_bool_vec(&delta);
        let q : Vec<_> = delta.iter().enumerate().map(|(i,&d)| (d as u128) * u[i] + t[i]).collect();
        
        // Sender outputs `q_j`
        // Receiver outputs `t_j`

    }

    #[test]
    fn old_correlated_ot_with_errors() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha12Rng;
        let l = 64; // some parameter

        // sender
        let delta = 42; // value in 2^COMP_SEC;

        
        // receiver
        let xs = vec![0; l];

        // sender
        let mut _rng = ChaCha12Rng::from_entropy();
        let ts = vec![0; l]; // todo rng

        // receiver
        let _qs : Vec<u64> = ts.iter().zip(xs.iter())
                    .map(|(t, x)| t + x * delta).collect();
    }


}
