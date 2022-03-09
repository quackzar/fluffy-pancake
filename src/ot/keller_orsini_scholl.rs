// https://eprint.iacr.org/2015/546.pdf

use crate::util::*;

use itertools::izip;
use crate::ot::util::*;

/// The computational security paramter (k)
const COMP_SEC : usize = 256;
/// The statistical security paramter (s)
const STAT_SEC : usize = 128;


struct Sender {
    bootstrap: Box<dyn ObliviousReceiver>,
}

struct Receiver {
    bootstrap: Box<dyn ObliviousSender>,
}


struct Matrix {
    rows: usize,
    cols: usize,
    data: Vec<Vec<u8>>,
}



impl ObliviousSender for Sender {
    fn exchange(&self, msg: &Message, channel: &Channel<Vec<u8>>) -> Result<(), Error> {
        assert!(msg.len() % 8 == 0, "Message length must be a multiple of 8");
        let l = msg.len() / 8;
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
            (xor_bytes(m0, &v0), xor_bytes(m1, &v1))
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
    use super::*;

    #[test]
    fn test_ot_receiver() {
        use crate::ot::chou_orlandi::{OTSender, OTReceiver};
        let (s1,r1) = ductile::new_local_channel();
        let (s2,r2) = ductile::new_local_channel();
        let ch1 = (s1,r2);
        let ch2 = (s2,r1);

        use std::thread;
        let h1 = thread::Builder::new().name("Sender".to_string()).spawn(move || {
            let sender = Sender { 
                bootstrap: Box::new(OTReceiver),
            };
            let msg = Message::new(&[b"Hello"; 8], &[b"World"; 8]);
            sender.exchange(&msg, &ch1).unwrap();
        });

        let h2 = thread::Builder::new().name("Receiver".to_string()).spawn(move || {
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
