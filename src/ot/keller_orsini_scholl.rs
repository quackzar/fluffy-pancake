// https://eprint.iacr.org/2015/546.pdf

use crate::util::*;


/// The computational security paramter (k)
const COMP_SEC : usize = 256;
/// The statistical security paramter (s)
const STAT_SEC : usize = 128;



#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use super::*;
    use crate::ot::chou_orlandi::*;


    #[test]
    fn correlated_ot_with_errors() {
        // COTe
        use rand::Rng;

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
        let sender = ObliviousSender::new(&msg);

        let receiver = ObliviousReceiver::new(&u8_vec_to_bool_vec(&delta));

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
        let x = vec![0u128; COMP_SEC];
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
