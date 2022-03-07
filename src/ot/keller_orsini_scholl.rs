// https://eprint.iacr.org/2015/546.pdf

use crate::util::*;


/// The computational security paramter (k)
const COMP_SEC : usize = 128;
/// The statistical security paramter (s)
const STAT_SEC : usize = 128;


#[cfg(test)]
mod tests {
    use super::*;
    use crate::ot::chou_orlandi::*;


    fn correlated_ot_with_errors() {
        // COTe
        use rand::Rng;
        use bytemuck::cast;
        let mut rng = rand::thread_rng();
        // receiver:
        // sample k pairs of k-bit seeds.

        let mut seeds0 = [0u8; COMP_SEC * 16];
        rand::thread_rng().fill(&mut seeds0);
        let mut seeds1 = [0u8; COMP_SEC * 16];
        rand::thread_rng().fill(&mut seeds1);
        let seeds = (seeds0, seeds1);
        // sender:
        let delta : u128 = rng.gen();
    
        // do OT.
        let seeds0 : [[u8; 16]; COMP_SEC] = cast(seeds.0);
        let seeds1 : [[u8; 16]; COMP_SEC] = cast(seeds.1);

        let msg = Message::new(&seeds0, &seeds1);
        let sender = ObliviousSender::new(&msg);
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
