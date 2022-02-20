use core::ops;
use std::iter;

use sha2::{Sha256, Digest};

use crate::util::*;


const SECURITY_PARAM : usize = 256; // bits used total
const WIRE_LENGTH: usize = SECURITY_PARAM / 8; // bytes used

// TODO: Improve internal representation and implement from/into.
#[derive(Debug, Clone)]
pub struct ArithWire {
    pub domain: u64,
    values: [u8; WIRE_LENGTH],
}

impl ops::Add<&ArithWire> for &ArithWire {
    type Output = ArithWire;
    fn add(self, rhs: &ArithWire) -> ArithWire {
        self.map_with(rhs, |a,b| (a + b) % self.domain)
    }
}

impl ops::Sub<&ArithWire> for &ArithWire {
    type Output = ArithWire;
    fn sub(self, rhs: &ArithWire) -> Self::Output {
        self.map_with(rhs, |a,b| (a + (self.domain - b)) % self.domain)
    }
}

impl ops::Neg for &ArithWire {
    type Output = ArithWire;
    fn neg(self) -> ArithWire {
        self.map(|x| (self.domain - x) % self.domain)
    }
}

impl ops::Mul<u64> for &ArithWire {
    type Output = ArithWire;
    #[inline]
    fn mul(self, rhs: u64) -> ArithWire {
        self.map(|x| (x * rhs) % self.domain )
    }
}

impl iter::Sum for ArithWire {
    fn sum<I: Iterator<Item=Self>>(mut iter: I) -> Self {
        let init = iter.next().unwrap();
        iter.fold(init, |acc: ArithWire, w: ArithWire| &acc + &w)
    }
}

impl ArithWire {
    pub(crate) fn empty() -> ArithWire {
        ArithWire {
            domain: 0,
            values: [0; WIRE_LENGTH],
        }
    }

    fn map<F>(&self, op : F) -> ArithWire where
        F: Fn(u64) -> u64 {
        let domain = self.domain;
        // TODO: change size based on domain
        let input : [u64; WIRE_LENGTH / 8] = bytemuck::cast(self.values);
        let mut output = [0u64; WIRE_LENGTH / 8];
        for i in 0..output.len() {
            output[i] = op(input[i]);
        }
        debug_assert!(output.iter().all(|&x| x < self.domain),
            "output out of domain {} {:?}", domain, output);
        let values = bytemuck::cast(output);
        ArithWire {
            domain,
            values,
        }
    }

    fn map_with<F>(&self, other : &ArithWire, op : F) -> ArithWire where
        F: Fn(u64, u64) -> u64 {
        debug_assert_eq!(self.domain, other.domain, "Domain not matching");
        let l1 : [u64; WIRE_LENGTH / 8] = bytemuck::cast(self.values);
        let l2 : [u64; WIRE_LENGTH / 8] = bytemuck::cast(other.values);
        let mut output = [0u64; WIRE_LENGTH / 8];
        for i in 0..output.len() {
            output[i] = op(l1[i], l2[i]);
        }
        debug_assert!(output.iter().all(|&x| x < self.domain));
        let values = bytemuck::cast(output);
        let domain = self.domain;
        ArithWire {
            domain,
            values,
        }
    }


    pub(crate) fn new(domain: u64) -> ArithWire {
        let mut values = [0u64; WIRE_LENGTH / 8];
        for i in 0..(WIRE_LENGTH/8) {
            values[i] = rng(domain);
        }
        debug_assert!(values.iter().all(|&x| x < domain));
        let values = bytemuck::cast(values);
        ArithWire {
            values,
            domain,
        }
    }

    pub(crate) fn delta(domain: u64) -> ArithWire {
        let mut values = [0u64; WIRE_LENGTH / 8];
        for i in 0..(WIRE_LENGTH/8) {
            values[i] = rng(domain);
        }
        values[WIRE_LENGTH/8 - 1] = 1;
        debug_assert!(values.iter().all(|&x| x < domain));
        let values = bytemuck::cast(values);
        ArithWire {
            values,
            domain,
        }
    }

    #[inline]
    pub(crate) fn tau(&self) -> u64 {
        bytemuck::cast::<[u8; WIRE_LENGTH], [u64; WIRE_LENGTH/8]>(self.values)[WIRE_LENGTH/8 - 1]
    }

}

pub fn hash_wire(index: usize, wire: &ArithWire, target: &ArithWire) -> ArithWire {
    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    hasher.update(wire.values);
    let digest = hasher.finalize(); // TODO: use variable size hashing
    let bytes = <[u8; WIRE_LENGTH]>::try_from(digest.as_ref()).expect("digest too long");
    
    // Makes values for the wire of target size from the output of the hash function, recall that
    // the hash function outputs 256 bits, which means that the number of values * the number of
    // bits in a value must be less than or equal to 256.
    let wire = ArithWire {
        domain: target.domain,
        values: bytes,
    };
    wire.map(|x| x % wire.domain)
}



pub fn hash(index: u64, x: u64, wire: &ArithWire) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    hasher.update(x.to_be_bytes());
    hasher.update(wire.values);
    let digest = hasher.finalize();
    let bytes = <[u8; WIRE_LENGTH]>::try_from(digest.as_ref()).expect("digest too long");

    u64::from_be_bytes(bytes[..8].try_into().unwrap())
}
