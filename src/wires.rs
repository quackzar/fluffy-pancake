use core::ops;
use std::iter;

use sha2::{Sha256, Digest};

use crate::util::*;


type Domain = u16;


// NOTE: Security paramter depends on hash function.
const SECURITY_PARAM : usize = 256; // bits used total
const LENGTH: usize = SECURITY_PARAM / 8; // bytes used

// Maybe use domain as const generic?
#[derive(Debug, Clone)]
pub struct ArithWire {
    pub domain: u16,
    values: [u8; LENGTH],
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

impl ops::Mul<u16> for &ArithWire {
    type Output = ArithWire;
    #[inline]
    fn mul(self, rhs: u16) -> ArithWire {
        self.map(|x| (((x as u32) * (rhs as u32)) % (self.domain as u32)) as u16)
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
            values: [0; LENGTH],
        }
    }

    fn map<F>(&self, op : F) -> ArithWire where
        F: Fn(u16) -> u16 {
        let domain = self.domain;
        // TODO: change size based on domain
        let input : [u16; LENGTH / 2] = bytemuck::cast(self.values);
        let mut output = [0u16; LENGTH / 2];
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
        F: Fn(u16, u16) -> u16 {
        debug_assert_eq!(self.domain, other.domain, "Domain not matching");
        let l1 : [u16; LENGTH / 2] = bytemuck::cast(self.values);
        let l2 : [u16; LENGTH / 2] = bytemuck::cast(other.values);
        
        let mut output = [0u16; LENGTH / 2];
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


    pub(crate) fn new(domain: u16) -> ArithWire {
        let mut values = [0u16; LENGTH / 2];
        for i in 0..(LENGTH/8) {
            values[i] = rng(domain);
        }
        debug_assert!(values.iter().all(|&x| x < domain));
        let values = bytemuck::cast(values);
        ArithWire {
            values,
            domain,
        }
    }

    pub(crate) fn delta(domain: u16) -> ArithWire {
        let mut values = [0u16; LENGTH / 2];
        for i in 0..(LENGTH/8) {
            values[i] = rng(domain);
        }
        values[LENGTH/2 - 1] = 1;
        debug_assert!(values.iter().all(|&x| x < domain));
        let values = bytemuck::cast(values);
        ArithWire {
            values,
            domain,
        }
    }

    #[inline]
    pub(crate) fn color(&self) -> u16 {
        bytemuck::cast::<[u8; LENGTH], [u16; LENGTH/2]>(self.values)[LENGTH/2 - 1]
    }

}

impl AsRef<[u8]> for &ArithWire {
    fn as_ref(&self) -> &[u8] {
        &self.values
    }
}

pub fn hash_wire(index: usize, wire: &ArithWire, target: &ArithWire) -> ArithWire {
    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    hasher.update(wire.values);
    let digest = hasher.finalize(); // TODO: use variable size hashing
    let bytes = <[u8; LENGTH]>::try_from(digest.as_ref()).expect("digest too long");
    
    // Makes values for the wire of target size from the output of the hash function, recall that
    // the hash function outputs 256 bits, which means that the number of values * the number of
    // bits in a value must be less than or equal to 256.
    let wire = ArithWire {
        domain: target.domain,
        values: bytes,
    };
    wire.map(|x| x % wire.domain)
}



pub type Bytes = [u8; LENGTH];

pub fn hash(index: usize, x: u16, wire: &ArithWire) -> Bytes {
    hash!(index.to_be_bytes(), x.to_be_bytes(), wire)
}
