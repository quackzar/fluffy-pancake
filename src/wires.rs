use crate::util::*;
use core::ops;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::iter;

type Domain = u16;


// NOTE: Security parameter depends on hash function.
const SECURITY_PARAM: usize = 256; // bits used total
const LENGTH: usize = SECURITY_PARAM / 8; // bytes used

// Maybe use domain as const generic?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wire {
    pub domain: u16,
    values: [u8; LENGTH],
}

impl ops::Add<&Wire> for &Wire {
    type Output = Wire;
    fn add(self, rhs: &Wire) -> Wire {
        self.map_with(rhs, |a, b| (a + b) % self.domain)
    }
}

impl ops::Sub<&Wire> for &Wire {
    type Output = Wire;
    fn sub(self, rhs: &Wire) -> Self::Output {
        self.map_with(rhs, |a, b| (a + (self.domain - b)) % self.domain)
    }
}

impl ops::Neg for &Wire {
    type Output = Wire;
    fn neg(self) -> Wire {
        self.map(|x| (self.domain - x) % self.domain)
    }
}

impl ops::Mul<u16> for &Wire {
    type Output = Wire;
    #[inline]
    fn mul(self, rhs: u16) -> Wire {
        self.map(|x| (((x as u32) * (rhs as u32)) % (self.domain as u32)) as u16)
    }
}

impl iter::Sum for Wire {
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let init = iter.next().unwrap();
        iter.fold(init, |acc: Wire, w: Wire| &acc + &w)
    }
}

impl Wire {
    pub(crate) fn empty() -> Wire {
        Wire {
            domain: 0,
            values: [0; LENGTH],
        }
    }

    fn map<F>(&self, op: F) -> Wire
    where
        F: Fn(u16) -> u16,
    {
        let domain = self.domain;
        // TODO: change size based on domain
        let input: [u16; LENGTH / 2] = bytemuck::cast(self.values);
        let mut output = [0u16; LENGTH / 2];
        for i in 0..output.len() {
            output[i] = op(input[i]);
        }
        debug_assert!(
            output.iter().all(|&x| x < self.domain),
            "output out of domain {} {:?}",
            domain,
            output
        );
        let values = bytemuck::cast(output);
        Wire { domain, values }
    }


    fn map_with<F>(&self, other: &Wire, op: F) -> Wire
    where
        F: Fn(u16, u16) -> u16,
    {
        debug_assert_eq!(self.domain, other.domain, "Domain not matching");
        let l1: [u16; LENGTH / 2] = bytemuck::cast(self.values);
        let l2: [u16; LENGTH / 2] = bytemuck::cast(other.values);

        let mut output = [0u16; LENGTH / 2];
        for i in 0..output.len() {
            output[i] = op(l1[i], l2[i]);
        }
        debug_assert!(output.iter().all(|&x| x < self.domain));
        let values = bytemuck::cast(output);
        let domain = self.domain;
        Wire { domain, values }
    }

    pub(crate) fn new(domain: u16) -> Wire {
        let mut values = [0u16; LENGTH / 2];
        for i in 0..(LENGTH / 2) {
            values[i] = rng(domain);
        }
        debug_assert!(values.iter().all(|&x| x < domain));
        let values = bytemuck::cast(values);
        Wire { values, domain }
    }

    pub(crate) fn delta(domain: u16) -> Wire {
        let mut values = [0u16; LENGTH / 2];
        for i in 0..(LENGTH / 2) {
            values[i] = rng(domain);
        }
        values[LENGTH / 2 - 1] = 1;
        debug_assert!(values.iter().all(|&x| x < domain));
        let values = bytemuck::cast(values);
        Wire { values, domain }
    }

    #[inline]
    pub(crate) fn color(&self) -> u16 {
        bytemuck::cast::<[u8; LENGTH], [u16; LENGTH / 2]>(self.values)[LENGTH / 2 - 1]
    }
}

impl AsRef<[u8]> for &Wire {
    fn as_ref(&self) -> &[u8] {
        &self.values
    }
}

pub fn hash_wire(index: usize, wire: &Wire, target: &Wire) -> Wire {
    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    hasher.update(wire);
    let digest = hasher.finalize(); // TODO: use variable size hashing
    let bytes = <[u8; LENGTH]>::try_from(digest.as_ref()).expect("digest too long");

    // Makes values for the wire of target size from the output of the hash function, recall that
    // the hash function outputs 256 bits, which means that the number of values * the number of
    // bits in a value must be less than or equal to 256.
    let wire = Wire {
        domain: target.domain,
        values: bytes,
    };
    wire.map(|x| x % wire.domain)
}

pub type Bytes = [u8; LENGTH];

pub fn hash(index: usize, x: u16, wire: &Wire) -> Bytes {
    hash!(index.to_be_bytes(), x.to_be_bytes(), wire)
}
