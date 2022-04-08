use crate::util::*;
use core::ops;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::iter;

// Maybe use domain as const generic?
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Wire {
    domain: Domain,
    values: WireBytes,
}

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum Domain {
    Binary,
    U8(u8),
    U16(u16),
    U8MAX,
    U16MAX,
}

impl Domain {
    const fn num(self) -> u16 {
        match self {
            Domain::Binary => 2,
            Domain::U8(m) => m as u16,
            Domain::U16(m) => m,
            Domain::U8MAX => (u8::max_value() as u16) + 1,
            Domain::U16MAX => 0,
        }
    }

    fn new(m: u16) -> Self {
        const U8_MAX: u16 = u8::max_value() as u16;
        const U16_MAX: u16 = u16::max_value();
        if m == 0 {
            Self::U16MAX
        } else if m == 2 {
            Self::Binary
        } else if m < U8_MAX {
            Self::U8(m as u8)
        } else if m == U8_MAX + 1 {
            Self::U8MAX
        } else if m < U16_MAX {
            Self::U16(m)
        } else {
            panic!("Bad Domain: {}", m);
        }
    }
}

impl ops::Add<&Wire> for &Wire {
    type Output = Wire;
    fn add(self, rhs: &Wire) -> Wire {
        match self.domain {
            Domain::Binary => self.map_with(rhs, |a, b| a ^ b),
            Domain::U8(m) => self.map_with(rhs, |a, b| (a + b) % m),
            Domain::U16(m) => self.map_with_as_u16(rhs, |a, b| (a + b) % m),
            _ => panic!("Add not defined for this domain {}", self.domain()),
        }
    }
}

impl ops::Sub<&Wire> for &Wire {
    type Output = Wire;
    fn sub(self, rhs: &Wire) -> Self::Output {
        match self.domain {
            Domain::Binary => self.map_with(rhs, |a, b| a ^ b),
            Domain::U8(m) => self.map_with(rhs, |a, b| (a + (m - b)) % m),
            Domain::U16(m) => self.map_with_as_u16(rhs, |a, b| (a + (m - b)) % m),
            _ => panic!("Sub not defined for this domain {}", self.domain()),
        }
    }
}

impl ops::Neg for &Wire {
    type Output = Wire;
    fn neg(self) -> Wire {
        match self.domain {
            Domain::Binary => self.map(|x: u8| 0xFF ^ x),
            Domain::U8(m) => self.map(|x: u8| (m - x) % m),
            Domain::U16(m) => self.map_as_u16(|x: u16| (m - x) % m),
            _ => panic!("Neg not defined for this domain {}", self.domain()),
        }
    }
}

impl ops::Mul<u16> for &Wire {
    type Output = Wire;
    #[inline]
    fn mul(self, rhs: u16) -> Wire {
        debug_assert!(rhs < self.domain());
        match self.domain {
            Domain::Binary => self.map(|b| if rhs == 0 { 0 } else { b }),
            Domain::U8(m) => self.map(|x| (((x as u16) * (rhs as u16)) % (m as u16)) as u8),
            Domain::U16(m) => {
                self.map_as_u16(|x| (((x as u32) * (rhs as u32)) % (m as u32)) as u16)
            }
            _ => panic!("Mul not defined for this domain"),
        }
    }
}

impl iter::Sum for Wire {
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let init = iter.next().unwrap();
        iter.fold(init, |acc: Self, w: Self| &acc + &w)
    }
}

impl Wire {
    pub(crate) const fn empty() -> Self {
        Self {
            domain: Domain::Binary,
            values: [0; LENGTH],
        }
    }

    fn map<F>(&self, op: F) -> Self
    where
        F: Fn(u8) -> u8,
    {
        let domain = self.domain;
        let input = self.values;
        let mut values = [0u8; LENGTH];
        for i in 0..values.len() {
            values[i] = op(input[i]);
        }
        Self { domain, values }
    }

    fn map_as_u16<F>(&self, op: F) -> Self
    where
        F: Fn(u16) -> u16,
    {
        let domain = self.domain;
        let input: [u16; LENGTH / 2] = bytemuck::cast(self.values);
        let mut output = [0u16; LENGTH / 2];
        for i in 0..output.len() {
            output[i] = op(input[i]);
        }
        debug_assert!(
            output.iter().all(|&x| x < self.domain()),
            "output out of domain {} {:?}",
            self.domain(),
            output
        );
        let values = bytemuck::cast(output);
        Self { domain, values }
    }

    fn map_with<F>(&self, other: &Self, op: F) -> Self
    where
        F: Fn(u8, u8) -> u8,
    {
        debug_assert_eq!(self.domain, other.domain, "Domain not matching");
        let mut values = [0u8; LENGTH];
        for (i,v) in values.iter_mut().enumerate() {
            *v = op(self.values[i], other.values[i]);
        }
        let domain = self.domain;
        Self { domain, values }
    }

    fn map_with_as_u16<F>(&self, other: &Self, op: F) -> Self
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
        debug_assert!(
            output.iter().all(|&x| x < self.domain()),
            "output out of domain {} {:?}",
            self.domain(),
            output
        );
        let values = bytemuck::cast(output);
        let domain = self.domain;
        Self { domain, values }
    }

    pub fn new(domain: u16) -> Self {
        let domain = Domain::new(domain);
        let mut values = [0u8; LENGTH];
        match domain {
            Domain::Binary | Domain::U8MAX | Domain::U16MAX => {
                values = rand::random();
            }
            Domain::U8(m) => {
                for v in values.iter_mut() {
                    *v = rand::thread_rng().gen_range(0..m);
                }
            }
            Domain::U16(m) => {
                let mut val: [u16; LENGTH / 2] = bytemuck::cast(values);
                for v in val.iter_mut() {
                    *v = rand::thread_rng().gen_range(0..m);
                }
                values = bytemuck::cast(val);
            }
        }
        Self { values, domain }
    }

    pub fn delta(domain: u16) -> Self {
        let mut wire = Self::new(domain);
        match wire.domain {
            Domain::Binary => {
                // endianness?
                wire.values[LENGTH - 1] |= 1;
            }
            Domain::U8(_) | Domain::U8MAX => {
                wire.values[LENGTH - 1] = 1;
            }
            Domain::U16(_) | Domain::U16MAX => {
                let mut v: [u16; LENGTH / 2] = bytemuck::cast(wire.values);
                v[LENGTH / 2 - 1] = 1;
                wire.values = bytemuck::cast(v);
            }
        }
        wire
    }

    #[inline]
    pub fn color(&self) -> u16 {
        match self.domain {
            Domain::Binary => (self.values[LENGTH - 1] & 1) as u16, // endianness?
            Domain::U8(_) | Domain::U8MAX => self.values[LENGTH - 1] as u16,
            Domain::U16(_) | Domain::U16MAX => {
                let v: [u16; LENGTH / 2] = bytemuck::cast(self.values);
                v[LENGTH / 2 - 1]
            }
        }
    }

    #[inline]
    pub const fn domain(&self) -> u16 {
        self.domain.num()
    }

    pub fn from_array(values: WireBytes, domain: Domain) -> Self {
        let wire = Self { domain, values };
        match domain {
            Domain::Binary | Domain::U8MAX | Domain::U16MAX => wire,
            Domain::U8(m) => wire.map(|x| x % m),
            Domain::U16(m) => wire.map_as_u16(|x| x % m),
        }
    }

    pub fn from_bytes(values: &[u8], domain: Domain) -> Self {
        let wire = Self { domain, values: values.try_into().unwrap() };
        match domain {
            Domain::Binary | Domain::U8MAX | Domain::U16MAX => wire,
            Domain::U8(m) => wire.map(|x| x % m),
            Domain::U16(m) => wire.map_as_u16(|x| x % m),
        }
    }

    pub const fn to_bytes(&self) -> WireBytes {
        self.values
    }
}

impl AsRef<[u8]> for Wire {
    fn as_ref(&self) -> &[u8] {
        &self.values
    }
}

pub fn hash_wire(index: usize, wire: &Wire, target: &Wire) -> Wire {
    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    hasher.update(wire);
    let digest = hasher.finalize(); // TODO: use variable size hashing
    let bytes = <WireBytes>::try_from(digest.as_ref()).expect("digest too long");

    // Makes values for the wire of target size from the output of the hash function, recall that
    // the hash function outputs 256 bits, which means that the number of values * the number of
    // bits in a value must be less than or equal to 256.
    Wire::from_array(bytes, target.domain)
}

pub fn hash(index: usize, x: u16, wire: &Wire) -> WireBytes {
    hash!(index.to_be_bytes(), x.to_be_bytes(), wire)
}
