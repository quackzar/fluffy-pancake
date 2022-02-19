use core::ops;
use std::fs::File;
use rand::Rng;
use ring::digest::Context;
use ring::digest::SHA256;
use std::cmp;
use std::iter;
use std::io::{Read, Write};

use crate::util::*;


// TODO: Improve internal representation and implement from/into.
#[derive(Debug, Clone)]
pub struct ArithWire {
    pub lambda: u64,
    pub domain: u64,
    values: Vec<u64>,
}

impl ops::Add<&ArithWire> for &ArithWire {
    type Output = ArithWire;
    fn add(self, rhs: &ArithWire) -> ArithWire {
        debug_assert_eq!(self.lambda, rhs.lambda, "Lambdas doesn't match.");
        debug_assert_eq!(self.domain, rhs.domain, "Domain not matching");

        let domain = self.domain;
        let lambda = self.lambda;
        let values = self
            .values
            .iter()
            .zip(rhs.values.iter())
            .map(|(a, b)| (a + b) % domain)
            .collect();

        ArithWire {
            domain,
            values,
            lambda,
        }
    }
}

impl ops::Sub<&ArithWire> for &ArithWire {
    type Output = ArithWire;
    fn sub(self, rhs: &ArithWire) -> Self::Output {
        debug_assert_eq!(self.lambda, rhs.lambda, "Lambdas doesn't match.");
        debug_assert_eq!(self.domain, rhs.domain, "Domain not matching");

        let domain = self.domain;
        let lambda = self.lambda;
        let values = self
            .values
            .iter()
            .zip(rhs.values.iter())
            .map(|(a, b)| (a + (domain - b)) % domain)
            .collect();

        ArithWire {
            domain,
            values,
            lambda,
        }
    }
}

impl ops::Neg for &ArithWire {
    type Output = ArithWire;
    fn neg(self) -> ArithWire {
        return ArithWire {
            domain: self.domain,
            lambda: self.lambda, // this probably works
            values: self.values.iter().map(|x| self.domain - x).collect(),
        };
    }
}

impl ops::Mul<u64> for &ArithWire {
    type Output = ArithWire;
    #[inline]
    fn mul(self, rhs: u64) -> ArithWire {
        let domain = self.domain;
        let lambda = self.lambda;
        let values = self.values.iter().map(|x| (x * rhs) % domain).collect();
        ArithWire {
            domain,
            values,
            lambda,
        }
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
            lambda: 0,
            values: Vec::new(),
        }
    }

    pub(crate) fn new(domain: u64, lambda: u64) -> ArithWire {
        let mut values = vec![0u64; lambda as usize];
        for i in 0..lambda {
            values[i as usize] = rng(domain + 1);
        }

        ArithWire {
            values,
            lambda,
            domain,
        }
    }

    pub(crate) fn delta(domain: u64, lambda: u64) -> ArithWire {
        let mut values = vec![0u64; lambda as usize];
        for i in 0..lambda {
            values[i as usize] = rng(domain + 1);
        }
        values[(lambda - 1) as usize] = 1;

        ArithWire {
            values,
            lambda,
            domain,
        }
    }

    #[inline]
    pub(crate) fn tau(&self) -> u64 {
        self.values[(self.lambda - 1) as usize]
    }

    pub(crate) fn from_bytes(bytes: &[u8], lambda: u64, domain: u64) -> ArithWire {
        let mut values = Vec::with_capacity(lambda as usize);
        let bits_per_value = log2(domain);
        let bits_available = (bytes.len() * 8) as u64;
        debug_assert!(bits_per_value * lambda <= bits_available);

        let mut bits_in_byte = 8;
        let mut byte_idx = 0;
        for _ in 0..lambda {
            let mut bits_wanted = bits_per_value;
            let mut value: u64 = 0;

            // Grab bits up until the next full byte
            if bits_in_byte != 8 {
                let bits_to_grab = cmp::min(bits_in_byte, bits_wanted);
                bits_wanted -= bits_to_grab;

                let mask_shift = 8 - bits_to_grab;
                let mask = ((0xFFu8 << mask_shift) >> mask_shift) as u8;
                let bits = bytes[byte_idx] & mask;

                if bits_to_grab == bits_in_byte as u64 {
                    bits_in_byte = 8;
                    byte_idx += 1;
                } else {
                    bits_in_byte -= bits_to_grab;
                }

                value |= bits as u64;
                if bits_wanted != 0 {
                    value <<= cmp::min(8, bits_wanted);
                }
            }

            // Grab as many full bytes as we need
            // From the previous code we know that at this point either we want no more bits or the
            // number of bits in the current byte from the hash will be equal to 8, thus we do not need
            // to update bits_in_byte.
            while bits_wanted >= 8 {
                value |= bytes[byte_idx] as u64;
                byte_idx += 1;
                bits_wanted -= 8;

                if bits_wanted < 8 {
                    value <<= bits_wanted;
                    break;
                }

                value <<= 8;
            }

            // Grab any remaining bits
            if bits_wanted != 0 {
                let mask_shift = 8 - bits_wanted;

                let mask = ((0xFFu8 << mask_shift) >> mask_shift) as u8;
                let bits = (bytes[byte_idx] & mask) as u8;

                value |= bits as u64;
                bits_in_byte -= bits_wanted;
            }

            values.push(value % domain);
        }

        debug_assert_eq!(values.len(), lambda as usize);
        debug_assert!(values.iter().all(|v| v < &domain), "value not under domain");

        ArithWire {
            domain,
            lambda,
            values,
        }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let bits_per_value = log2(self.domain);
        let wire_bits = self.lambda * bits_per_value;
        let wire_bytes_truncated = wire_bits / 8;
        let wire_bytes = if wire_bytes_truncated * 8 != wire_bits {
            wire_bytes_truncated + 1
        } else {
            wire_bytes_truncated
        };
        let mut bytes = vec![0u8; wire_bytes as usize];

        let mut byte_idx = 0;
        let mut byte_bits = 8;
        for value_ref in &self.values {
            let mut value = *value_ref;
            let mut bits_remaining = bits_per_value;
            while bits_remaining != 0 {
                let bits_to_grab = cmp::min(8, cmp::min(bits_remaining, byte_bits));
                let mask_shift = 8 - bits_to_grab;
                let source_mask = ((0xFFu8 << mask_shift) >> mask_shift) as u64;

                bytes[byte_idx] <<= bits_to_grab;
                bytes[byte_idx] |= (value & source_mask) as u8;
                byte_bits -= bits_to_grab;
                if byte_bits == 0 {
                    byte_bits = 8;
                    byte_idx += 1;
                }

                value >>= bits_to_grab;
                bits_remaining -= bits_to_grab;
            }
        }

        bytes
    }

    fn serialize(&self, file: &mut File) {
        write_u64(self.lambda, file);
        write_u64(self.domain, file);
        for value in &self.values {
            write_u64(*value, file);
        }
    }
    fn deserialize(file: &mut File) -> ArithWire {
        let lambda = read_u64(file);
        let domain = read_u64(file);

        let mut values = Vec::with_capacity(lambda as usize);
        for _ in 0..lambda {
            values.push(read_u64(file));
        }

        ArithWire {
            lambda,
            domain,
            values
        }
    }
}

fn serialize_wires(wires: &Vec<ArithWire>, file: &mut File) {
    // TODO(frm): We could probably do with a u16 or u24!
    write_u64(wires.len() as u64, file);
    for wire in wires {
        wire.serialize(file);
    }
}
fn deserialize_wires(file: &mut File) -> Vec<ArithWire> {
    let length = read_u64(file);
    let mut wires = Vec::with_capacity(length as usize);

    for _ in 0..length {
        wires.push(ArithWire::deserialize(file));
    }

    wires
}

pub fn hash_wire(index: usize, wire: &ArithWire, target: &ArithWire) -> ArithWire {
    let mut context = Context::new(&SHA256);
    context.update(&index.to_be_bytes());
    context.update(&wire.lambda.to_be_bytes());
    context.update(&wire.domain.to_be_bytes());
    for v in &wire.values {
        context.update(&v.to_be_bytes());
    }

    let digest = context.finish();
    let bytes = digest.as_ref();

    // Makes values for the wire of target size from the output of the hash function, recall that
    // the hash function outputs 256 bits, which means that the number of values * the number of
    // bits in a value must be less than or equal to 256.
    ArithWire::from_bytes(bytes, target.lambda, target.domain)
}



pub fn hash(index: u64, x: u64, wire: &ArithWire) -> u64 {
    let mut context = Context::new(&SHA256);
    context.update(&index.to_be_bytes());
    context.update(&x.to_be_bytes());
    context.update(&wire.lambda.to_be_bytes());
    context.update(&wire.domain.to_be_bytes());
    for value in &wire.values {
        context.update(&value.to_be_bytes());
    }

    let digest = context.finish();
    let bytes = digest.as_ref();

    u64::from_be_bytes(bytes[..8].try_into().unwrap())
}
