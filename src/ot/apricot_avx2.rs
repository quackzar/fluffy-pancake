use crate::util::*;

use crate::ot::common::*;
use crate::ot::polynomial::*;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::arch::x86_64::*;
use itertools::izip;
use crate::circuit::ProjKind::Map;


use crate::ot::bitmatrix::*;
use bitvec::prelude::*;
use crate::util;

const K: usize = 128;
const S: usize = 128;
const BLOCK_SIZE: usize = 8;
const K_BYTES: usize = K / 8;

pub struct Sender {
    pub bootstrap: Box<dyn ObliviousReceiver>,
}
pub struct Receiver {
    pub bootstrap: Box<dyn ObliviousSender>,
}
// -------------------------------------------------------------------------------------------------
// TEMPORARY: Helper functions
fn assert_compare_matrix(bitmatrix: &BitMatrix, raw: &Vec<Vec<u8>>, width: usize, height: usize) {
    for row_idx in 0..height {
        let raw_row = &raw[row_idx];
        for col_idx in 0..width {
            let raw_byte = raw_row[col_idx];
            for b in 0..8 {
                let raw_bit = (raw_byte >> b) & 1 > 0;
                let col_bit_index = col_idx * 8 + b;
                let bitmatrix_bit = bitmatrix[row_idx][col_bit_index];

                debug_assert_eq!(bitmatrix_bit, raw_bit);
            }
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Array/slice helpers
#[inline]
unsafe fn bool_vec(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(8 * bytes.len());
    for i in 0..bytes.len() {
        let s = bytes[i];
        for i in 0..8 {
            bits.push((s >> i) & 1 == 1);
        }
    }

    return bits;
}

#[inline]
fn array<const N: usize>(vector: &Vec<u8>) -> [u8; N] {
    return vector.as_slice().try_into().unwrap();
}

// -------------------------------------------------------------------------------------------------
// RNG
#[inline]
fn random_bytes(seed: [u8; 32], count: usize) -> BitVec<Block> {
    let mut vector = vec![0u8; count];
    let bytes = vector.as_mut_slice();

    let mut random = ChaCha20Rng::from_seed(seed);
    random.fill_bytes(bytes);

    return BitVec::from_vec(vector);
}
#[inline]
fn fill_random_bytes(seed: [u8; 32], bytes: &mut [u8]) {
    let mut random = ChaCha20Rng::from_seed(seed);
    random.fill_bytes(bytes);
}

// -------------------------------------------------------------------------------------------------
// Helpers for working with arrays of packed bits
#[inline]
fn xor(destination: &mut [u8], left: &[u8], right: &[u8]) {
    debug_assert_eq!(left.len(), right.len());
    debug_assert_eq!(left.len(), destination.len());

    // TODO: Vectorize this!
    for i in 0..left.len() {
        destination[i] = left[i] ^ right[i];
    }
}
fn xor_inplace(destination: &mut [u8], right: &[u8]) {
    debug_assert_eq!(right.len(), destination.len());

    // TODO: Vectorize this!
    for i in 0..right.len() {
        destination[i] ^= right[i];
    }
}

impl ObliviousSender for Sender {
    fn exchange(&self, msg: &Message, channel: &Channel<Vec<u8>>) -> Result<(), Error> {
        debug_assert!(msg.len() >= BLOCK_SIZE, "Message must be longer than {BLOCK_SIZE} bytes");
        debug_assert!(msg.len() % BLOCK_SIZE == 0, "Message length must be multiple of {BLOCK_SIZE} bytes");

        // TODO: What the hell are these?
        let transaction_properties = TransactionProperties{msg_size: msg.len()};
        validate_properties(&transaction_properties, channel)?;

        // "Constants" and things we need throughout
        let l = msg.len() + K + S;
        let l_bytes = l / 8;
        const K_BYTES: usize = K / 8;

        let matrix_width = K_BYTES;
        let matrix_height = l;
        let matrix_transposed_width = matrix_height / 8;
        let matrix_transposed_height = matrix_width * 8;

        let mut random = ChaCha20Rng::from_entropy();
        let (_, r) = channel;

        // Generate random delta
        let mut delta = [0u8; K_BYTES];
        let delta = delta.as_mut_slice();
        random.fill_bytes(delta);
        let delta_choices = unsafe { bool_vec(delta) };

        // do OT.
        let payload = self.bootstrap.exchange(&delta_choices, channel)?;
        let mut t_rows = Vec::with_capacity(matrix_height);
        for p in payload.iter() {
            let seed: [u8; 32] = array(p);
            let bits = random_bytes(seed, matrix_width);

            t_rows.push(bits);
        }
        // TODO: Lets not have this be a bit matrix!
        let t = BitMatrix::new(t_rows);

        // NOTE: OPTIMIZED/CLEANED DRAFT:
        // TODO: Lets not have this be a bit matrix!
        let u: BitMatrix = bincode::deserialize(&r.recv()?)?;
        /*
        let mut q = Vec::with_capacity(K);
        for i in K_BYTES {
            for b in 0..8 {
                let delta_bit = (delta[i] >> b) & 1;
                if delta_bit == 1 {

                } else {

                }
            }
        }
        */

        // NOTE: THIS IS WHAT WE ARE CURRENTLY OPTIMIZING/CLEANING
        let delta : BitVec<Block> = BitVec::from_vec(delta.to_vec());
        let mut q = Vec::with_capacity(K);
        for i in 0..K {
            if delta[i] {
                q.push(u[i].clone() ^ t[i].clone());
            } else {
                q.push(t[i].clone());
            }
        }

        // NOTE: END OF OPTIMIZING/CLEANING
        let q = BitMatrix::new(q);
        let q = q.transpose();

        // -- Check correlation --
        let chi: BitMatrix = bincode::deserialize(&r.recv()?)?;
        let vector_len = chi[0].len();
        let mut q_sum = Polynomial::new(vector_len);
        for (q, chi) in izip!(&q, &chi) {
            // We would like to work in the finite field F_(2^k) in order to achieve this we will
            // work on polynomials modulo x^k with coefficients in F_2. The coefficients can be
            // represented directly as strings of bits and the sum of two of these polynomials will
            // be the xor of these bitstrings (as dictated by the operations on the underlying field
            // to which the coefficients belong). The product of two elements will be the standard
            // polynomial products modulo x^k.
            let q = Polynomial::from_bitvec(q);
            let chi = Polynomial::from_bitvec(chi);

            // q_sum.add_assign(&q.mul(chi));
            q_sum.mul_add_assign(q, chi);



            // TODO: Depending on the performance of the bitvector it might be faster to add a check
            //       here, so we avoid doing unnecessary work the last iteration. (This depends
            //       greatly on the underlying implementation and the performance of the branch
            //       predictor)
            // polynomial_zero_bytes(&mut q_acc);
        }

        // TODO: *Maybe* doesn't work
        {
            let x_sum : Polynomial = bincode::deserialize(&r.recv()?)?;
            let t_sum : Polynomial = bincode::deserialize(&r.recv()?)?;
            let delta = Polynomial::from_bitvec(&delta);
            q_sum.mul_add_assign(&x_sum, delta);

            if t_sum != q_sum {
                return Err(Box::new(OTError::PolychromaticInput()));
            }
        }



        // -- Randomize --
        let (v0, v1): (Vec<Vec<u8>>, Vec<Vec<u8>>) = q[..msg.len()]
            .iter()
            .enumerate()
            .map(|(j, q)| {
                let v0 = hash!(j.to_be_bytes(), q.as_raw_slice()).to_vec();
                let q = q.clone() ^ &delta;
                let v1 = hash!(j.to_be_bytes(), q.as_raw_slice()).to_vec();
                (v0, v1)
            })
            .unzip();

        // -- DeROT --
        use aes_gcm::aead::{Aead, NewAead};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        let (d0, d1): (Vec<Vec<u8>>, Vec<Vec<u8>>) = izip!(&msg.0, v0, v1)
            .map(|([m0, m1], v0, v1)| {
                // encrypt the messages.
                let nonce = Nonce::from_slice(b"unique nonce");
                let cipher = Aes256Gcm::new(Key::from_slice(&v0));
                let c0 = cipher.encrypt(nonce, m0.as_slice()).unwrap();
                let cipher = Aes256Gcm::new(Key::from_slice(&v1));
                let c1 = cipher.encrypt(nonce, m1.as_slice()).unwrap();
                (c0, c1) // TODO: Proper error handling.
            })
            .unzip();

        let (s, _) = channel;
        let d0 = bincode::serialize(&d0)?;
        let d1 = bincode::serialize(&d1)?;
        s.send(d0)?;
        s.send(d1)?;

        return Ok(());
    }
}

impl ObliviousReceiver for Receiver {
    fn exchange(&self, choices: &[bool], channel: &Channel<Vec<u8>>) -> Result<Payload, Error> {
        debug_assert!(choices.len() >= BLOCK_SIZE, "Choices must be longer than {BLOCK_SIZE} bytes");
        debug_assert!(choices.len() % BLOCK_SIZE == 0, "Choices length must be multiple of {BLOCK_SIZE} bytes");

        // TODO: What the hell are these?
        let transaction_properties = TransactionProperties{msg_size: choices.len()};
        validate_properties(&transaction_properties, channel)?;

        // "Constants" and things we need throughout
        let l = choices.len() + K + S;
        let l_bytes = l / 8;
        const K_BYTES: usize = K / 8;

        let matrix_width = K_BYTES;
        let matrix_height = l;
        let matrix_transposed_width = matrix_height / 8;
        let matrix_transposed_height = matrix_width * 8;

        let mut random = ChaCha20Rng::from_entropy();
        let (s, _) = channel;

        // INITIALIZATION
        let bonus: [bool; K + S] = random.gen();
        let seed0: [u8; K * 32] = random.gen();
        let seed0: [[u8; 32]; K] = unsafe { std::mem::transmute(seed0) };
        let seed1: [u8; K * 32] = random.gen();
        let seed1: [[u8; 32]; K] = unsafe { std::mem::transmute(seed1) };

        let msg = Message::new(&seed0, &seed1);
        self.bootstrap.exchange(&msg, channel)?;

        /* The matrices are supposed to be this large (width by height):
            x: 128 by 288
            x^T: 288 by 128
            t0: 288 by 128
            t1: 288 by 128
            t: 128 by 288
            u: 288 by 128
        */

        // EXTENSION
        let mut t0_raw = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let row = t0_raw[row_idx].as_mut_slice();
            fill_random_bytes(seed0[row_idx], row);
        }
        println!("t0: {} by {}", t0_raw[0].len() * 8, t0_raw.len());

        let mut t1_raw = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let row = t1_raw[row_idx].as_mut_slice();
            fill_random_bytes(seed1[row_idx], row);
        }
        println!("t1: {} by {}", t1_raw[0].len() * 8, t1_raw.len());

        let t0: BitMatrix = t0_raw
            .iter()
            .map(|v | {
                BitVec::from_vec(v.clone())
            })
            .collect();
        /*
        let t0: BitMatrix = seed0
            .iter()
            .map(|&s| {
                random_bytes(s, matrix_width)
            })
            .collect();
        let t = t0.transpose();
        println!("t: {} by {}", t.dims().1, t.dims().0);
         */

        /*
        let t1: BitMatrix = seed1
            .iter()
            .map(|&s| {
                random_bytes(s, matrix_width)
            })
            .collect();
        */

        // TODO: Get rid of the choices bool array and just use this all the time instead
        let padded_choices = [choices, &bonus].concat();
        let mut packed_choices = vec![0u8; l_bytes];
        let packed_choices = packed_choices.as_mut_slice();
        for i in 0..l_bytes {
            for b in 0..8 {
                let index = i * 8 + b;
                if padded_choices[index] {
                    packed_choices[i] |= 1 << b;
                }
            }
        }

        let mut x_transposed = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let row = x_transposed[row_idx].as_mut_slice();
            for col_idx in 0..matrix_transposed_width {
                row[col_idx] = packed_choices[col_idx];
            }
            /*
            let choice = (packed_choices[row_idx / 8] >> row_idx % 8) & 1;
            if choice > 0 {
                // TODO: This can be vectorized
                for col_idx in 0..matrix_transposed_width {
                    row[col_idx] = 0xFF;
                }
            }
            */
        }
        println!("x^T: {} by {}", x_transposed[0].len() * 8, x_transposed.len());

        // TEMPORARY: Code to check that construct x_transposed correctly!
        /*
        let x: BitMatrix = padded_choices
            .iter()
            .map(|b| {
                if !*b {
                    vec![0x00u8; K / 8]
                } else {
                    vec![0xFFu8; K / 8]
                }
            })
            .map(BitVec::from_vec)
            .collect();
        let x = x.transpose();
        assert_compare_matrix(&x, &x_transposed, matrix_transposed_width, matrix_transposed_height);
        */

        let mut u_raw = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let u_row = u_raw[row_idx].as_mut_slice();

            let x_row = x_transposed[row_idx].as_slice();
            let t0_row = t0_raw[row_idx].as_slice();
            let t1_row = t1_raw[row_idx].as_slice();

            // TODO: This can be done more efficiently
            xor(u_row, x_row, t0_row);
            xor_inplace(u_row, t1_row);
        }
        println!("u: {} by {}", u_raw[0].len() * 8, u_raw.len());

        // TEMPORARY: Code to check that construct x_transposed correctly!
        /*
        let u: BitMatrix = izip!(x, t0, t1)
            .map(|(x, t0, t1)| {
                let mut u = x;
                u ^= &t0;
                u ^= &t1;
                u
            })
            .collect();
        assert_compare_matrix(&u, &u_raw, matrix_transposed_width, matrix_transposed_height);
        */

        let u = bincode::serialize(&u_raw)?;
        s.send(u)?;

        // -- Check correlation --
        let k_blocks = K / 8;
        let chi : BitMatrix = (0..l).map(|_| {
            let v = (0..k_blocks).map(|_| random.gen::<Block>()).collect();
            BitVec::from_vec(v)
        }).collect();
        s.send(bincode::serialize(&chi)?)?;

        let vector_len = chi[0].len();
        let mut x_sum = Polynomial::new(vector_len);
        let mut t_sum = Polynomial::new(vector_len);
        for (x, t, chi) in izip!(padded_choices, &t, &chi) {
            let t = Polynomial::from_bitvec(t);
            let chi = Polynomial::from_bitvec(chi);
            if x {
                x_sum.add_assign(chi)
            }

            // t_sum.add_assign(&t.mul(chi));
            t_sum.mul_add_assign(t, chi);

            // polynomial_zero_bytes(&mut t_acc);
        }
        s.send(bincode::serialize(&x_sum)?)?;
        s.send(bincode::serialize(&t_sum)?)?;


        // -- Randomize --
        let v: Vec<Vec<u8>> = t
            .into_iter()
            .enumerate()
            .map(|(j, t)| hash!(j.to_be_bytes(), t.as_raw_slice()).to_vec())
            .collect();

        // -- DeROT --
        use aes_gcm::aead::{Aead, NewAead};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        let (_, r) = channel;
        let d0: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let d1: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let y = izip!(v, choices, d0, d1)
            .map(|(v, c, d0, d1)| {
                let nonce = Nonce::from_slice(b"unique nonce");
                let cipher = Aes256Gcm::new(Key::from_slice(&v));
                let d = if *c { d1 } else { d0 };
                let c = cipher.decrypt(nonce, d.as_slice()).unwrap();
                c // TODO: Proper error handling.
            })
            .collect();
        Ok(y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_avx2_ot_receiver() {
        use crate::ot::chou_orlandi::{OTReceiver, OTSender};
        let (s1, r1) = ductile::new_local_channel();
        let (s2, r2) = ductile::new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);

        use std::thread;
        let h1 = thread::Builder::new()
            .name("Sender".to_string())
            .spawn(move || {
                let sender = Sender {
                    bootstrap: Box::new(OTReceiver),
                };
                let msg = Message::new(&[b"Hello"; 8 << 2], &[b"World"; 8 << 2]);
                sender.exchange(&msg, &ch1).unwrap();
            });

        let h2 = thread::Builder::new()
            .name("Receiver".to_string())
            .spawn(move || {
                let receiver = Receiver {
                    bootstrap: Box::new(OTSender),
                };
                let choices = [true; 8 << 2];
                let msg = receiver.exchange(&choices, &ch2).unwrap();
                assert_eq!(msg[0], b"World");
            });

        h1.unwrap().join().unwrap();
        h2.unwrap().join().unwrap();
    }
}

/*
unsafe fn tranpose_bitmatrix(source: *const u8, target: *mut u8, width: usize, height: usize) {
    for x in 0..width {
        for y in 0..height {
            let index = y * width + x;
            let byte = source[index];

            for x_bit in 0..8 {
                let bit = byte & (1 << x_bit) >> x_bit;

                let transposed_index = x * width + x;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    fn test_tranpose_bitmatrix() {
        unsafe {
            const WIDTH: usize = 4;
            const HEIGHT: usize = 2;
            let matrix = [
                0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00,
                0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11,
                0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11,
                0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11, 0b00, 0b11,
            ].as_ptr();

            let transposed = [0u8; WIDTH * HEIGHT].as_mut_ptr();
            let expected = [
                0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00,
                0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00,
                0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11,
                0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11,
                0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00,
                0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00,
                0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11,
                0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b00, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11, 0b11,
            ];

            for i in 0..(WIDTH * HEIGHT) {
                assert_eq!(expected[i], transposed[i]);
            }
        }
    }
}
*/