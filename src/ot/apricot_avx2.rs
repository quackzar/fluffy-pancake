use crate::common::*;

use crate::ot::common::*;
use crate::util::*;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use bitvec::prelude::*;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

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

fn print_matrix(matrix: &Vec<Vec<u8>>) {
    let width = matrix[0].len();
    let height = matrix.len();

    for row_idx in 0..height {
        for col_idx in 0..width {
            for b in 0..8 {
                let bit = (matrix[row_idx][col_idx] >> b) & 1;
                print!("{}", bit);
            }
        }
        println!();
    }
}

fn print_matrix_transposed(matrix: &Vec<Vec<u8>>) {
    let width = matrix[0].len();
    let height = matrix.len();

    for col_idx in 0..width {
        for b in 0..8 {
            for row_idx in 0..height {
                let bit = (matrix[row_idx][col_idx] >> b) & 1;
                print!("{}", bit);
            }
            println!();
        }
    }
}

fn print_bits(array: &[u8]) {
    for i in 0..array.len() {
        for b in 0..8 {
            let bit = (array[i] >> b) & 1;
            print!("{}", bit);
        }
    }
}

fn print_array(array: &[u8]) {
    println!("0x");
    for i in 0..array.len() {
        print!("{:02X}", array[i]);
    }
    println!();
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

    bits
}

#[inline]
fn array<const N: usize>(vector: &Vec<u8>) -> [u8; N] {
    return vector.as_slice().try_into().unwrap();
}

// -------------------------------------------------------------------------------------------------
// RNG
#[inline]
fn fill_random_bytes_from_seed(seed: &[u8; 32], bytes: &mut [u8]) {
    // TODO: Is it better to not have it be a reference?
    let mut random = ChaCha20Rng::from_seed(*seed);
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

#[inline]
fn xor_inplace(destination: &mut [u8], right: &[u8]) {
    debug_assert_eq!(right.len(), destination.len());

    // TODO: Vectorize this!
    for i in 0..right.len() {
        destination[i] ^= right[i];
    }
}

#[inline]
fn and(destination: &mut [u8], left: &[u8], right: &[u8]) {
    debug_assert_eq!(left.len(), right.len());
    debug_assert_eq!(left.len(), destination.len());

    // TODO: Vectorize this!
    for i in 0..left.len() {
        destination[i] = left[i] & right[i];
    }
}

#[inline]
fn and_inplace(destination: &mut [u8], right: &[u8]) {
    debug_assert_eq!(right.len(), destination.len());

    // TODO: Vectorize this!
    for i in 0..right.len() {
        destination[i] &= right[i];
    }
}

#[inline]
fn eq(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), right.len());

    // TODO: Vectorize this!
    for i in 0..left.len() {
        if left[i] != right[i] {
            return false;
        }
    }

    true
}

#[inline]
fn polynomial_mul_acc(destination: &mut [u8], left: &[u8], right: &[u8]) {
    use std::arch::x86_64::*;
    unsafe {
        let left_bytes = left.as_ptr() as *const __m128i;
        let right_bytes = right.as_ptr() as *const __m128i;
        let result_bytes = destination.as_mut_ptr() as *mut __m128i;

        let a = _mm_lddqu_si128(left_bytes);
        let b = _mm_lddqu_si128(right_bytes);

        let c = _mm_clmulepi64_si128(a, b, 0x00);
        let d = _mm_clmulepi64_si128(a, b, 0x11);
        let e = _mm_clmulepi64_si128(a, b, 0x01);
        let f = _mm_clmulepi64_si128(a, b, 0x10);

        let ef = _mm_xor_si128(e, f);
        let lower = _mm_slli_si128(ef, 64 / 8);
        let upper = _mm_srli_si128(ef, 64 / 8);

        let left = _mm_xor_si128(d, upper);
        let right = _mm_xor_si128(c, lower);
        let xor = _mm_xor_si128(left, right);

        *result_bytes = _mm_xor_si128(*result_bytes, xor);
    }
}

// -------------------------------------------------------------------------------------------------
// Polynomials

impl ObliviousSender for Sender {
    fn exchange(&self, msg: &Message, channel: &Channel<Vec<u8>>) -> Result<(), Error> {
        debug_assert!(
            msg.len() >= BLOCK_SIZE,
            "Message must be longer than {BLOCK_SIZE} bytes"
        );
        debug_assert!(
            msg.len() % BLOCK_SIZE == 0,
            "Message length must be multiple of {BLOCK_SIZE} bytes"
        );

        // TODO: What the hell are these?
        let transaction_properties = TransactionProperties {
            msg_size: msg.len(),
            protocol: "Apricot AVX2".to_string(),
        };
        validate_properties(&transaction_properties, channel)?;

        // "Constants" and things we need throughout
        let l = msg.len() + K + S;
        let _l_bytes = l / 8;
        const K_BYTES: usize = K / 8;

        let matrix_width = K_BYTES;
        let matrix_height = l;
        let matrix_transposed_width = matrix_height / 8;
        let matrix_transposed_height = matrix_width * 8;

        let mut random = ChaCha20Rng::from_seed([0u8; 32]);
        let (s, r) = channel;

        // Generate random delta
        let mut delta = [0u8; K_BYTES];
        let delta = delta.as_mut_slice();
        random.fill_bytes(delta);
        let delta_choices = unsafe { bool_vec(delta) };

        // do OT.
        let payloads = self.bootstrap.exchange(&delta_choices, channel)?;
        let mut t_raw = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let payload = &payloads[row_idx];
            let seed: [u8; 32] = array(payload);
            let row = t_raw[row_idx].as_mut_slice();
            fill_random_bytes_from_seed(&seed, row);
        }

        let u_raw: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let mut q_orig = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let row = q_orig[row_idx].as_mut_slice();
            let d = (delta[row_idx / 8] >> (row_idx % 8)) & 1;
            if d == 1 {
                xor_inplace(row, u_raw[row_idx].as_slice());
            }
            xor_inplace(row, t_raw[row_idx].as_slice());
        }

        let mut q_raw = vec![vec![0u8; matrix_width]; matrix_height];
        for row_idx in 0..matrix_transposed_height {
            for col_idx in 0..matrix_transposed_width {
                let source_byte = q_orig[row_idx][col_idx];
                for b in 0..8 {
                    let source_bit = (source_byte >> b) & 1;

                    let target_row = col_idx * 8 + b;
                    let target_col = row_idx / 8;
                    let target_shift = row_idx % 8;

                    q_raw[target_row][target_col] |= source_bit << target_shift;
                }
            }
        }

        // -- Check correlation --
        let chi: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;

        let mut q_sum = vec![0u8; matrix_width];
        for row_idx in 0..matrix_height {
            let q_row = q_raw[row_idx].as_slice();
            let chi_row = chi[row_idx].as_slice();

            polynomial_mul_acc(q_sum.as_mut_slice(), q_row, chi_row);
        }

        let x_sum: Vec<u8> = bincode::deserialize(&r.recv()?)?;
        let t_sum: Vec<u8> = bincode::deserialize(&r.recv()?)?;
        polynomial_mul_acc(q_sum.as_mut_slice(), x_sum.as_slice(), delta);

        if !eq(t_sum.as_slice(), q_sum.as_slice()) {
            return Err(Box::new(OTError::PolychromaticInput()));
        }

        // -- Randomize --
        // TODO: Should we put msg.len() in a variable?
        let mut d0_raw = Vec::with_capacity(msg.len());
        let mut d1_raw = Vec::with_capacity(msg.len());
        let nonce = Nonce::from_slice(b"unique nonce");
        for row_idx in 0..msg.len() {
            let v0 = hash!(row_idx.to_be_bytes(), q_raw[row_idx].as_slice());

            // TODO: Can we do this in a better way?
            let mut q_delta = vec![0u8; matrix_width];
            xor(q_delta.as_mut_slice(), q_raw[row_idx].as_slice(), delta);
            let v1 = hash!(row_idx.to_be_bytes(), q_delta);

            let m0 = msg.0[row_idx][0].as_slice();
            let cipher = Aes256Gcm::new(Key::from_slice(v0.as_slice()));
            d0_raw.push(cipher.encrypt(nonce, m0).unwrap());

            let m1 = msg.0[row_idx][1].as_slice();
            let cipher = Aes256Gcm::new(Key::from_slice(v1.as_slice()));
            d1_raw.push(cipher.encrypt(nonce, m1).unwrap());
        }

        s.send(bincode::serialize(&d0_raw)?)?;
        s.send(bincode::serialize(&d1_raw)?)?;

        Ok(())
    }
}

impl ObliviousReceiver for Receiver {
    fn exchange(&self, choices: &[bool], channel: &Channel<Vec<u8>>) -> Result<Payload, Error> {
        debug_assert!(
            choices.len() >= BLOCK_SIZE,
            "Choices must be longer than {BLOCK_SIZE} bytes"
        );
        debug_assert!(
            choices.len() % BLOCK_SIZE == 0,
            "Choices length must be multiple of {BLOCK_SIZE} bytes"
        );

        // TODO: What the hell are these?
        let transaction_properties = TransactionProperties {
            msg_size: choices.len(),
            protocol: "Apricot AVX2".to_string(),
        };
        validate_properties(&transaction_properties, channel)?;

        // "Constants" and things we need throughout
        let l = choices.len() + K + S;
        let l_bytes = l / 8;
        const K_BYTES: usize = K / 8;

        let matrix_width = K_BYTES;
        let matrix_height = l;
        let matrix_transposed_width = matrix_height / 8;
        let matrix_transposed_height = matrix_width * 8;

        let mut random = ChaCha20Rng::from_seed([0u8; 32]);
        let (s, r) = channel;

        // INITIALIZATION
        let bonus: [bool; K + S] = random.gen();
        let seed0: [[u8; 32]; K] = random.gen();
        let seed1: [[u8; 32]; K] = random.gen();

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
            fill_random_bytes_from_seed(&seed0[row_idx], row);
        }

        // TODO: It might be beneficial to do this in the loop for t0!
        // TODO: Can we vectorize the transposing?
        let mut t_raw = vec![vec![0u8; matrix_width]; matrix_height];
        for row_idx in 0..matrix_transposed_height {
            for col_idx in 0..matrix_transposed_width {
                let source_byte = t0_raw[row_idx][col_idx];
                for b in 0..8 {
                    let source_bit = (source_byte >> b) & 1;

                    let target_row = col_idx * 8 + b;
                    let target_col = row_idx / 8;
                    let target_shift = row_idx % 8;

                    t_raw[target_row][target_col] |= source_bit << target_shift;
                }
            }
        }

        let mut t1_raw = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let row = t1_raw[row_idx].as_mut_slice();
            fill_random_bytes_from_seed(&seed1[row_idx], row);
        }

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

        let mut u_raw = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let u_row = u_raw[row_idx].as_mut_slice();

            // TODO: This can be done more efficiently
            let t0_row = t0_raw[row_idx].as_slice();
            let t1_row = t1_raw[row_idx].as_slice();
            xor(u_row, t0_row, t1_row);

            let x_row = x_transposed[row_idx].as_slice();
            xor_inplace(u_row, x_row);
        }
        s.send(bincode::serialize(&u_raw)?)?;

        // -- Check correlation --
        let mut chi_raw = vec![vec![0u8; matrix_width]; matrix_height];
        for row_idx in 0..matrix_height {
            let row = chi_raw[row_idx].as_mut_slice();
            random.fill_bytes(row);
        }
        s.send(bincode::serialize(&chi_raw)?)?;

        let mut x_sum = vec![0u8; matrix_width];
        let mut t_sum = vec![0u8; matrix_width];
        for row_idx in 0..matrix_height {
            let chi_row = chi_raw[row_idx].as_slice();
            if padded_choices[row_idx] {
                xor_inplace(x_sum.as_mut_slice(), chi_row);
            }

            let t_row = t_raw[row_idx].as_slice();
            polynomial_mul_acc(t_sum.as_mut_slice(), t_row, chi_row);
        }
        s.send(bincode::serialize(&x_sum)?)?;
        s.send(bincode::serialize(&t_sum)?)?;

        // -- Randomize --
        let mut v_raw = vec![vec![0u8; 32]; matrix_height];
        for row_idx in 0..matrix_height {
            let row = v_raw[row_idx].as_mut_slice();
            let hash = hash!(row_idx.to_be_bytes(), t_raw[row_idx].as_slice());
            xor_inplace(row, &hash);
        }

        // -- DeROT --
        let d0: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let d1: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let mut y: Vec<Vec<u8>> = Vec::with_capacity(choices.len());
        for i in 0..choices.len() {
            let nonce = Nonce::from_slice(b"unique nonce");
            let cipher = Aes256Gcm::new(Key::from_slice(v_raw[i].as_slice()));
            // TODO: This we can probably optimize
            let d = if choices[i] {
                d1[i].as_slice()
            } else {
                d0[i].as_slice()
            };

            let c = cipher.decrypt(nonce, d).unwrap();
            y.push(c);
        }

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
