use crate::util::*;
use crate::ot::common::*;
use crate::common::*;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};

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

    return true;
}

#[inline]
fn matrix_transpose(source: &Vec<Vec<u8>>, target: &mut Vec<Vec<u8>>, transposed_height: usize, transposed_width: usize) {
    for row_idx in 0..transposed_height {
        for col_idx in 0..transposed_width {
            let source_byte = source[row_idx][col_idx];
            for b in 0..8 {
                let source_bit = (source_byte >> b) & 1;
                let target_row = col_idx * 8 + b;
                let target_col = row_idx / 8;
                let target_shift = row_idx % 8;

                target[target_row][target_col] |= source_bit << target_shift;
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[inline]
#[cfg(target_arch = "x86_64")]
unsafe fn _mm_slli_si128_1(value: __m128i) -> __m128i {
    const SHIFT: i32 = 1;
    let carry = _mm_bslli_si128(value, 8);
    let carry = _mm_srli_epi64(carry, 64 - SHIFT);
    let value = _mm_slli_epi64(value, SHIFT);
    return _mm_or_si128(value, carry);
}
#[inline]
#[cfg(target_arch = "x86_64")]
unsafe fn _mm_slli_si128_2(value: __m128i) -> __m128i {
    const SHIFT: i32 = 2;
    let carry = _mm_bslli_si128(value, 8);
    let carry = _mm_srli_epi64(carry, 64 - SHIFT);
    let value = _mm_slli_epi64(value, SHIFT);
    return _mm_or_si128(value, carry);
}
#[inline]
#[cfg(target_arch = "x86_64")]
unsafe fn _mm_slli_si128_7(value: __m128i) -> __m128i {
    const SHIFT: i32 = 7;
    let carry = _mm_bslli_si128(value, 8);
    let carry = _mm_srli_epi64(carry, 64 - SHIFT);
    let value = _mm_slli_epi64(value, SHIFT);
    return _mm_or_si128(value, carry);
}

#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn polynomial_gf128_reduce(x32: __m128i, x10: __m128i) -> __m128i {
    use std::arch::x86_64::*;
    let x2 = _mm_extract_epi64(x32, 0) as u64;
    let x3 = _mm_extract_epi64(x32, 1) as u64;

    let a = x3 >> 63;
    let b = x3 >> 62;
    let c = x3 >> 57;
    let d = x2 ^ a ^ b ^ c;

    let x3d = _mm_set_epi64x(x3 as i64, d as i64); // maybe here?
    let e = _mm_slli_si128_1(x3d);
    let f = _mm_slli_si128_2(x3d);
    let g = _mm_slli_si128_7(x3d);

    let h = _mm_xor_si128(x3d, e);
    let h = _mm_xor_si128(h, f);
    let h = _mm_xor_si128(h, g);

    return _mm_xor_si128(h, x10);
}

#[inline]
#[cfg(target_arch = "x86_64")]
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

        let reduced = polynomial_gf128_reduce(left, right);
        *result_bytes = _mm_xor_si128(*result_bytes, reduced);
    }
}

#[inline]
#[cfg(target_arch = "aarch64")]
fn polynomial_mul_acc(destination: &mut [u8], left: &[u8], right: &[u8]) {
    debug_assert!(left.len() == 128);
    debug_assert!(right.len() == 128);
    use core::arch::aarch64::*;

    #[inline(always)]
    unsafe fn pmull<const A_LANE: i32, const B_LANE: i32>(a: poly64x2_t, b: poly64x2_t) -> u128 {
        vmull_p64(vgetq_lane_p64(a, A_LANE), vgetq_lane_p64(b, B_LANE))
    }

    const fn gf128_reduce(x32: u128, x10: u128) -> u128 {
        let x2 = x32 as u64;
        let x3 = (x32 >> 64) as u64;

        let a = x3 >> 63;
        let b = x3 >> 62;
        let c = x3 >> 57;
        let d = x2 ^ a ^ b ^ c;

        let x3d = ((x3 as u128) << 64) | (d as u128); // maybe here?
        let e = x3d << 1;
        let f = x3d << 2;
        let g = x3d << 7;

        let h = x3d ^ e ^ f ^ g;

        h ^ x10
    }

    unsafe {
        let left = left.as_ptr() as *const u64;
        let right = right.as_ptr() as *const u64;
        let result = destination.as_mut_ptr() as *mut u128;

        let a = vld1q_p64(left);
        let b = vld1q_p64(right);

        // polynomial multiply
        let z = vdupq_n_p64(0);

        let c = pmull::<0, 0>(a, b);
        let d = pmull::<1, 1>(a, b);
        let e = pmull::<0, 1>(a, b);
        let f = pmull::<1, 0>(a, b);

        let ef = vaddq_p128(e, f);
        let lower = vextq_p64(z, vreinterpretq_p64_p128(ef), 1);
        let upper = vextq_p64(vreinterpretq_p64_p128(ef), z, 1);
        let left = vaddq_p128(d, vreinterpretq_p128_p64(upper));
        let right = vaddq_p128(c, vreinterpretq_p128_p64(lower));

        let reduced = gf128_reduce(left, right);
        *result ^= reduced;
    }
}

// -------------------------------------------------------------------------------------------------
// Polynomials

impl ObliviousSender for Sender {
    fn exchange(&self, msg: &Message, channel: &Channel<Vec<u8>>) -> Result<(), Error> {
        debug_assert!(msg.len() >= BLOCK_SIZE, "Message must be longer than {BLOCK_SIZE} bytes");
        debug_assert!(msg.len() % BLOCK_SIZE == 0, "Message length must be multiple of {BLOCK_SIZE} bytes");

        // TODO: What the hell are these?
        let transaction_properties = TransactionProperties { msg_size: msg.len(), protocol: "Apricot AVX2".to_string() };
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
        let mut t = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let payload = &payloads[row_idx];
            let seed: [u8; 32] = array(payload);
            let row = t[row_idx].as_mut_slice();
            fill_random_bytes_from_seed(&seed, row);
        }

        let u: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let mut q = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let row = q[row_idx].as_mut_slice();
            let d = (delta[row_idx / 8] >> row_idx % 8) & 1;
            if d == 1 {
                xor_inplace(row, u[row_idx].as_slice());
            }
            xor_inplace(row, t[row_idx].as_slice());
        }

        let mut q_transposed = vec![vec![0u8; matrix_width]; matrix_height];
        matrix_transpose(&q, &mut q_transposed, matrix_transposed_height, matrix_transposed_width);

        // -- Check correlation --
        let chi: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let mut q_sum = vec![0u8; matrix_width];
        for row_idx in 0..matrix_height {
            let q_row = q_transposed[row_idx].as_slice();
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
        let mut d0 = Vec::with_capacity(msg.len());
        let mut d1 = Vec::with_capacity(msg.len());
        let nonce = Nonce::from_slice(b"unique nonce");
        for row_idx in 0..msg.len() {
            let v0 = hash!(row_idx.to_be_bytes(), q_transposed[row_idx].as_slice());

            // TODO: Can we do this in a better way?
            let mut q_delta = vec![0u8; matrix_width];
            xor(q_delta.as_mut_slice(), q_transposed[row_idx].as_slice(), delta);
            let v1 = hash!(row_idx.to_be_bytes(), q_delta);

            let m0 = msg.0[row_idx][0].as_slice();
            let cipher = Aes256Gcm::new(Key::from_slice(v0.as_slice()));
            d0.push(cipher.encrypt(nonce, m0).unwrap());

            let m1 = msg.0[row_idx][1].as_slice();
            let cipher = Aes256Gcm::new(Key::from_slice(v1.as_slice()));
            d1.push(cipher.encrypt(nonce, m1).unwrap());
        }

        s.send(bincode::serialize(&d0)?)?;
        s.send(bincode::serialize(&d1)?)?;

        return Ok(());
    }
}

impl ObliviousReceiver for Receiver {
    fn exchange(&self, choices: &[bool], channel: &Channel<Vec<u8>>) -> Result<Payload, Error> {
        debug_assert!(choices.len() >= BLOCK_SIZE, "Choices must be longer than {BLOCK_SIZE} bytes");
        debug_assert!(choices.len() % BLOCK_SIZE == 0, "Choices length must be multiple of {BLOCK_SIZE} bytes");

        // TODO: What the hell are these?
        let transaction_properties = TransactionProperties { msg_size: choices.len(), protocol: "Apricot AVX2".to_string() };
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
        let mut t0 = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let row = t0[row_idx].as_mut_slice();
            fill_random_bytes_from_seed(&seed0[row_idx], row);
        }

        // TODO: It might be beneficial to do this in the loop for t0!
        // TODO: Can we vectorize the transposing?
        let mut t = vec![vec![0u8; matrix_width]; matrix_height];
        matrix_transpose(&t0, &mut t, matrix_transposed_height, matrix_transposed_width);

        let mut t1 = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let row = t1[row_idx].as_mut_slice();
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
        }

        let mut u = vec![vec![0u8; matrix_transposed_width]; matrix_transposed_height];
        for row_idx in 0..matrix_transposed_height {
            let u_row = u[row_idx].as_mut_slice();

            // TODO: This can be done more efficiently
            let t0_row = t0[row_idx].as_slice();
            let t1_row = t1[row_idx].as_slice();
            xor(u_row, t0_row, t1_row);

            let x_row = x_transposed[row_idx].as_slice();
            xor_inplace(u_row, x_row);
        }
        s.send(bincode::serialize(&u)?)?;

        // -- Check correlation --
        let mut chi = vec![vec![0u8; matrix_width]; matrix_height];
        for row_idx in 0..matrix_height {
            let row = chi[row_idx].as_mut_slice();
            random.fill_bytes(row);
        }
        s.send(bincode::serialize(&chi)?)?;

        let mut x_sum = vec![0u8; matrix_width];
        let mut t_sum = vec![0u8; matrix_width];
        for row_idx in 0..matrix_height {
            let chi_row = chi[row_idx].as_slice();
            if padded_choices[row_idx] {
                xor_inplace(x_sum.as_mut_slice(), chi_row);
            }

            let t_row = t[row_idx].as_slice();
            polynomial_mul_acc(t_sum.as_mut_slice(), t_row, chi_row);
        }
        s.send(bincode::serialize(&x_sum)?)?;
        s.send(bincode::serialize(&t_sum)?)?;


        // -- Randomize --
        let mut v = vec![vec![0u8; 32]; matrix_height];
        for row_idx in 0..matrix_height {
            let row = v[row_idx].as_mut_slice();
            let hash = hash!(row_idx.to_be_bytes(), t[row_idx].as_slice());
            xor_inplace(row, &hash);
        }

        // -- DeROT --
        let d0: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let d1: Vec<Vec<u8>> = bincode::deserialize(&r.recv()?)?;
        let mut y: Vec<Vec<u8>> = Vec::with_capacity(choices.len());
        for i in 0..choices.len() {
            let nonce = Nonce::from_slice(b"unique nonce");
            let cipher = Aes256Gcm::new(Key::from_slice(v[i].as_slice()));
            // TODO: This we can probably optimize
            let d = if choices[i] { d1[i].as_slice() } else { d0[i].as_slice() };

            let c = cipher.decrypt(nonce, d).unwrap();
            y.push(c);
        }

        return Ok(y);
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