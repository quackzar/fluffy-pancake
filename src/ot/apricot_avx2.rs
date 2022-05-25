use crate::common::*;
use crate::instrument;
use crate::instrument::{E_COMP_COLOR, E_FUNC_COLOR, E_PROT_COLOR, E_RECV_COLOR, E_SEND_COLOR};
use crate::ot::coinflip::coinflip_receiver;
use crate::ot::coinflip::coinflip_sender;
use crate::ot::common::*;
use crate::util::*;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

const K: usize = 128;
const S: usize = 128;
const BLOCK_SIZE: usize = 128 / 8;
const K_BYTES: usize = K / 8;

pub struct Sender {
    pub bootstrap: Box<dyn ObliviousReceiver>,
}

pub struct Receiver {
    pub bootstrap: Box<dyn ObliviousSender>,
}

// -------------------------------------------------------------------------------------------------
// Sender

impl ObliviousSender for Sender {
    fn exchange(&self, msg: &Message, channel: &Channel) -> Result<()> {
        instrument::begin("Apricot x86 Sender", E_FUNC_COLOR);

        debug_assert!(
            msg.len() >= BLOCK_SIZE,
            "Message must be longer than {BLOCK_SIZE} bytes"
        );
        debug_assert!(
            msg.len() % BLOCK_SIZE == 0,
            "Message length must be multiple of {BLOCK_SIZE} bytes"
        );

        let transaction_properties = TransactionProperties {
            msg_size: msg.len(),
            protocol: "Apricot AVX2".to_string(),
        };
        validate_properties(&transaction_properties, channel)?;

        let l = msg.len() + K + S;
        const K_BYTES: usize = K / 8;

        let (matrix_w, matrix_h) = (K_BYTES, l);
        let (matrix_t_w, matrix_t_h) = (matrix_h / 8, matrix_w * 8);
        let matrix_size = matrix_w * matrix_h;

        instrument::begin("Chi Coinflip Receiver", E_PROT_COLOR);
        let seed = coinflip_receiver::<32>(channel)?;
        instrument::end();

        // -- COTe
        instrument::begin("COTe", E_PROT_COLOR);

        let mut random = ChaCha20Rng::from_entropy();
        let (s, r) = channel;

        let msg_size = msg.0[0][0].len();
        s.send(&(msg_size as u16).to_be_bytes())?;

        // Generate random delta
        instrument::begin("Generate delta", E_COMP_COLOR);
        let mut delta = [0u8; K_BYTES];
        let delta = delta.as_mut_slice();
        random.fill_bytes(delta);
        let delta_choices = unsafe { unpack_bits_to_vec(delta) };
        instrument::end();

        // do OT.
        instrument::begin("Bootstrap", E_COMP_COLOR);
        let payloads = self.bootstrap.exchange(&delta_choices, channel)?;
        instrument::end();

        instrument::begin("Compute t", E_COMP_COLOR);
        let mut t = vec![0u8; matrix_t_w * matrix_t_h];
        for row_idx in 0..matrix_t_h {
            let row = unsafe { vector_row_mut(&mut t, row_idx, matrix_t_w) };
            fill_random_bytes_from_seed(&payloads[row_idx], row);
        }
        instrument::end();

        instrument::begin("Allocate q, q^T", E_COMP_COLOR);
        let mut q = vec![0u8; matrix_t_w * matrix_t_h];
        let mut q_transposed = vec![0u8; matrix_w * matrix_h];
        instrument::end();

        instrument::begin("Generate Chi", E_COMP_COLOR);
        let mut chi = vec![0u8; matrix_w * matrix_h];
        fill_random_bytes_from_seed_array(&seed, &mut chi);
        instrument::end();

        instrument::begin("Receive u", E_RECV_COLOR);
        let u: Vec<u8> = r.recv()?;
        instrument::end();

        instrument::begin("Compute q", E_COMP_COLOR);
        for row_idx in 0..matrix_t_h {
            let row = unsafe { vector_row_mut(&mut q, row_idx, matrix_t_w) };
            let d = (delta[row_idx / 8] >> (row_idx % 8)) & 1;
            if d == 1 {
                let u_row = unsafe { vector_row(&u, row_idx, matrix_t_w) };
                xor_inplace(row, u_row);
            }

            let t_row = unsafe { vector_row(&t, row_idx, matrix_t_w) };
            xor_inplace(row, t_row);
        }
        instrument::end();

        instrument::begin("Transpose q", E_COMP_COLOR);
        transpose_matrix(&q, &mut q_transposed, matrix_t_h, matrix_t_w, matrix_w);
        instrument::end();
        instrument::end();

        // -- ROTe
        instrument::begin("ROTe", E_PROT_COLOR);

        // Correlation Check
        instrument::begin("Compute q_sum", E_COMP_COLOR);
        debug_assert_eq!(matrix_size, chi.len());
        let mut q_sum = vec![0u8; matrix_w];
        for row_idx in 0..matrix_h {
            let q_row = unsafe { vector_row(&q_transposed, row_idx, matrix_w) };
            let chi_row = unsafe { vector_row(&chi, row_idx, matrix_w) };

            polynomial_mul_acc(q_sum.as_mut_slice(), q_row, chi_row);
        }
        instrument::end();

        instrument::begin("Receive x_sum, t_sum", E_RECV_COLOR);
        let x_sum: Vec<u8> = r.recv()?;
        let t_sum: Vec<u8> = r.recv()?;
        instrument::end();

        instrument::begin("Compare correlation sums", E_COMP_COLOR);
        debug_assert_eq!(matrix_w, x_sum.len());
        debug_assert_eq!(matrix_w, t_sum.len());
        polynomial_mul_acc(q_sum.as_mut_slice(), x_sum.as_slice(), delta);

        if !eq(t_sum.as_slice(), q_sum.as_slice()) {
            return Err(Box::new(OTError::PolychromaticInput()));
        }
        instrument::end();

        // Randomize
        instrument::begin("Randomize", E_COMP_COLOR);
        let msg_count = msg.len();
        let msg_pair_size = msg_size * 2;
        let mut d = vec![0u8; msg_count * msg_pair_size];

        let thread_count = pick_suitable_thread_count(msg_count);
        let rows_in_chunk = msg_count / thread_count;
        let bytes_in_chunk = rows_in_chunk * msg_pair_size;
        rayon::scope(|s| {
            let q_transposed = &q_transposed;
            let delta = &delta;

            let d_chunks = d.chunks_mut(bytes_in_chunk);
            for (chunk_idx, chunk) in d_chunks.enumerate() {
                let handle = s.spawn(move |_| {
                    instrument::begin("Randomize - worker", E_COMP_COLOR);

                    let mut q_buffer = vec![0u8; matrix_w];
                    let q_buffer = q_buffer.as_mut_slice();

                    let rows_in_this_chunk = chunk.len() / msg_pair_size;
                    for i in 0..rows_in_this_chunk {
                        let row_idx = chunk_idx * rows_in_chunk + i;

                        let q_row = unsafe { vector_row(q_transposed, row_idx, matrix_w) };
                        let v0 = hash!(row_idx.to_be_bytes(), q_row);

                        let d0_idx = i * msg_pair_size;
                        let d1_idx = d0_idx + msg_size;

                        let m0 = msg.0[row_idx][0];
                        let mut chacha = ChaCha20Rng::from_seed(v0);
                        let plain = unsafe { vector_slice_mut(chunk, d0_idx, msg_size) };
                        chacha.fill_bytes(plain);
                        xor_inplace(plain, m0);

                        zero_inplace(q_buffer);
                        xor(q_buffer, q_row, delta);
                        let v1 = hash!(row_idx.to_be_bytes(), &q_buffer);

                        let m1 = msg.0[row_idx][1];
                        let mut chacha = ChaCha20Rng::from_seed(v1);
                        let plain = unsafe { vector_slice_mut(chunk, d1_idx, msg_size) };
                        chacha.fill_bytes(plain);
                        xor_inplace(plain, m1);
                    }

                    instrument::end();
                    ()
                });
            }
        });
        /*
        for row_idx in 0..msg.len() {
            let q_row = unsafe { vector_row(&q_transposed, row_idx, matrix_w) };
            let v0 = hash!(row_idx.to_be_bytes(), q_row);

            let d0_idx = row_idx * msg_size * 2;
            let d1_idx = d0_idx + msg_size;

            let m0 = msg.0[row_idx][0];
            let mut chacha = ChaCha20Rng::from_seed(v0);
            let plain = unsafe { vector_slice_mut(&mut d, d0_idx, msg_size) };
            chacha.fill_bytes(plain);
            xor_inplace(plain, m0);

            let q_row = unsafe { vector_row_mut(&mut q_transposed, row_idx, matrix_w) };
            xor_inplace(q_row, delta);
            let v1 = hash!(row_idx.to_be_bytes(), &q_row);

            let m1 = msg.0[row_idx][1];
            let mut chacha = ChaCha20Rng::from_seed(v1);
            let plain = unsafe { vector_slice_mut(&mut d, d1_idx, msg_size) };
            chacha.fill_bytes(plain);
            xor_inplace(plain, m1);
        }
        */
        instrument::end();

        instrument::begin("Send d", E_SEND_COLOR);
        s.send(d.as_slice())?;
        instrument::end();
        instrument::end();
        instrument::end();

        Ok(())
    }
}

// -------------------------------------------------------------------------------------------------
// Receiver

impl ObliviousReceiver for Receiver {
    fn exchange(&self, choices: &[bool], channel: &Channel) -> Result<Payload> {
        instrument::begin("Apricot x86 Receiver", E_FUNC_COLOR);

        debug_assert!(
            choices.len() >= BLOCK_SIZE,
            "Choices must be longer than {BLOCK_SIZE} bytes"
        );
        debug_assert!(
            choices.len() % BLOCK_SIZE == 0,
            "Choices length must be multiple of {BLOCK_SIZE} bytes"
        );

        let transaction_properties = TransactionProperties {
            msg_size: choices.len(),
            protocol: "Apricot AVX2".to_string(),
        };
        validate_properties(&transaction_properties, channel)?;

        let l = choices.len() + K + S;
        let l_bytes = l / 8;
        const K_BYTES: usize = K / 8;

        let (matrix_w, matrix_h) = (K_BYTES, l);
        let (matrix_t_w, matrix_t_h) = (matrix_h / 8, matrix_w * 8);

        let mut random = ChaCha20Rng::from_entropy();
        let (s, r) = channel;

        instrument::begin("Chi Coinflip Sender", E_PROT_COLOR);
        let seed = coinflip_sender::<32>(channel)?;
        instrument::end();

        // INITIALIZATION
        instrument::begin("COTe", E_PROT_COLOR);
        instrument::begin("Initialization", E_COMP_COLOR);
        let bonus: [bool; K + S] = random.gen();
        let seed0: [[u8; 32]; K] = random.gen();
        let seed1: [[u8; 32]; K] = random.gen();
        instrument::end();

        instrument::begin("Receive msg_size", E_COMP_COLOR);
        let msg_size_bytes = r.recv()?;
        let msg_size = ((msg_size_bytes[0] as u16) << 8) | (msg_size_bytes[1] as u16);
        instrument::end();

        instrument::begin("Bootstrap", E_COMP_COLOR);
        let msg = Message::from_unzipped(&seed0, &seed1);
        self.bootstrap.exchange(&msg, channel)?;
        instrument::end();

        // EXTENSION
        instrument::begin("Compute t0", E_COMP_COLOR);
        let mut t0 = vec![0u8; matrix_t_w * matrix_t_h];
        for row_idx in 0..matrix_t_h {
            let row = unsafe { vector_row_mut(&mut t0, row_idx, matrix_t_w) };
            fill_random_bytes_from_seed_array(&seed0[row_idx], row);
        }
        instrument::end();

        instrument::begin("Compute t1", E_COMP_COLOR);
        let mut t1 = vec![0u8; matrix_t_w * matrix_t_h];
        for row_idx in 0..matrix_t_h {
            let row = unsafe { vector_row_mut(&mut t1, row_idx, matrix_t_w) };
            fill_random_bytes_from_seed_array(&seed1[row_idx], row);
        }
        instrument::end();

        // TODO: We can do this without concat!
        instrument::begin("Pack choices", E_COMP_COLOR);
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
        instrument::end();

        instrument::begin("Compute u", E_COMP_COLOR);
        let mut u = vec![0u8; matrix_t_w * matrix_t_h];
        for row_idx in 0..matrix_t_h {
            let u_row = unsafe { vector_row_mut(&mut u, row_idx, matrix_t_w) };

            // TODO: This can be done more efficiently
            let t0_row = unsafe { vector_row(&t0, row_idx, matrix_t_w) };
            let t1_row = unsafe { vector_row(&t1, row_idx, matrix_t_w) };
            xor(u_row, t0_row, t1_row);

            xor_inplace(u_row, packed_choices);
        }
        instrument::end();

        instrument::begin("Send u", E_SEND_COLOR);
        s.send(u.as_slice())?;
        instrument::end();

        instrument::begin("Transpose t0 -> t", E_COMP_COLOR);
        let mut t = vec![0u8; matrix_w * matrix_h];
        transpose_matrix(&t0, &mut t, matrix_t_h, matrix_t_w, matrix_w);
        instrument::end();

        instrument::end();

        // -- Check correlation / ROTe
        instrument::begin("ROTe", E_PROT_COLOR);

        instrument::begin("Generate Chi", E_COMP_COLOR);
        let mut chi = vec![0u8; matrix_w * matrix_h];
        fill_random_bytes_from_seed_array(&seed, &mut chi);
        instrument::end();

        instrument::begin("Check Correlation", E_COMP_COLOR);
        let mut x_sum = vec![0u8; matrix_w];
        let mut t_sum = vec![0u8; matrix_w];
        for row_idx in 0..matrix_h {
            let chi_row = unsafe { vector_row(&chi, row_idx, matrix_w) };
            if padded_choices[row_idx] {
                xor_inplace(x_sum.as_mut_slice(), chi_row);
            }

            let t_row = unsafe { vector_row(&t, row_idx, matrix_w) };
            polynomial_mul_acc(t_sum.as_mut_slice(), t_row, chi_row);
        }
        instrument::end();

        instrument::begin("Send x_sum, t_sum", E_SEND_COLOR);
        s.send(x_sum.as_slice())?;
        s.send(t_sum.as_slice())?;
        instrument::end();
        instrument::end();

        // -- DeROT
        instrument::begin("DeROT", E_PROT_COLOR);

        instrument::begin("Compute v", E_COMP_COLOR);
        let mut v = vec![0u8; 32 * matrix_h];
        let thread_count = pick_suitable_thread_count(matrix_h);
        let rows_in_chunk = matrix_h / thread_count;
        let bytes_in_chunk = rows_in_chunk * 32;
        rayon::scope(|s| {
            let t = &t;

            let chunks = v.chunks_mut(bytes_in_chunk);
            for (chunk_idx, chunk) in chunks.enumerate() {
                let handle = s.spawn(move |_| {
                    instrument::begin("Compute v - worker", E_COMP_COLOR);

                    let rows_in_this_chunk = chunk.len() / 32;
                    for i in 0..rows_in_this_chunk {
                        let row_idx = chunk_idx * rows_in_chunk + i;

                        let row = unsafe { vector_row_mut(chunk, i, 32) };
                        let t_row = unsafe { vector_row(&t, row_idx, matrix_w) };
                        let hash = hash!(row_idx.to_be_bytes(), t_row);
                        xor_inplace(row, &hash);
                    }

                    instrument::end();
                    ()
                });
            }
        });
        /*
        for row_idx in 0..matrix_h {
            let row = unsafe { vector_row_mut(&mut v, row_idx, 32) };
            let t_row = unsafe { vector_row(&t, row_idx, matrix_w) };
            let hash = hash!(row_idx.to_be_bytes(), t_row);
            xor_inplace(row, &hash);
        }
        */
        instrument::end();

        instrument::begin("Allocate y", E_COMP_COLOR);
        let choices_count = choices.len();
        // TODO: Flatten y
        let mut y = vec![vec![0u8; msg_size as usize]; choices_count];
        instrument::end();

        instrument::begin("Receive d", E_RECV_COLOR);
        let d: Vec<u8> = r.recv()?;
        instrument::end();

        instrument::begin("De-randomize", E_COMP_COLOR);
        let msg_count = choices.len() / 8;
        let msg_size = (d.len() / 2) / choices.len();

        //*
        let thread_count = pick_suitable_thread_count(choices_count);
        let rows_in_chunk = choices_count / thread_count;
        rayon::scope(|s| {
            let d = &d;
            let v = &v;
            let packed_choices = &packed_choices;

            let chunks = y.chunks_mut(rows_in_chunk);
            for (chunk_idx, chunk) in chunks.enumerate() {
                let handle = s.spawn(move |_| {
                    instrument::begin("De-randomize - worker", E_COMP_COLOR);

                    let rows_in_this_chunk = chunk.len();
                    for i in 0..rows_in_this_chunk {
                        let row_idx = chunk_idx * rows_in_chunk + i;

                        let j = row_idx;
                        let b = j % 8;
                        let i_actual = (j - b) / 8;

                        let v_row = unsafe { vector_row(&v, j, 32) };
                        let mut chacha = ChaCha20Rng::from_seed(*array_from_slice(v_row));
                        chacha.fill_bytes(chunk[i].as_mut_slice());

                        let choice = ((packed_choices[i_actual] >> b) & 1) as usize;
                        let d_idx = (j * msg_size * 2) + choice * msg_size;
                        let d = unsafe { vector_slice(&d, d_idx, msg_size) };

                        xor_inplace(chunk[i].as_mut_slice(), d);
                    }

                    instrument::end();
                    ()
                });
            }
        });
        /*
        for i in 0..(choices.len() / 8) {
            for b in 0..8 {
                let j = i * 8 + b;

                let v_row = unsafe { vector_row(&v, j, 32) };
                let mut chacha = ChaCha20Rng::from_seed(*array_from_slice(v_row));
                chacha.fill_bytes(y[j].as_mut_slice());

                let choice = ((packed_choices[i] >> b) & 1) as usize;
                let d_idx = (j * msg_size * 2) + choice * msg_size;
                let d = unsafe { vector_slice(&d, d_idx, msg_size) };

                xor_inplace(y[j].as_mut_slice(), d);
            }
        }
        */
        instrument::end();
        instrument::end();
        instrument::end();

        Ok(y)
    }
}

// -------------------------------------------------------------------------------------------------
// Array/slice helpers
#[inline]
unsafe fn unpack_bits_to_vec(bytes: &[u8]) -> Vec<bool> {
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
fn array_from_slice<const N: usize>(vector: &[u8]) -> &[u8; N] {
    unsafe { std::mem::transmute(vector.as_ptr()) }
}

// -------------------------------------------------------------------------------------------------
// RNG
#[inline]
fn fill_random_bytes_from_seed(seed: &Vec<u8>, bytes: &mut [u8]) {
    let mut random = ChaCha20Rng::from_seed(*array_from_slice(seed.as_slice()));
    random.fill_bytes(bytes);
}

#[inline]
fn fill_random_bytes_from_seed_array(seed: &[u8; 32], bytes: &mut [u8]) {
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
fn zero_inplace(destination: &mut [u8]) {
    // TODO: Vectorize this!
    for i in 0..destination.len() {
        destination[i] ^= 0;
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
fn transpose_matrix(
    source: &[u8],
    target: &mut [u8],
    transposed_height: usize,
    transposed_width: usize,
    original_width: usize,
) {
    // TODO: There is probably a better way of doing this!
    for row_idx in 0..transposed_height {
        for col_idx in 0..transposed_width {
            let source_byte = source[index_1d(row_idx, col_idx, transposed_width)];
            for b in 0..8 {
                let source_bit = (source_byte >> b) & 1;
                let target_row = col_idx * 8 + b;
                let target_col = row_idx / 8;
                let target_shift = row_idx % 8;

                let idx = index_1d(target_row, target_col, original_width);
                target[idx] |= source_bit << target_shift;
            }
        }
    }
}

#[inline]
fn pick_suitable_thread_count(rows: usize) -> usize {
    let logical_cores = num_cpus::get();

    if rows < logical_cores {
        return rows;
    }

    if rows % logical_cores == 0 {
        return logical_cores;
    }

    return rows / logical_cores;
}

// -------------------------------------------------------------------------------------------------
// Polynomials

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
// Tests

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_avx2_ot_receiver() {
        use crate::ot::chou_orlandi;
        let (s1, r1) = raw::new_local_channel();
        let (s2, r2) = raw::new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);

        use std::thread;
        let h1 = thread::Builder::new()
            .name("Sender".to_string())
            .spawn(move || {
                let sender = Sender {
                    bootstrap: Box::new(chou_orlandi::Receiver),
                };
                let msg = Message::from_unzipped(&[b"Hello"; 8 << 2], &[b"World"; 8 << 2]);
                sender.exchange(&msg, &ch1).unwrap();
            });

        let h2 = thread::Builder::new()
            .name("Receiver".to_string())
            .spawn(move || {
                let receiver = Receiver {
                    bootstrap: Box::new(chou_orlandi::Sender),
                };
                let choices = [true; 8 << 2];
                let msg = receiver.exchange(&choices, &ch2).unwrap();
                assert_eq!(msg[0], b"World");
            });

        h1.unwrap().join().unwrap();
        h2.unwrap().join().unwrap();
    }

    #[test]
    fn test_avx2_ot_receiver_many() {
        use crate::ot::chou_orlandi;
        let (s1, r1) = raw::new_local_channel();
        let (s2, r2) = raw::new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);

        fn print_vec(vec: &Vec<u8>) {
            print!("[");
            for i in 0..vec.len() {
                print!("{:#04x}", vec[i]);

                if i != vec.len() - 1 {
                    print!(", ");
                }
            }
            print!("]");
        }

        const CASES: usize = 1 << 5;

        use std::thread;
        let h1 = thread::Builder::new()
            .name("Sender".to_string())
            .spawn(move || {
                let sender = Sender {
                    bootstrap: Box::new(chou_orlandi::Receiver),
                };

                let mut m0 = [[0u8; 8]; CASES];
                let mut m1 = [[0u8; 8]; CASES];
                for i in 0..CASES {
                    m0[i] = (i as u64).to_be_bytes();
                    m1[i] = (0xFFFF_FFFF_FFFF_FFFF - (i as u64)).to_be_bytes();
                }

                for i in 0..CASES {
                    print!("{:04}: ", i);
                    print_vec(&m0[i].to_vec());
                    print!(", ");
                    print_vec(&m1[i].to_vec());
                    println!();
                }

                let msg = Message::from_unzipped(&m0, &m1);
                sender.exchange(&msg, &ch1).unwrap();
            });

        let h2 = thread::Builder::new()
            .name("Receiver".to_string())
            .spawn(move || {
                let receiver = Receiver {
                    bootstrap: Box::new(chou_orlandi::Sender),
                };
                let mut choices = vec![true; CASES];
                for i in 0..CASES {
                    choices[i] = (i & 1) > 0;
                }

                let msg = receiver.exchange(&choices, &ch2).unwrap();

                for i in 0..CASES {
                    print!("{:04}: ", i);
                    print_vec(&msg[i]);
                    println!();
                }

                for i in 0..CASES {
                    if choices[i] {
                        assert_eq!(
                            (0xFFFF_FFFF_FFFF_FFFF_u64 - i as u64)
                                .to_be_bytes()
                                .to_vec(),
                            msg[i]
                        );
                    } else {
                        assert_eq!((i as u64).to_be_bytes().to_vec(), msg[i]);
                    }
                }
            });

        h1.unwrap().join().unwrap();
        h2.unwrap().join().unwrap();
    }
}
