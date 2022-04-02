#![allow(clippy::suspicious_arithmetic_impl)]
#![allow(clippy::suspicious_op_assign_impl)]

use crate::{ot::bitmatrix::*, util::u8_vec_to_bool_vec};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    ops::{Add, AddAssign, Mul, MulAssign},
};

#[repr(transparent)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Polynomial(pub BitVector);

impl Polynomial {
    #[inline]
    pub fn new() -> Self {
        Self(BitVector::zeros(128))
    }

    #[inline]
    pub fn mul_add_assign(&mut self, a: &Self, b: &Self) {
        polynomial_mul_acc(&mut self.0, &a.0, &b.0);
    }
}

impl From<BitVector> for Polynomial {
    #[inline]
    fn from(bitvec: BitVector) -> Self {
        debug_assert_eq!(bitvec.len(), 128);
        Self(bitvec)
    }
}

impl From<&BitVector> for &Polynomial {
    #[inline]
    fn from(bitvec: &BitVector) -> Self {
        debug_assert_eq!(bitvec.len(), 128);
        unsafe { core::mem::transmute(bitvec) }
    }
}

impl Default for Polynomial {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Add for Polynomial {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
}

impl AddAssign<&Self> for Polynomial {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        self.0 ^= &other.0;
    }
}

impl AddAssign<Self> for Polynomial {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        self.0 ^= other.0;
    }
}

impl Mul for Polynomial {
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        let v = polynomial_mul(&self.0, &other.0);
        Self(v)
    }
}

impl Mul for &Polynomial {
    type Output = Polynomial;

    #[inline]
    fn mul(self, other: Self) -> Polynomial {
        let v = polynomial_mul(&self.0, &other.0);
        Polynomial(v)
    }
}


impl MulAssign for Polynomial {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        self.0 = polynomial_mul(&self.0, &other.0);
    }
}

impl Display for Polynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.0.len();
        let vec = u8_vec_to_bool_vec(self.0.as_bytes());
        let mut last = 0;
        for i in 0..len {
            if vec[len - i - 1] {
                last = i;
            }
        }

        for i in 0..len {
            if vec[len - i - 1] {
                if i == 0 {
                    write!(f, "1")?;
                } else if i == 1 {
                    write!(f, "X")?;
                } else {
                    write!(f, "X^{}", len - i - 1)?;
                }

                if i != last {
                    write!(f, " + ")?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn polynomial_mul(left: &BitVector, right: &BitVector) -> BitVector {
    debug_assert!(left.len() == right.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();

    let mut intermediate_bytes = [0u8; 128];

    for i in 0..size_bytes {
        for j in 0..size_bytes {
            for ib in 0..8 {
                for jb in 0..8 {
                    let ii = i * 8 + ib;
                    let jj = j * 8 + jb;
                    let l = left_bytes[i] & (1 << ib) > 0;
                    let r = right_bytes[j] & (1 << jb) > 0;

                    if l && r {
                        let target = ii + jj;
                        let result_index = target / 8;
                        let result_bit = target % 8;
                        intermediate_bytes[result_index] ^= 1 << result_bit;
                    }
                }
            }
        }
    }

    BitVector::from_bytes(&intermediate_bytes[..size_bytes])
}

#[cfg(not(target_arch = "x86_64"))]
fn polynomial_mul_acc(result: &mut BitVector, left: &BitVector, right: &BitVector) {
    polynomial_mul_acc_generic(result, left, right);
}

#[inline]
fn polynomial_mul_acc_generic(result: &mut BitVector, left: &BitVector, right: &BitVector) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();

    let mut intermediate_bytes = [0u8; 128];

    for i in 0..size_bytes {
        for j in 0..size_bytes {
            for ib in 0..8 {
                for jb in 0..8 {
                    let ii = i * 8 + ib;
                    let jj = j * 8 + jb;
                    let l = left_bytes[i] & (1 << ib) > 0;
                    let r = right_bytes[j] & (1 << jb) > 0;

                    if l && r {
                        let target = ii + jj;
                        let result_index = target / 8;
                        let result_bit = target % 8;
                        intermediate_bytes[result_index] ^= 1 << result_bit;
                    }
                }
            }
        }
    }

    let result_bytes = result.as_mut_bytes();
    for i in 0..size_bytes {
        result_bytes[i] ^= intermediate_bytes[i];
    }
}

// https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/backend/soft64.rs
fn polynomial_mul_acc_generic_fast(result: &mut BitVector, left: &BitVector, right: &BitVector) {
    fn bmul64(x: u64, y: u64) -> u64 {
        use std::num::Wrapping;
        let x0 = Wrapping(x & 0x1111_1111_1111_1111);
        let x1 = Wrapping(x & 0x2222_2222_2222_2222);
        let x2 = Wrapping(x & 0x4444_4444_4444_4444);
        let x3 = Wrapping(x & 0x8888_8888_8888_8888);
        let y0 = Wrapping(y & 0x1111_1111_1111_1111);
        let y1 = Wrapping(y & 0x2222_2222_2222_2222);
        let y2 = Wrapping(y & 0x4444_4444_4444_4444);
        let y3 = Wrapping(y & 0x8888_8888_8888_8888);

        let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
        let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
        let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
        let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;
        z0 &= 0x1111_1111_1111_1111;
        z1 &= 0x2222_2222_2222_2222;
        z2 &= 0x4444_4444_4444_4444;
        z3 &= 0x8888_8888_8888_8888;

        z0 | z1 | z2 | z3
    }

    /// Bit-reverse a `u64` in constant time
    fn rev64(mut x: u64) -> u64 {
        x = ((x & 0x5555_5555_5555_5555) << 1) | ((x >> 1) & 0x5555_5555_5555_5555);
        x = ((x & 0x3333_3333_3333_3333) << 2) | ((x >> 2) & 0x3333_3333_3333_3333);
        x = ((x & 0x0f0f_0f0f_0f0f_0f0f) << 4) | ((x >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
        x = ((x & 0x00ff_00ff_00ff_00ff) << 8) | ((x >> 8) & 0x00ff_00ff_00ff_00ff);
        x = ((x & 0xffff_0000_ffff) << 16) | ((x >> 16) & 0xffff_0000_ffff);
        (x << 32) | (x >> 32)
    }

    let left = left.as_slice();
    let right = right.as_slice();

    let h0 = left[0];
    let h1 = left[1];
    let h0r = rev64(h0);
    let h1r = rev64(h1);
    let h2 = h0 ^ h1;
    let h2r = h0r ^ h1r;

    let y0 = right[0];
    let y1 = right[1];
    let y0r = rev64(y0);
    let y1r = rev64(y1);
    let y2 = y0 ^ y1;
    let y2r = y0r ^ y1r;
    let z0 = bmul64(y0, h0);
    let z1 = bmul64(y1, h1);

    let mut z2 = bmul64(y2, h2);
    let mut z0h = bmul64(y0r, h0r);
    let mut z1h = bmul64(y1r, h1r);
    let mut z2h = bmul64(y2r, h2r);

    z2 ^= z0 ^ z1;
    z2h ^= z0h ^ z1h;
    z0h = rev64(z0h) >> 1;
    z1h = rev64(z1h) >> 1;
    z2h = rev64(z2h) >> 1;

    let v0 = z0;
    let mut v1 = z0h ^ z2;
    let mut v2 = z1 ^ z2h;
    let mut v3 = z1h;

    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);

    result.as_mut_slice()[0] ^= v2;
    result.as_mut_slice()[1] ^= v3;
}


#[inline]
#[cfg(target_arch = "x86_64")]
fn polynomial_mul_acc(destination: &mut BitVector, left: &BitVector, right: &BitVector) {
    polynomial_mul_acc_x86(destination, left, right);
}

#[cfg(target_arch = "x86_64")]
use {
    std::arch::x86_64::*
};

#[cfg(target_arch = "x86_64")]
pub unsafe fn polynomial_gf128_reduce(x32: __m128i, x10: __m128i) -> __m128i {
    use std::arch::x86_64::*;
    let x2 = _mm_extract_epi64(x32, 0) as u64;
    let x3 = _mm_extract_epi64(x32, 1) as u64;

    let a = x3 >> 63;
    let b = x3 >> 62;
    let c = x3 >> 57;
    let d = x2 ^ a ^ b ^ c;

    let x3d = _mm_set_epi64x(x3 as i64, d as i64);
    let e = _mm_slli_si128(x3d, 1);
    let f = _mm_slli_si128(x3d, 2);
    let g = _mm_slli_si128(x3d, 7);

    let h = _mm_xor_si128(x3d, e);
    let h = _mm_xor_si128(h, f);
    let h = _mm_xor_si128(h, g);

    return _mm_xor_si128(h, x10);
}

#[inline]
#[cfg(target_arch = "x86_64")]
fn polynomial_mul_acc_x86(destination: &mut BitVector, left: &BitVector, right: &BitVector) {
    use std::arch::x86_64::*;
    unsafe {
        let left_bytes = left.as_bytes().as_ptr() as *const __m128i;
        let right_bytes = right.as_bytes().as_ptr() as *const __m128i;
        let result_bytes = destination.as_mut_bytes().as_mut_ptr() as *mut __m128i;

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

#[cfg(target_arch = "x86_64")]
#[inline]
fn polynomial_mul(left: &BitVector, right: &BitVector) -> BitVector {
    use std::arch::x86_64::*;
    unsafe {
        let left_bytes = left.as_bytes().as_ptr() as *const __m128i;
        let right_bytes = right.as_bytes().as_ptr() as *const __m128i;

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

        let mut res = BitVector::zeros(128);
        let result_bytes = res.as_mut_bytes().as_mut_ptr() as *mut __m128i;
        *result_bytes = xor;
        res
    }
}

// #[cfg(target_arch = "aarch64")]
// pub fn polynomial_mul_acc(destination: &mut BitVector, left: &BitVector, right: &BitVector) {
//     polynomial_mul_acc_arm64(destination, left, right)
// }

#[cfg(target_arch = "aarch64")]
pub fn polynomial_mul_acc_arm64(destination: &mut BitVector, left: &BitVector, right: &BitVector) {
    debug_assert!(left.len() == 128);
    debug_assert!(right.len() == 128);
    use core::{arch::aarch64::*, mem};

    // shamelessly stolen from
    // https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/backend/pmull.rs
    // but that was just stolen from
    // https://github.com/noloader/AES-Intrinsics/blob/master/clmul-arm.c
    // so we are back to start.
    #[inline(always)]
    unsafe fn pmull<const A_LANE: i32, const B_LANE: i32>(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        mem::transmute(vmull_p64(
            vgetq_lane_u64(vreinterpretq_u64_u8(a), A_LANE),
            vgetq_lane_u64(vreinterpretq_u64_u8(b), B_LANE),
        ))
    }
    const MASK: u128 = 1 << 127 | 1 << 126 | 1 << 121 | 1;

    unsafe {
        let left = left.as_bytes().as_ptr() as *const u8;
        let right = right.as_bytes().as_ptr() as *const u8;
        let result = destination.as_mut_bytes().as_mut_ptr() as *mut u128;

        let h = vld1q_u8(left);
        let y = vld1q_u8(right);

        // polynomial multiply
        let z = vdupq_n_u8(0);
        let r0 = pmull::<0, 0>(h, y);
        let r1 = pmull::<1, 1>(h, y);
        let t0 = pmull::<0, 1>(h, y);
        let t1 = pmull::<1, 0>(h, y);
        let t0 = veorq_u8(t0, t1);
        let t1 = vextq_u8(z, t0, 8);
        let r0 = veorq_u8(r0, t1);
        let t1 = vextq_u8(t0, z, 8);
        let r1 = veorq_u8(r1, t1);

        // polynomial reduction
        let p = mem::transmute(MASK);
        let t0 = pmull::<0, 1>(r0, p);
        let t1 = vextq_u8(t0, t0, 8);
        let r0 = veorq_u8(r0, t1);
        let t1 = pmull::<1, 1>(r0, p);
        let r0 = veorq_u8(r0, t1);

        let c = veorq_u8(r0, r1);
        let c = vreinterpretq_p128_u8(c);
        *result ^= c;

    }
}


#[cfg(test)]
mod tests {


    #[test]
    fn test_polynomial_mul() {
        use super::*;
        let left: BitVector = BitVector::from_bytes(&[
            0b00000011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]); // x + 1
        let right: BitVector = BitVector::from_bytes(&[
            0b00000101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]); // x^2 + 1
        let mut result = Polynomial::new();

        polynomial_mul_acc_generic(&mut result.0, &left, &right);

        // Expecting x^3 + x^2 + x + 1
        let result_bytes = result.0.as_bytes();
        assert_eq!(0b0000_1111, result_bytes[0]);
        for i in 1..16 {
            assert_eq!(0, result_bytes[i]);
        }
    }


    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_polynomial_mul_x86() {
        use super::*;
        let left: BitVector = BitVector::from_bytes(&[
            0b00000011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]); // x + 1
        let right: BitVector = BitVector::from_bytes(&[
            0b00000101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]); // x^2 + 1
        let mut result = Polynomial::new();

        polynomial_mul_acc_x86(&mut result.0, &left, &right);

        // Expecting x^3 + x^2 + x + 1
        let result_bytes = result.0.as_bytes();
        assert_eq!(0b0000_1111, result_bytes[0]);
        for i in 1..16 {
            assert_eq!(0, result_bytes[i]);
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_polynomial_mul_aarch64() {
        use super::*;
        let left: BitVector = BitVector::from_bytes(&[
            0b00000011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]); // x + 1
        let right: BitVector = BitVector::from_bytes(&[
            0b00000101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]); // x^2 + 1
        let mut result = Polynomial::new();

        polynomial_mul_acc_arm64(&mut result.0, &left, &right);

        println!("Result: {:?}", result);
        // Expecting x^3 + x^2 + x + 1
        let result_bytes = result.0.as_bytes();
        assert_eq!(0b0000_1111, result_bytes[0]);
        for i in 1..16 {
            assert_eq!(0, result_bytes[i]);
        }
    }


    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_aarch64_poly() {
        use super::*;
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaChaRng;
        let mut rng = ChaChaRng::from_seed([0; 32]);
        for _ in 0..100 {
            let a = rng.gen::<[u8; 16]>();
            let b = rng.gen::<[u8; 16]>();
            let a = BitVector::from_bytes(&a);
            let b = BitVector::from_bytes(&b);
            let mut c1 = BitVector::from_bytes(&[0x00; 16]);
            polynomial_mul_acc_arm64(&mut c1, &a, &b);
            let r1 = Polynomial::from(c1);

            let mut c2 = BitVector::from_bytes(&[0x00; 16]);
            polynomial_mul_acc_generic_fast(&mut c2, &a, &b);
            let r2 = Polynomial::from(c2);

            assert_eq!(r1, r2);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_x86_poly() {
        use super::*;
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaChaRng;
        let mut rng = ChaChaRng::from_seed([0; 32]);
        for _ in 0..100 {
            let a = rng.gen::<[u8; 16]>();
            let b = rng.gen::<[u8; 16]>();
            let a = BitVector::from_bytes(&a);
            let b = BitVector::from_bytes(&b);
            let mut c1 = BitVector::from_bytes(&[0x00; 16]);
            polynomial_mul_acc_x86(&mut c1, &a, &b);
            let r1 = Polynomial::from(c1);

            let mut c2 = BitVector::from_bytes(&[0x00; 16]);
            polynomial_mul_acc_generic_fast(&mut c2, &a, &b);
            let r2 = Polynomial::from(c2);

            assert_eq!(r1, r2);
        }
    }

    #[test]
    fn test_generic_fast_poly() {
        use super::*;
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaChaRng;
        let mut rng = ChaChaRng::from_seed([0; 32]);
        for _ in 0..100 {
            let a = rng.gen::<[u8; 16]>();
            let b = rng.gen::<[u8; 16]>();
            let a = BitVector::from_bytes(&a);
            let b = BitVector::from_bytes(&b);
            let mut c1 = BitVector::from_bytes(&[0x00; 16]);
            polynomial_mul_acc_generic_fast(&mut c1, &a, &b);
            let r1 = Polynomial::from(c1);

            let mut c2 = BitVector::from_bytes(&[0x00; 16]);
            polynomial_mul_acc_generic(&mut c2, &a, &b);
            let r2 = Polynomial::from(c2);

            assert_eq!(r1, r2);
        }
    }


}
