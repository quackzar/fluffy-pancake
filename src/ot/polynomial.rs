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

#[inline]
#[cfg(target_arch = "x86_64")]
fn polynomial_mul_acc(destination: &mut BitVector, left: &BitVector, right: &BitVector) {
    polynomial_mul_acc_x86(destination, left, right);
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
        let xor = _mm_xor_si128(left, right);

        *result_bytes = _mm_xor_si128(*result_bytes, xor);
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
    use std::arch::aarch64::*;
    #[inline(always)]
    unsafe fn pmull_low(a : poly64x2_t, b : poly64x2_t) -> poly64x2_t {
        let c = vmull_p64(vgetq_lane_p64(a, 0),
            vgetq_lane_p64(b, 0));
    vreinterpretq_p64_p128(c)
    }
    #[inline(always)]
    unsafe fn pmull_high(a : poly64x2_t, b : poly64x2_t) -> poly64x2_t {
        let c = vmull_high_p64(a, b);
        vreinterpretq_p64_p128(c)
    }
    unsafe {
        let left = left.as_bytes().as_ptr() as *const u8;
        let right = right.as_bytes().as_ptr() as *const u8;
        let result = destination.as_mut_bytes().as_mut_ptr() as *mut u128;

        // https://github.com/noloader/AES-Intrinsics/blob/master/clmul-arm.c
        
        // load them in and flip them?
        let a = vreinterpretq_p64_p8(vrbitq_p8(vld1q_p8(left)));
        let b = vreinterpretq_p64_p8(vrbitq_p8(vld1q_p8(right)));

        // polynomial multiply
        let z = vdupq_n_p64(0);
        let r0 = pmull_low(a, b);
        let r1 = pmull_high(a, b);
        let t0 = vextq_p64(a, b, 1);
        let t1 = pmull_low(a, t0);
        let t0 = pmull_high(a, t0);
        let t0 = vaddq_p64(t0, t1);
        let t1 = vextq_p64(z, t0, 1);
        let r0 = vaddq_p64(r0, t1);
        let t1 = vextq_p64(t0, z, 1);
        let r1 = vaddq_p64(r1, t1);

        // reduction
        let p = vreinterpretq_p64_u64(vdupq_n_u64(0x0000_0000_0000_0087));
        let t0 = pmull_high(r1, p);
        let t1 = vextq_p64(t0, z, 1);
        let r1 = vaddq_p64(r1, t1);
        let t1 = vextq_p64(z, t0, 1);
        let r0 = vaddq_p64(r0, t1);
        let t0 = pmull_low(r1, p);
        let c = vaddq_p64(r0, t0);

        // idk
        let c = vreinterpretq_p8_p64(c);
        let c = vrbitq_p8(c);

        let c = vreinterpretq_p128_p8(c);
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
            polynomial_mul_acc(&mut c2, &a, &b);
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
            polynomial_mul_acc(&mut c2, &a, &b);
            let r2 = Polynomial::from(c2);

            assert_eq!(r1, r2);
        }
    }

}
