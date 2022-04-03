#![allow(clippy::suspicious_arithmetic_impl)]
#![allow(clippy::suspicious_op_assign_impl)]

use crate::{ot::bitmatrix::*, util::u8_vec_to_bool_vec};
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Mul, MulAssign};

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
        // polynomial_mul_acc(&mut self.0, &a.0, &b.0);
        todo!();
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
        todo!()
        // let v = polynomial_mul(&self.0, &other.0);
        // Self(v)
    }
}

impl Mul for &Polynomial {
    type Output = Polynomial;

    #[inline]
    fn mul(self, other: Self) -> Polynomial {
        todo!()
        // let v = polynomial_mul(&self.0, &other.0);
        // Polynomial(v)
    }
}


impl MulAssign for Polynomial {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        todo!()
        // self.0 = polynomial_mul(&self.0, &other.0);
    }
}


const fn gf128_reduce(x32: u128, x10: u128) -> u128 {
    let x2 = x32 as u64;
    let x3 = (x32 >> 64) as u64;

    let a = x3 >> 63;
    let b = x3 >> 62;
    let c = x3 >> 57;
    let d = x2 ^ a ^ b ^ c;

    let x3d = ((x3 as u128) << 64) | (d as u128);
    let e = x3d << 1;
    let f = x3d << 2;
    let g = x3d << 7;

    let h = x3d ^ e ^ f ^ g;
    h ^ x10
}

// https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/backend/soft64.rs
fn polynomial_mul_acc_generic(result: &mut BitVector, left: &BitVector, right: &BitVector) {
    debug_assert!(left.len() == 128);
    debug_assert!(right.len() == 128);
    dbg!("generic");
    dbg!(left, right);

    #[inline]
    unsafe fn clmul<const A: isize, const B: isize>(a : *const u64, b  : *const u64) -> u128 {
        let mut a = *a.offset(A) as u128;
        let mut b = *b.offset(B) as u128;
        let mut r : u128 = 0;
        while b != 0 {
            if a & 1 == 1 {
                r ^= b;
            }
            a >>= 1;
            b <<= 1;
        }
        r
    }

    let a = left.as_bytes().as_ptr() as *const u64 ;
    let b = right.as_bytes().as_ptr() as *const u64 ;

    unsafe {
        let c = clmul::<0, 0>(a, b);
        let d = clmul::<1, 1>(a, b);
        let e = clmul::<0, 1>(a, b);
        let f = clmul::<1, 0>(a, b);
        dbg!(*a, *b, c, d, e, f);

        let ef = e ^ f;
        let lower = ef << 64;
        let upper = ef >> 64;
        let left = d ^ upper;
        let right = c ^ lower;

        dbg!(ef, lower, upper, left, right);
        let res = gf128_reduce(left, right);
        dbg!(res);

        let acc = result.as_mut_bytes().as_mut_ptr() as *mut u128;
        *acc ^= res;
    }
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
        let upper = _mm_srli_si128(ef, 64 / 8); // should this be in the lower or upper register?
        dbg!(a, b, c, d, e, f, ef, lower, upper);

        let left = _mm_xor_si128(d, upper);
        let right = _mm_xor_si128(c, lower);
        dbg!(left, right);

        let reduced = polynomial_gf128_reduce(left, right);

        *result_bytes = _mm_xor_si128(*result_bytes, reduced);
    }
}



#[cfg(target_arch = "aarch64")]
pub fn polynomial_mul_acc_arm64(destination: &mut BitVector, left: &BitVector, right: &BitVector) {
    dbg!("arm64");
    debug_assert!(left.len() == 128);
    debug_assert!(right.len() == 128);
    use core::arch::aarch64::*;

    #[inline(always)]
    unsafe fn pmull<const A_LANE: i32, const B_LANE: i32>(a: poly64x2_t, b: poly64x2_t) -> u128 {
        vmull_p64(
            vgetq_lane_p64(a, A_LANE),
            vgetq_lane_p64(b, B_LANE),
        )
    }

    unsafe {
        dbg!(left, right);
        let left = left.as_bytes().as_ptr() as *const u64;
        let right = right.as_bytes().as_ptr() as *const u64;
        let result = destination.as_mut_bytes().as_mut_ptr() as *mut u128;

        let a = vld1q_p64(left);
        let b = vld1q_p64(right);

        // polynomial multiply
        let z = vdupq_n_p64(0);

        let c = pmull::<0, 0>(a, b);
        let d = pmull::<1, 1>(a, b);
        let e = pmull::<0, 1>(a, b);
        let f = pmull::<1, 0>(a, b);
        dbg!(a, b, c, d, e, f);

        let ef = vaddq_p128(e, f);
        let lower = vextq_p64(z, vreinterpretq_p64_p128(ef), 1);
        let upper = vextq_p64(vreinterpretq_p64_p128(ef), z, 1);
        let left = vaddq_p128(d, vreinterpretq_p128_p64(upper));
        let right = vaddq_p128(c, vreinterpretq_p128_p64(lower));
        dbg!(ef, lower, upper, left, right);

        let reduced = gf128_reduce(left, right);
        *result ^= reduced;
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
            polynomial_mul_acc_generic(&mut c2, &a, &b);
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
            polynomial_mul_acc_generic(&mut c2, &a, &b);
            let r2 = Polynomial::from(c2);

            assert_eq!(r1, r2);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_reduce() {
        use super::*;
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaChaRng;
        use core::arch::x86_64::*;
        let mut rng = ChaChaRng::from_seed([0; 32]);
        for _ in 0..100 {
            let a : u128 = rng.gen();
            let b : u128 = rng.gen();
            let c1 = gf128_reduce(a, b) ;

            let c2  : u128 = unsafe {
                let a0 = a as i64;
                let a1 = (a >> 64) as i64;
                let b0 = b as i64;
                let b1 = (b >> 64) as i64;
                let a = _mm_set_epi64x(a1, a0);
                let b = _mm_set_epi64x(b1, b0);
                let c2 = polynomial_gf128_reduce(a, b);
                let c2_0 = _mm_extract_epi64(c2, 0) as u64;
                let c2_1 = _mm_extract_epi64(c2, 1) as u64;
                c2_0 as u128 | (c2_1 as u128) << 64
            };
            assert_eq!(c1, c2);
        }

    }


}
