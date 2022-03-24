use crate::ot::bitmatrix::*;
use bitvec::prelude::*;
use serde::{Serialize, Deserialize};
use std::ops::{Add, Mul, AddAssign, MulAssign};

#[repr(transparent)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Polynomial (BitVec<Block>);

impl Polynomial {
    #[inline]
    pub fn new(size: usize) -> Self {
        Self(polynomial_new_bytes(size))
    }

    #[inline]
    pub fn from_bitvec(bitvec: &BitVec<Block>) -> &Self {
        unsafe { core::mem::transmute(bitvec) }
    }

    #[inline]
    pub fn add_assign(&mut self, other: &Self) {
        self.0 ^= &other.0;

    }

    #[inline]
    pub fn add(&self, other: &Self) -> Self {
        let mut res = self.0.clone();
        res ^= &other.0;
        Self(res)

    }

    #[inline]
    pub fn mul_assign(&mut self, other: &Self) {
        let mut res = self.0.clone();
        polynomial_mul_bytes(&mut res, &self.0, &other.0);
        self.0 = res;
    }

    #[inline]
    pub fn mul(&self, other: &Self) -> Self {
        let mut res = self.0.clone();
        polynomial_mul_bytes(&mut res, &self.0, &other.0);
        Polynomial(res)
    }

    #[inline]
    pub fn mul_add_assign(&mut self, a: &Self, b: &Self) {
        polynomial_mul_acc_bytes(&mut self.0, &a.0, &b.0);
    }
}


// Implementations using BitVec
pub fn polynomial_new_bitvec(size: usize) -> BitVec<Block> {
    let mut result = BitVec::with_capacity(size);
    for _ in 0..size {
        result.push(false);
    }

    return result;
}
pub fn polynomial_zero_bitvec(coefficients: &mut BitVec<Block>) {
    coefficients.fill(false);
}
pub fn polynomial_acc_bitvec(left: &mut BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    *left ^= right;
}
pub fn polynomial_eq_bitvec(left: &BitVec<Block>, right: &BitVec<Block>) -> bool {
    debug_assert!(left.len() == right.len());
    return left.eq(right);
}
pub fn polynomial_mul_bitvec(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let mut intermediate = polynomial_new_bitvec(left.len() * 2);

    // Multiply by the remainder of the lhs
    for i in 0..size {
        // TODO: It might be faster to check the LHS before looping, depending on how good the
        //       branch predictor is.
        for j in 0..size {
            let l = left[i];
            let r = right[j];

            if l && r {
                let target = i + j;
                let value = intermediate[target] ^ true;
                intermediate.set(target, value);
            }
        }
    }

    // TODO: What about the modulo/overflow?
    for i in 0..size {
        result.set(i, intermediate[i]);
    }
}

// Implmentation manipulating bytes of the BitVec
pub fn polynomial_new_bytes(size: usize) -> BitVec<Block> {
    let bytes = vec![0u8; size / 8];
    return BitVec::from_slice(bytes.as_slice());
}
pub fn polynomial_zero_bytes(coefficients: &mut BitVec<Block>) {
    let bytes = coefficients.as_raw_mut_slice();
    for i in 0..bytes.len() {
        bytes[i] = 0;
    }
}
pub fn polynomial_acc_bytes(left: &mut BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());

    let left_bytes = left.as_raw_mut_slice();
    let right_bytes = right.as_raw_slice();

    for i in 0..right_bytes.len() {
        left_bytes[i] ^= right_bytes[i];
    }
}
pub fn polynomial_eq_bytes(left: &BitVec<Block>, right: &BitVec<Block>) -> bool {
    debug_assert!(left.len() == right.len());

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();

    for i in 0..left_bytes.len() {
        if left_bytes[i] != right_bytes[i] {
            return false;
        }
    }

    return true;
}
pub fn polynomial_mul_bytes(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();

    let mut intermediate = polynomial_new_bitvec(left.len() * 2);
    let intermediate_bytes = intermediate.as_raw_mut_slice();

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

    let result_bytes = result.as_raw_mut_slice();
    for i in 0..size_bytes {
        result_bytes[i] = intermediate_bytes[i];
    }
}
pub fn polynomial_mul_acc_bytes(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();

    let mut intermediate = polynomial_new_bitvec(left.len() * 2);
    let intermediate_bytes = intermediate.as_raw_mut_slice();

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

    let result_bytes = result.as_raw_mut_slice();
    for i in 0..size_bytes {
        result_bytes[i] ^= intermediate_bytes[i];
    }
}
pub fn polynomial_mul_acc_bytes_alt(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();
    let result_bytes = result.as_raw_mut_slice();

    for i in 0..size_bytes {
        for j in 0..size_bytes {
            for ib in 0..8 {
                for jb in 0..8 {
                    let ii = i * 8 + ib;
                    let jj = j * 8 + jb;
                    let l = left_bytes[i] & (1 << ib) > 0;
                    let r = right_bytes[j] & (1 << jb) > 0;

                    let target = ii + jj;
                    let result_index = target / 8;
                    let result_bit = target % 8;

                    if l && r && result_index < size_bytes {
                        result_bytes[result_index] ^= 1 << result_bit;
                    }
                }
            }
        }
    }
}

pub fn polynomial_print(polynomial: &BitVec<Block>) {
    let len = polynomial.len();
    let mut last = 0;
    for i in 0..len {
        if polynomial[len - i - 1] {
            last = i;
        }
    }

    for i in 0..len {
        if polynomial[len - i - 1] {
            if i == 0 {
                print!("1");
            } else if i == 1 {
                print!("X");
            } else {
                print!("X^{}", len - i - 1);
            }

            if i != last {
                print!(" + ");
            }
        }
    }
    println!();
}

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

#[cfg(target_arch = "x86_64")]
pub unsafe fn polynomial_gf128_mul_lower(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    use std::arch::x86_64::*;
    let left_bytes = left.as_raw_slice().as_ptr() as *const __m128i;
    let right_bytes = right.as_raw_slice().as_ptr() as *const __m128i;
    let result_bytes = result.as_raw_mut_slice().as_mut_ptr() as *mut __m128i;

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

    _mm_store_si128(result_bytes, right);
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn polynomial_gf128_mul_ocelot(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    use std::arch::x86_64::*;
    let left_bytes = left.as_raw_slice().as_ptr() as *const __m128i;
    let right_bytes = right.as_raw_slice().as_ptr() as *const __m128i;
    let result_bytes = result.as_raw_mut_slice().as_mut_ptr() as *mut __m128i;

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

    _mm_store_si128(result_bytes, xor);
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn polynomial_gf128_mul_reduce(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    use std::arch::x86_64::*;
    let left_bytes = left.as_raw_slice().as_ptr() as *const __m128i;
    let right_bytes = right.as_raw_slice().as_ptr() as *const __m128i;
    let result_bytes = result.as_raw_mut_slice().as_mut_ptr() as *mut __m128i;

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
    _mm_store_si128(result_bytes, reduced);
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn polynomial_mul_acc_fast(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    use std::arch::x86_64::*;
    let left_bytes = left.as_raw_slice().as_ptr() as *const __m128i;
    let right_bytes = right.as_raw_slice().as_ptr() as *const __m128i;
    let result_bytes = result.as_raw_mut_slice().as_mut_ptr() as *mut __m128i;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_mul_bitvec() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101]); // x^2 + 1
        let mut result = polynomial_new_bitvec(8);

        polynomial_mul_bitvec(&mut result, &left, &right);

        // Expecting x^3 + x^2 + x + 1
        assert_eq!(true, result[0]);
        assert_eq!(true, result[1]);
        assert_eq!(true, result[2]);
        assert_eq!(true, result[3]);
        assert_eq!(false, result[4]);
        assert_eq!(false, result[5]);
        assert_eq!(false, result[6]);
        assert_eq!(false, result[7]);
    }

    #[test]
    fn test_polynomial_mul_bytes() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101]); // x^2 + 1
        let mut result = polynomial_new_bitvec(8);

        polynomial_mul_bytes(&mut result, &left, &right);

        // Expecting x^3 + x^2 + x + 1
        assert_eq!(true, result[0]);
        assert_eq!(true, result[1]);
        assert_eq!(true, result[2]);
        assert_eq!(true, result[3]);
        assert_eq!(false, result[4]);
        assert_eq!(false, result[5]);
        assert_eq!(false, result[6]);
        assert_eq!(false, result[7]);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_polynomial_gf128_mul_lower() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // x^2 + 1
        let mut result = polynomial_new_bitvec(128);

        unsafe {
            polynomial_gf128_mul_lower(&mut result, &left, &right);
        }

        // Expecting x^3 + x^2 + x + 1
        let result_bytes = result.as_raw_slice();
        assert_eq!(0b0000_1111, result_bytes[0]);
        for i in 1..16 {
            assert_eq!(0, result_bytes[i]);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_polynomial_gf128_mul_ocelot() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // x^2 + 1
        let mut result = polynomial_new_bitvec(128);

        unsafe {
            polynomial_gf128_mul_ocelot(&mut result, &left, &right);
        }

        // Expecting x^3 + x^2 + x + 1
        let result_bytes = result.as_raw_slice();
        assert_eq!(0b0000_1111, result_bytes[0]);
        for i in 1..16 {
            assert_eq!(0, result_bytes[i]);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_polynomial_gf128_mul_reduce() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // x^2 + 1
        let mut result = polynomial_new_bitvec(128);

        unsafe {
            polynomial_gf128_mul_reduce(&mut result, &left, &right);
        }

        // Expecting x^3 + x^2 + x + 1
        let result_bytes = result.as_raw_slice();
        assert_eq!(0b0000_1111, result_bytes[0]);
        for i in 1..16 {
            assert_eq!(0, result_bytes[i]);
        }
    }
}
