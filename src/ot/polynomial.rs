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
        if cfg!(target_arch = "x86_64") {
            polynomial_mul_acc_x86(&mut self.0, &a.0, &b.0);
        } else {
            polynomial_mul_acc(&mut self.0, &a.0, &b.0);
        }
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
        Self(polynomial_mul(&self.0, &other.0))
    }
}

impl MulAssign for Polynomial {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        self.0 = polynomial_mul(&self.0, &other.0)
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

fn polynomial_mul(left: &BitVector, right: &BitVector) -> BitVector {
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

fn polynomial_mul_acc(result: &mut BitVector, left: &BitVector, right: &BitVector) {
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


// #[cfg(target_arch = "x86_64")]
#[inline]
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

// https://stackoverflow.com/questions/38553881/convert-mm-clmulepi64-si128-to-vmull-high-p64
#[allow(clippy::missing_safety_doc)]
#[cfg(target_arch = "aarch64")]
pub unsafe fn polynomial_mul_acc_arm64(left: &BitVector, right: &BitVector) -> BitVector {
    debug_assert!(left.len() == 128);
    debug_assert!(right.len() == 128);
    use std::arch::aarch64::*;
    let left = left.as_bytes().as_ptr() as *const u64;
    let right = right.as_bytes().as_ptr() as *const u64;

    let a = vmull_p64(*left, *right); // first 'low' 64 bits
    let left = vld1q_p64(left);
    let right = vld1q_p64(right);
    let b = vmull_high_p64(left, right); // second 'high' 64 bits
    let c = (b & 0xFFFFFFFF00000000u128) ^ (a & 0x00000000FFFFFFFFu128); // combine
    let res: [Block; 128 / BLOCK_SIZE] = std::mem::transmute(c);
    BitVector::from_vec(res.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_aarch64_poly() {
        use rand::{thread_rng, Rng};
        for _ in 0..100 {
            let a = thread_rng().gen::<[u8; 16]>();
            let b = thread_rng().gen::<[u8; 16]>();
            let a = BitVector::from_bytes(&a);
            let b = BitVector::from_bytes(&b);
            // let mut c = BitVec::<Block>::from_slice(&[0x00; 16]);
            let c = unsafe { polynomial_mul_acc_arm64(&a, &b) };
            let r1 = Polynomial::from(c);

            let _c = BitVector::from_bytes(&[0x00; 16]);
            let c = polynomial_mul(&a, &b);
            let r2 = Polynomial::from(c);

            assert_eq!(r1, r2);
        }
    }
}
