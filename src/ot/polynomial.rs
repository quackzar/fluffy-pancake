use std::io::Write;
use std::ops::BitXor;
use num_integer;
use crate::ot::bitmatrix::*;
use bitvec::prelude::*;

pub fn polynomial_new(size: usize) -> BitVec<Block> {
    let mut result = BitVec::with_capacity(size);
    for _ in 0..size {
        result.push(false);
    }

    return result;
}
pub fn polynomial_new_raw(size: usize) -> BitVec<Block> {
    let bytes = vec![0u8; size / 8];
    return BitVec::from_slice(bytes.as_slice());
}

pub fn polynomial_zero(coefficients: &mut BitVec<Block>) {
    coefficients.fill(false);
}
pub fn polynomial_zero_raw(coefficients: &mut BitVec<Block>) {
    let bytes = coefficients.as_raw_mut_slice();
    for i in 0..bytes.len() {
        bytes[i] = 0;
    }
}

pub fn polynomial_acc(left: &mut BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    *left ^= right;
}
pub fn polynomial_acc_raw(left: &mut BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());

    let left_bytes = left.as_raw_mut_slice();
    let right_bytes = right.as_raw_slice();

    for i in 0..right_bytes.len() {
        left_bytes[i] ^= right_bytes[i];
    }
}

pub fn polynomial_mul(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let mut intermediate = polynomial_new(left.len() * 2);

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
pub fn polynomial_mul_raw(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();

    let mut intermediate = polynomial_new(left.len() * 2);

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
                        let value = intermediate[target] ^ true;
                        intermediate.set(target, value);
                    }
                }
            }
        }
    }

    // TODO: What about the modulo/overflow?
    for i in 0..size {
        result.set(i, intermediate[i]);
    }
}
pub fn polynomial_mul_raw_2(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();

    let mut intermediate = polynomial_new(left.len() * 2);
    let intermediate_bytes = intermediate.as_raw_mut_slice();

    for i in 0..size_bytes {
        for j in 0..size_bytes {
            for ib in 0..8 {
                for jb in 0..8 {
                    let ii = i * 8+ ib;
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

    // TODO: What about the modulo/overflow?
    for i in 0..size {
        result.set(i, intermediate[i]);
    }
}
pub fn polynomial_mul_raw_3(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();

    let mut intermediate = polynomial_new(left.len() * 2);
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
pub fn polynomial_mul_raw_4(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();

    let mut intermediate = polynomial_new(left.len() * 2);
    let intermediate_bytes = intermediate.as_raw_mut_slice();

    for i in 0..size_bytes {
        for j in 0..size_bytes {
            for ib in 0..8 {
                for jb in 0..8 {
                    let ii = i * 8 + ib;
                    let jj = j * 8 + jb;
                    let l = left_bytes[i] & (1 << ib) > 0;
                    let r = right_bytes[j] & (1 << jb) > 0;

                    if l & r {
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
pub fn polynomial_mul_raw_5(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();

    let mut intermediate = polynomial_new(left.len() * 2);
    let intermediate_bytes = intermediate.as_raw_mut_slice();

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
                    intermediate_bytes[result_index] ^= ((l && r) as u8) << result_bit;
                }
            }
        }
    }

    let result_bytes = result.as_raw_mut_slice();
    for i in 0..size_bytes {
        result_bytes[i] = intermediate_bytes[i];
    }
}

pub fn polynomial_mul_acc(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    let size = left.len();
    let size_bytes = size / 8;

    let left_bytes = left.as_raw_slice();
    let right_bytes = right.as_raw_slice();

    let mut intermediate = polynomial_new(left.len() * 2);
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

pub fn polynomial_mul_acc_2(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
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

pub fn polynomial_eq(left: &BitVec<Block>, right: &BitVec<Block>) -> bool {
    debug_assert!(left.len() == right.len());
    return left.eq(right);
}
pub fn polynomial_eq_raw(left: &BitVec<Block>, right: &BitVec<Block>) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_mul() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101]); // x^2 + 1
        let mut result = polynomial_new(8);

        polynomial_mul(&mut result, &left, &right);

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
    fn test_polynomial_mul_raw() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101]); // x^2 + 1
        let mut result = polynomial_new(8);

        polynomial_mul_raw(&mut result, &left, &right);

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
    fn test_polynomial_mul_raw_2() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101]); // x^2 + 1
        let mut result = polynomial_new(8);

        polynomial_mul_raw_2(&mut result, &left, &right);

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
    fn test_polynomial_mul_raw_3() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101]); // x^2 + 1
        let mut result = polynomial_new(8);

        polynomial_mul_raw_3(&mut result, &left, &right);

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
    fn test_polynomial_mul_raw_4() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101]); // x^2 + 1
        let mut result = polynomial_new(8);

        polynomial_mul_raw_4(&mut result, &left, &right);
        print!("Result ->");
        polynomial_print(&result);

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
    fn test_polynomial_mul_raw_5() {
        let left: BitVec<Block> = BitVec::from_vec(vec![0b00000011]); // x + 1
        let right: BitVec<Block> = BitVec::from_vec(vec![0b00000101]); // x^2 + 1
        let mut result = polynomial_new(8);

        polynomial_mul_raw_5(&mut result, &left, &right);
        print!("Result -> ");
        polynomial_print(&result);

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
}