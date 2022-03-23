use crate::ot::bitmatrix::*;
use bitvec::prelude::*;

pub fn polynomial_new(size: usize) -> BitVec<Block> {
    let mut result = BitVec::with_capacity(size);
    for _ in 0..size {
        result.push(false);
    }

    return result;
}
pub fn polynomial_zero(coefficients: &mut BitVec<Block>) {
    coefficients.fill(false);
}
pub fn polynomial_add(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    *result ^= left;
    *result ^= right;
}
pub fn polynomial_acc(left: &mut BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    *left ^= right;
}
pub fn polynomial_mul(result: &mut BitVec<Block>, left: &BitVec<Block>, right: &BitVec<Block>) {
    debug_assert!(left.len() == right.len());
    debug_assert!(left.len() == result.len());

    // NOTE: By convention the coefficients start at index 0
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
pub fn polynomial_eq(left: &BitVec<Block>, right: &BitVec<Block>) -> bool {
    debug_assert!(left.len() == right.len());
    return left.eq(right);
}

pub fn polynomial_print(polynomial: &BitVec<Block>) {
    let len = polynomial.len();
    let mut last = 0;
    for i in 0..len {
        if polynomial[i] {
            last = i;
        }
    }

    for i in 0..len {
        if polynomial[i] {
            if i == 0 {
                print!("1");
            } else {
                print!("x^{i}");
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
    fn test_polynomial_multiply() {
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
}