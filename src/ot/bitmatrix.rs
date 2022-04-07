use std::mem;

use std::ops::BitAnd;
use std::ops::BitAndAssign;
use std::ops::BitXor;
use std::ops::BitXorAssign;
use std::ops::Index;
use std::ops::Range;
use std::ops::RangeFrom;
use std::ops::RangeFull;
use std::ops::RangeInclusive;

use rayon::prelude::*;

use rayon::iter::FromParallelIterator;
use rayon::prelude::IntoParallelIterator;
// BitMatrix and BitVector
use serde::{Deserialize, Serialize};

pub type Block = u64;
pub const BLOCK_SIZE: usize = mem::size_of::<Block>() * 8;

#[repr(transparent)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BitVector(Vec<Block>);

impl BitVector {
    #[inline]
    pub fn zeros(size: usize) -> Self {
        Self::from_bytes(&vec![0x00u8; size / 8])
    }

    #[inline]
    pub fn ones(size: usize) -> Self {
        Self::from_bytes(&vec![0xFFu8; size / 8])
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len() * BLOCK_SIZE
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn from_vec(vec: Vec<Block>) -> Self {
        Self(vec)
    }

    #[inline]
    pub fn from_bytes(vec: &[u8]) -> Self {
        unsafe {
            // TODO: Fallback if alignment fails.
            let (head, body, tail) = vec.align_to::<Block>();
            debug_assert!(tail.is_empty());
            debug_assert!(head.is_empty());
            Self::from_vec(body.to_vec())
        }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            let (head, body, tail) = self.0.align_to::<u8>();
            debug_assert!(tail.is_empty());
            debug_assert!(head.is_empty());
            body
        }
    }

    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe {
            let (head, body, tail) = self.0.align_to_mut::<u8>();
            debug_assert!(tail.is_empty());
            debug_assert!(head.is_empty());
            body
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[Block] {
        &self.0
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [Block] {
        &mut self.0
    }
}

impl BitXor for BitVector {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output::from_vec(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(l, r)| l ^ r)
                .collect(),
        )
    }
}

impl BitXor for &BitVector {
    type Output = BitVector;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output::from_vec(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(l, r)| l ^ r)
                .collect(),
        )
    }
}

impl BitAnd for BitVector {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self::Output::from_vec(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(l, r)| l & r)
                .collect(),
        )
    }
}

impl BitXorAssign for BitVector {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l ^= *r;
        }
    }
}

impl BitXorAssign<&Self> for BitVector {
    #[inline]
    fn bitxor_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.0.len(), rhs.0.len(), "BitVector lengths must be equal");
        let lhs = &mut self.0;
        let rhs = &rhs.0;
        for i in 0..lhs.len() {
            lhs[i] ^= rhs[i];
        }
    }
}

impl BitAndAssign for BitVector {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l &= *r;
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitMatrix {
    rows: Vec<BitVector>,
}

impl BitMatrix {
    #[inline]
    pub fn new(rows: Vec<BitVector>) -> Self {
        Self { rows }
    }

    #[inline]
    pub fn monochrome(choices: &[bool], size: usize) -> Self {
        let l = choices.len();
        let mut packed_choices = vec![0u64; l/64];
        for i in 0..l/64 {
            for b in 0..64 {
                packed_choices[i] |= (choices[i*64 + b] as u64) << b;
            }
        }
        let mut x = vec![vec![0u64; l/64]; size];
        for row in x.iter_mut() {
            row[..(l / 64)].copy_from_slice(&packed_choices);
        }
        Self::from(x)
    }

    #[inline]
    pub fn dims(&self) -> (usize, usize) {
        (self.rows.len(), self.rows[0].len())
    }

    // PERF: Work on bytes instead of booleans. See below.
    // // https://stackoverflow.com/questions/31742483/how-would-you-transpose-a-binary-matrix
    #[inline]
    pub fn transpose(&self) -> Self {
        let (rows, cols) = self.dims();
        let mut raw: Vec<Vec<Block>> = vec![vec![0; rows / BLOCK_SIZE]; cols];
        let source = self.rows.as_slice();
        for row_idx in 0..rows {
            for col_idx in 0..cols / BLOCK_SIZE {
                let source_byte = source[row_idx].as_slice()[col_idx];
                for b in 0..BLOCK_SIZE {
                    let source_bit = (source_byte >> b) & 1;

                    let target_row = col_idx * BLOCK_SIZE + b;
                    let target_col = row_idx / BLOCK_SIZE;
                    let target_shift = row_idx % BLOCK_SIZE;

                    raw[target_row][target_col] |= source_bit << target_shift;
                }
            }
        }
        let raw: Vec<BitVector> = unsafe { mem::transmute(raw) };
        Self { rows: raw }
    }
}

fn tranpose_64(matrix: &mut [u64; 64])  {
    let mut m = 0x0000_0000_FFFF_FFFF; // 32 bit.
    let mut j = 16;
    while j != 0 {
        let mut k = 0;
        while k < 64 {
            let t = matrix[k] ^ (matrix[k+j] >> j) & m;
            matrix[k] ^=  t;
            matrix[k+j] ^= t << j;
            k = (k + j + 1) & !j;
        }
        m ^= m << j;
        j >>= 1;
    }
}

impl From<Vec<Vec<Block>>> for BitMatrix {
    #[inline]
    fn from(rows: Vec<Vec<Block>>) -> Self {
        unsafe {
            mem::transmute(rows)
        }
    }
}


impl FromIterator<BitVector> for BitMatrix {
    fn from_iter<I: IntoIterator<Item = BitVector>>(iter: I) -> Self {
        let mut rows = Vec::new();
        for row in iter {
            rows.push(row);
        }
        Self::new(rows)
    }
}

impl FromParallelIterator<BitVector> for BitMatrix {
    fn from_par_iter<I: IntoParallelIterator<Item = BitVector>>(par_iter: I) -> Self {
        let rows: Vec<BitVector> = par_iter.into_par_iter().collect();
        Self::new(rows)
    }
}

impl IntoIterator for BitMatrix {
    type Item = BitVector;
    type IntoIter = std::vec::IntoIter<BitVector>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

impl<'a> IntoIterator for &'a BitMatrix {
    type Item = &'a BitVector;
    type IntoIter = std::slice::Iter<'a, BitVector>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.rows.iter()
    }
}

impl Index<usize> for BitMatrix {
    type Output = BitVector;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.rows[index]
    }
}

impl IntoParallelIterator for BitMatrix {
    type Item = BitVector;
    type Iter = rayon::vec::IntoIter<BitVector>;

    #[inline]
    fn into_par_iter(self) -> Self::Iter {
        self.rows.into_par_iter()
    }
}

use std::ops::RangeTo;
impl Index<RangeTo<usize>> for BitMatrix {
    type Output = [BitVector];

    #[inline]
    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.rows[index]
    }
}

impl Index<Range<usize>> for BitMatrix {
    type Output = [BitVector];

    #[inline]
    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.rows[index]
    }
}

impl Index<RangeInclusive<usize>> for BitMatrix {
    type Output = [BitVector];

    #[inline]
    fn index(&self, index: RangeInclusive<usize>) -> &Self::Output {
        &self.rows[index]
    }
}

impl Index<RangeFrom<usize>> for BitMatrix {
    type Output = [BitVector];

    #[inline]
    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.rows[index]
    }
}

impl Index<RangeFull> for BitMatrix {
    type Output = [BitVector];

    #[inline]
    fn index(&self, _index: RangeFull) -> &Self::Output {
        &self.rows[..]
    }
}


mod tests {
    use rand::{Rng, SeedableRng};

    use super::tranpose_64;

    #[test]
    fn test_transpose64() {
        // let mut rng = rand_chacha::ChaCha20Rng::from_seed([0; 32]);
        // let mut x : [u64; 64] = rng.gen();
        let mut x = [7; 64];
        println!("Before");
        for i in 0..64 {
            println!("{:#066b}", &x[i]);
        }

        tranpose_64(&mut x);

        println!("After");
        for i in 0..64 {
            println!("{:#066b}", &x[i]);
        }
    }

}
