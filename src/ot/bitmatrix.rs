use std::mem;

// BitMatrix and BitVector
use bitvec::prelude::*;
use serde::{Deserialize, Serialize};

pub type Block = u8;
pub const BLOCK_SIZE: usize = mem::size_of::<Block>() * 8;

#[repr(transparent)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitMatrix {
    rows: Vec<BitVec<Block>>,
}

impl BitMatrix {
    pub fn new(rows: Vec<BitVec<Block>>) -> BitMatrix {
        BitMatrix { rows }
    }

    pub fn dims(&self) -> (usize, usize) {
        (self.rows.len(), self.rows[0].len())
    }

    // PERF: Work on bytes instead of booleans.
    pub fn transpose(&self) -> BitMatrix {
        let (rows, cols) = self.dims();
        let mut new_rows = Vec::with_capacity(cols);
        for col in 0..cols {
            let mut new_row = BitVec::with_capacity(rows);
            for row in 0..rows {
                new_row.push(self.rows[row][col]);
            }
            new_rows.push(new_row);
        }
        BitMatrix::new(new_rows)
    }
}

impl FromIterator<BitVec<Block>> for BitMatrix {
    fn from_iter<I: IntoIterator<Item = BitVec<Block>>>(iter: I) -> Self {
        let mut rows = Vec::new();
        for row in iter {
            rows.push(row);
        }
        BitMatrix::new(rows)
    }
}

impl IntoIterator for BitMatrix {
    type Item = BitVec<Block>;
    type IntoIter = std::vec::IntoIter<BitVec<Block>>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

impl<'a> IntoIterator for &'a BitMatrix {
    type Item = &'a BitVec<Block>;
    type IntoIter = std::slice::Iter<'a, BitVec<Block>>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.iter()
    }
}

use std::ops::Index;
impl Index<usize> for BitMatrix {
    type Output = BitVec<Block>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.rows[index]
    }
}
