use num_traits::PrimInt;
use rand::{Rng, RngCore};

// Global Constants
pub const SECURITY_PARAM: usize = 256; // bits used total
pub const LENGTH: usize = SECURITY_PARAM / 8; // bytes used
pub type WireBytes = [u8; LENGTH];

#[inline]
pub fn rng(max: u16) -> u16 {
    rand::thread_rng().gen_range(0..max)
}

#[inline]
pub fn random_bytes(bytes: &mut [u8]) {
    rand::thread_rng().fill_bytes(bytes)
}

#[inline]
pub fn log2<N: PrimInt>(x: N) -> u32 {
    (std::mem::size_of::<N>() * 8) as u32 - (x - N::one()).leading_zeros()
}

pub fn u8_vec_to_bool_vec(str: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(8 * str.len());
    for s in str {
        for i in 0..8 {
            bits.push((s >> i) & 1 == 1);
        }
    }
    bits
}

pub fn bool_vec_to_u8_vec(str: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(str.len() / 8);
    let mut byte = 0;
    for (i, bit) in str.iter().enumerate() {
        if *bit {
            byte |= 1 << (7 - i % 8);
        }
        if i % 8 == 7 {
            bytes.push(byte);
            byte = 0;
        }
    }
    bytes
}

pub fn to_array(bytes: &[u8]) -> WireBytes {
    debug_assert!(bytes.len() == LENGTH, "Should be {} bytes", LENGTH);
    let mut array = [0u8; LENGTH];
    array.copy_from_slice(bytes);
    array
}

// impl core::ops::BitXor for WireBytes {
//     type Output = WireBytes;
//     fn bitxor(self, rhs: Self) -> Self::Output {
//         xor(self, rhs)
//     }
// }

/// Variadic Hashing
/// Hashing based on Sha256 producing a 32 byte hash
/// Arguments are hashed in order.
#[macro_export]
macro_rules! hash {
    // Decompose
    ($($ls:expr),+) => {{
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hash!(@next hasher, $($ls),+);
        let digest = hasher.finalize();
        <[u8; 256/8]>::try_from(digest.as_ref()).expect("digest too long")
    }};

    // Recursive update
    (@next $hasher:expr, $e:expr, $($ls:expr),+) => {{
        $hasher.update($e);
        hash!(@next $hasher, $($ls),+)
    }};

    // Last
    (@next $hasher:expr, $e:expr) => {{
        $hasher.update($e);
    }};
}
pub use hash;

pub fn xor(a: WireBytes, b: WireBytes) -> WireBytes {
    let mut result = [0u8; LENGTH];
    for i in 0..LENGTH {
        result[i] = a[i] ^ b[i];
    }
    result
}

pub fn xor_bytes(left: &[u8], right: &[u8]) -> Vec<u8> {
    debug_assert_eq!(left.len(), right.len());

    let mut result = Vec::with_capacity(left.len());
    for i in 0..left.len() {
        result.push(left[i] ^ right[i]);
    }

    result
}

pub fn xor_bytes_inplace(left: &mut [u8], right: &[u8]) {
    debug_assert_eq!(left.len(), right.len());

    for i in 0..left.len() {
        left[i] ^= right[i];
    }
}

// -------------------------------------------------------------------------------------------------
// PTR helpers
#[inline]
pub fn index_1d(row: usize, column: usize, width: usize) -> usize {
    width * row + column
}
#[inline]
pub unsafe fn vector_row(vector: &Vec<u8>, row: usize, width: usize) -> &[u8] {
    let ptr = vector.as_ptr();
    let offset = (width * row) as isize;
    let into = ptr.offset(offset);
    std::slice::from_raw_parts(into, width)
}
#[inline]
pub unsafe fn vector_row_mut(vector: &mut Vec<u8>, row: usize, width: usize) -> &mut [u8] {
    let ptr = vector.as_mut_ptr();
    let offset = (width * row) as isize;
    let into = ptr.offset(offset);
    std::slice::from_raw_parts_mut(into, width)
}
#[inline]
pub unsafe fn vector_slice(vector: &Vec<u8>, offset: usize, length: usize) -> &[u8] {
    let ptr = vector.as_ptr();
    let into = ptr.add(offset);
    std::slice::from_raw_parts(into, length)
}
#[inline]
pub unsafe fn vector_slice_mut(vector: &mut Vec<u8>, offset: usize, length: usize) -> &mut [u8] {
    let ptr = vector.as_mut_ptr();
    let into = ptr.add(offset);
    std::slice::from_raw_parts_mut(into, length)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn test_hash() {
        let h1 = hash!("hello", "world");
        let mut hasher = Sha256::new();
        hasher.update("hello");
        hasher.update("world");
        let h2 = hasher.finalize();
        let h2 = <WireBytes>::try_from(h2.as_ref()).expect("digest too long");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_log2() {
        assert!(log2(1) == 0);
        assert!(log2(2) == 1);
        assert!(log2(3) == 2);
        assert!(log2(4) == 2);
        assert!(log2(5) == 3);
        assert!(log2(8) == 3);
        assert!(log2(9) == 4);
    }
}
