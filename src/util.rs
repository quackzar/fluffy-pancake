use std::io::{Read, Write};
use num_traits::PrimInt;
use rand::Rng;
use std::fs::File;
use sha2::{Sha256, Digest};

#[inline]
pub fn rng(max: u16) -> u16 {
    rand::thread_rng().gen_range(0..max)
}


pub fn write_u8(value: u8, file: &mut File) {
    file.write(&value.to_be_bytes());
}

pub fn read_u8(file: &mut File) -> u8 {
    let mut bytes = [0u8; 1];
    file.read(&mut bytes);
    bytes[0]
}

pub fn write_u64(value: u64, file: &mut File) {
    file.write(&value.to_be_bytes());
}

pub fn read_u64(file: &mut File) -> u64 {
    let mut bytes = [0u8; 8];
    file.read(&mut bytes);
    u64::from_be_bytes(bytes)
}


#[inline]
pub fn log2<N : PrimInt>(x: N) -> u32 {
    (std::mem::size_of::<N>() * 8) as u32 - (x - N::one()).leading_zeros()
}



/// Variadic Hashing
/// Hashing based on Sha256 producing a 32 byte hash
/// Arguments are hashed in order.
#[macro_export]
macro_rules! hash {
    ($e:expr) => {{
        let mut hasher = Sha256::new();
        hasher.update($e);
        hasher.finalize()
    }};
    // Decompose
    ($e:expr, $($ls:expr),*) => {{
        let mut hasher = Sha256::new();
        hasher.update($e);
        hash!(@next hasher, $($ls),*);
        hasher.finalize()
    }};

    // Recursive update
    (@next $hasher:expr, $e:expr, $ls:tt) => {{
        $hasher.update($e);
        hash!(@next $hasher, $e);
    }};

    // Last
    (@next $hasher:expr, $e:expr) => {{
        $hasher.update($e);
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let h1 = hash!("hello", "world");
        let mut hasher = Sha256::new();
        hasher.update("hello");
        hasher.update("world");
        let h2 = hasher.finalize();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_log2() {
        assert!(log2(1)==0);
        assert!(log2(2)==1);
        assert!(log2(3)==2);
        assert!(log2(4)==2);
        assert!(log2(5)==3);
        assert!(log2(8)==3);
        assert!(log2(9)==4);
    }
}

