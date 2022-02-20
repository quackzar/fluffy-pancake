use std::io::{Read, Write};
use num_traits::PrimInt;
use rand::Rng;
use std::fs::File;

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
    // TODO: Test
    (std::mem::size_of::<N>() * 8) as u32 - x.leading_zeros()
}

#[cfg(tests)]
mod tests {
    use super::*;

    fn test_log2<N : PrimInt>(x: N) {
        assert_eq!(log2(2), 1);
    }
}

