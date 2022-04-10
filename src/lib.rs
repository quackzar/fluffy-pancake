#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::must_use_unit)]
// #![warn(clippy::pedantic)]
#![warn(clippy::nursery)]


extern crate core;

pub mod circuit;
pub mod common;
pub mod fpake;
pub mod garble;
pub mod ot;
pub mod util;
mod instrument;
mod wires;
