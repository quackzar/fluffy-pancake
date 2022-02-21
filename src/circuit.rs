use std::{error::Error, fmt, collections::HashSet};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
// Tools for building circuits.
#[derive(Debug, Serialize, Deserialize)]
pub struct Circuit {
    // TODO: Const Generics?
    pub num_wires: usize,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub(crate) gates: Vec<Gate>,
    pub input_domains: Vec<u16>,
}



#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum GateKind {
    Add,
    Mul(u16),
    Proj(ProjKind)
}


#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum ProjKind {
    Map(u16),
    Less(u16),
}

impl ProjKind {
    #[inline]
    pub fn project(&self, x : u16) -> u16 {
        use ProjKind::*;
        match *self {
            Map(_) => x,
            Less(t) => (x < t) as u16,
        }
    }

    #[inline]
    pub fn domain(&self) -> u16 {
        use ProjKind::*;
        match *self {
            Map(m) => m,
            Less(_) => 2,
        }
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Gate {
    pub output: usize,
    pub domain: u16,
    pub inputs: Vec<usize>,
    pub kind: GateKind,
}

// TODO: Make CircuitBuilder.

// TODO: Make non-garbled eval.
//



#[derive(Debug)]
pub enum CircuitError {
    BadOutputCount,
    BadInputCount,
    BadWireCount(usize, usize),
    BadDomain,
}
impl Error for CircuitError {}
impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            CircuitError::BadInputCount => {
                write!(f, "Error, circuit input wires are used as output.")
            }
            CircuitError::BadOutputCount => write!(f, "Bad output count"),
            CircuitError::BadWireCount(a, b) => {
                write!(f, "Bad wire count, actual {a}, but {b} defined")
            }
            CircuitError::BadDomain => write!(f, "Bad domain"),
        }
    }
}

fn verify_circuit(circuit: &Circuit) -> Result<(), CircuitError> {
    let num_wires = circuit
        .gates
        .iter()
        .flat_map(|g| &g.inputs)
        .chain(circuit.gates.iter().map(|g| &g.output))
        .unique()
        .count();
    if num_wires != circuit.num_wires {
        // circuit has different amount of wires
        return Err(CircuitError::BadWireCount(num_wires, circuit.num_wires));
    }
    let mut uniq = HashSet::new();
    let ok = circuit.gates.iter().map(|g| g.output).all(move |i| uniq.insert(i));
    if !ok {
        return Err(CircuitError::BadOutputCount);
    }
    Ok(())
}
