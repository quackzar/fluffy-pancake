use serde::{Deserialize, Serialize};
// Tools for building circuits.
#[derive(Debug, Serialize, Deserialize)]
pub struct ArithCircuit {
    // TODO: Const Generics?
    pub num_wires: usize,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub(crate) gates: Vec<ArithGate>,
    pub input_domains: Vec<u16>,
}



#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum ArithGateKind {
    Add,
    Mul(u16),
    Proj(ProjectionGate)
}


#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum ProjectionGate {
    Map(u16),
    Less(u16),
}

// TODO: Move Proj Gate logic here.


#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ArithGate {
    pub output: usize,
    pub domain: u16,
    pub inputs: Vec<usize>,
    pub kind: ArithGateKind,
}

// TODO: Make CircuitBuilder.

// TODO: Make non-garbled eval.
