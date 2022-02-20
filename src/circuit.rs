



// Tools for building circuits.
#[derive(Debug)]
pub struct ArithCircuit {
    pub num_wires: usize,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub(crate) gates: Vec<ArithGate>,
    pub input_domains: Vec<u16>,
}

#[derive(Debug, PartialEq)]
pub(crate) enum ArithGateKind {
    Add,
    Mul(u16),
    Proj(u16, fn(u16) -> u16),

    // Special cases of the projection gate
    Map(u16),
    Less(u16),
}

#[derive(Debug)]
pub(crate) struct ArithGate {
    pub output: usize,
    pub domain: u16,
    pub inputs: Vec<usize>,
    pub kind: ArithGateKind,
}

const GATE_ADD:  u8 = 0x00;
const GATE_MUL:  u8 = 0x01;
const GATE_MAP:  u8 = 0x02;
const GATE_LESS: u8 = 0x03;

