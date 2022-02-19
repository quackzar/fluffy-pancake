use std::fs::File;

use crate::util::*;

// Tools for building circuits.
#[derive(Debug)]
pub struct ArithCircuit {
    pub num_wires: usize,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub(crate) gates: Vec<ArithGate>,
    pub input_domains: Vec<u64>,
}

impl ArithCircuit {
    fn serialize(&self, file: &mut File) {
        write_u64(self.num_wires as u64, file);
        write_u64(self.num_inputs as u64, file);
        write_u64(self.num_outputs as u64, file);

        write_u64(self.gates.len() as u64, file);
        for gate in &self.gates {
            gate.serialize(file);
        }

        for domain in &self.input_domains {
            write_u64(*domain, file);
        }
    }
    fn deserialize(file: &mut File) -> ArithCircuit {
        let num_wires = read_u64(file) as usize;
        let num_inputs = read_u64(file) as usize;
        let num_outputs = read_u64(file) as usize;

        let num_gates = read_u64(file) as usize;
        let mut gates = Vec::with_capacity(num_gates);
        for _ in 0..num_gates {
            gates.push(ArithGate::deserialize(file));
        }

        let mut input_domains = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            input_domains.push(read_u64(file))
        }

        ArithCircuit {
            num_wires,
            num_inputs,
            num_outputs,
            gates,
            input_domains
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum ArithGateKind {
    Add,
    Mul(u64),
    Proj(u64, fn(u64) -> u64),

    // Special cases of the projection gate
    Map(u64),
    Less(u64),
}

#[derive(Debug)]
pub(crate) struct ArithGate {
    pub output: usize,
    pub domain: u64,
    pub inputs: Vec<usize>,
    pub kind: ArithGateKind,
}

const GATE_ADD:  u8 = 0x00;
const GATE_MUL:  u8 = 0x01;
const GATE_MAP:  u8 = 0x02;
const GATE_LESS: u8 = 0x03;

impl ArithGate {
    fn serialize(&self, file: &mut File) {
        write_u64(self.output as u64, file);
        write_u64(self.domain, file);
        // TODO(frm): We could probably do with a u16 or u24!
        write_u64(self.inputs.len() as u64, file);
        for input in &self.inputs {
            write_u64(*input as u64, file);
        }

        match self.kind {
            ArithGateKind::Add => {
                write_u8(GATE_ADD, file);
            },
            ArithGateKind::Mul(c) => {
                write_u8(GATE_ADD, file);
                write_u64(c, file);
            },
            ArithGateKind::Map(range) => {
                write_u8(GATE_MAP, file);
                write_u64(range, file);
            },
            ArithGateKind::Less(threshold) => {
                write_u8(GATE_LESS, file);
                write_u64(threshold, file);
            },

            ArithGateKind::Proj(_, _) => {
                debug_assert!(false, "Cannot serialize gate of this type!");
            }
        };
    }
    fn deserialize(file: &mut File) -> ArithGate {
        let output = read_u64(file) as usize;
        let domain = read_u64(file);

        let input_count = read_u64(file);
        let mut inputs = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            inputs.push(read_u64(file) as usize);
        }

        let gate_kind = read_u8(file);
        let kind = match gate_kind {
            GATE_ADD  => { ArithGateKind::Add },
            GATE_MUL  => { ArithGateKind::Mul(read_u64(file)) },
            GATE_MAP  => { ArithGateKind::Map(read_u64(file)) },
            GATE_LESS => { ArithGateKind::Less(read_u64(file)) },

            _ => {
                debug_assert!(false, "Unsupported gate kind identifier!");
                ArithGateKind::Add
            }
        };

        ArithGate {
            output,
            domain,
            inputs,
            kind
        }
    }
}
