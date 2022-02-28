use std::{collections::HashSet, error::Error, fmt};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
// Tools for building circuits.

/// A `Circuit` is a collection of gates, with a set of inputs and outputs.
#[derive(Debug, Serialize, Deserialize)]
pub struct Circuit {
    // TODO: Const Generics?
    pub num_wires: usize,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub(crate) gates: Vec<Gate>,
    pub input_domains: Vec<u16>,
}

/// A `Gate` is a single operation on a set of wires, which output to a single wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Gate {
    pub output: usize,
    pub domain: u16,
    pub inputs: Vec<usize>,
    pub kind: GateKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub(crate) enum GateKind {
    Add,
    Mul(u16),
    Proj(ProjKind),
    // TODO: Add And, Or, Xor, Not, Eq.
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub(crate) enum ProjKind {
    Map(u16),
    Less(u16),
}

impl ProjKind {
    #[inline]
    pub fn project(&self, x: u16) -> u16 {
        use ProjKind::*;
        match *self {
            Map(m) => x % m,
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

struct CircuitBuilder {
    gates : Vec<Gate>,
    next_wire: usize,
    num_inputs: usize,
    unread_wires: HashSet<usize>,
}

impl CircuitBuilder {
    pub fn new(num_inputs : usize) -> Self {
        CircuitBuilder {
            gates: Vec::new(),
            next_wire: 0,
            num_inputs,
            unread_wires: HashSet::new(),
        }
    }

    /// Offset circuit wires by `amount`.
    ///
    /// * `amount`: The amount to offset the circuit by.
    pub fn offset(&mut self, amount : usize) {
        self.gates.iter_mut().for_each(|g| {
            g.output += amount;
            g.inputs.iter_mut().for_each(|i| {
                *i += amount;
            });
        });
        self.unread_wires = self.unread_wires.iter().map(|x| x+amount).collect();
        self.next_wire += amount;
    }


    /// Add a new gate to the circuit.
    ///
    /// * `gate`: The gate to add.
    pub fn add_gate(&mut self, gate: Gate) {
        self.next_wire = gate.output;
        self.unread_wires.insert(gate.output);
        gate.inputs.iter().for_each(|i| {self.unread_wires.remove(i);} );
        self.gates.push(gate);
    }


    /// Append a circuit to the current circuit.
    /// The circuit will NOT be offset by the current circuit.
    ///
    /// * `circuit`: 
    pub fn append(&mut self, circuit: &Circuit) {
        for gate in &circuit.gates {
            self.add_gate(gate.clone());
        }
    }

    // TODO: Topological sorting.

    pub fn build(self) -> Circuit {
        let num_wires = self
            .gates
            .iter()
            .flat_map(|g| &g.inputs)
            .chain(self.gates.iter().map(|g| &g.output))
            .unique()
            .count();

        let num_outputs = self.unread_wires.len();

        let input_domains = self
            .gates
            .iter()
            .filter(|g| g.inputs.iter().any(|&i| i < self.num_inputs))
            .map(|g| g.domain)
            .collect();

        Circuit {
            num_wires,
            num_outputs,
            num_inputs: self.num_inputs,
            gates: self.gates,
            input_domains,
        }
    }
}


impl Circuit {
    pub fn eval(&self, inputs: &[u16]) -> Vec<u16> {
        assert_eq!(inputs.len(), self.num_inputs);
        let mut wires = vec![0; self.num_wires];
        for (i, input) in inputs.iter().enumerate() {
            wires[i] = *input;
        }
        for gate in &self.gates {
            let inputs = gate
                .inputs
                .iter()
                .map(|&i| wires[i]);
            let output : u16 = match gate.kind {
                GateKind::Add => inputs.sum(),
                GateKind::Mul(m) => inputs.map(|x| x * m).next().unwrap(),
                GateKind::Proj(ref p) => inputs.map(|x| p.project(x)).next().unwrap(),
            };
            wires[gate.output] = output;
        }
        wires
    }

    pub fn append(&self, other: &Circuit) -> Circuit {
        let mut builder = CircuitBuilder::new(self.num_inputs);
        for gate in &self.gates {
            builder.add_gate(gate.clone());
        }
        let offset = builder.next_wire;
        for gate in &other.gates {
            let inputs = gate
                .inputs
                .iter()
                .map(|&i| i + offset)
                .collect();
            builder.add_gate(Gate {
                inputs,
                output: gate.output + offset,
                domain: gate.domain,
                kind: gate.kind,
            });
        }
        builder.build()
    }
}


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
    let ok = circuit
        .gates
        .iter()
        .map(|g| g.output)
        .all(move |i| uniq.insert(i));
    if !ok {
        return Err(CircuitError::BadOutputCount);
    }
    Ok(())
}
