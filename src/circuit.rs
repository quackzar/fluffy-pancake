use std::{collections::HashSet, error::Error, fmt};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
// Tools for building circuits.

/// A `Circuit` is a collection of gates, with a set of inputs and outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct Gate {
    pub output: usize,
    pub domain: u16,
    pub inputs: Vec<usize>,
    pub kind: GateKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum GateKind {
    Add,
    Mul(u16),
    Proj(ProjKind),
    // Half Gates
    And,
    // TODO: Add And, Or, Xor, Not, Eq.
}

impl Gate {
    pub const fn output_domain(&self) -> u16 {
        match self.kind {
            GateKind::Add | GateKind::Mul(_) => self.domain,
            GateKind::Proj(proj) => match proj {
                ProjKind::Map(range) => range,
                ProjKind::Less(_) => 2,
            },
            GateKind::And => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ProjKind {
    Map(u16),
    Less(u16),
}

impl ProjKind {
    #[inline]
    pub const fn project(&self, x: u16) -> u16 {
        use ProjKind::*;
        match *self {
            Map(m) => x % m,
            Less(t) => (x < t) as u16,
        }
    }

    #[inline]
    pub const fn domain(&self) -> u16 {
        use ProjKind::*;
        match *self {
            Map(m) => m,
            Less(_) => 2,
        }
    }
}

pub struct CircuitBuilder {
    gates: Vec<Gate>,
    next_wire: usize,
    num_inputs: usize,
    unread_wires: HashSet<usize>,
}

impl CircuitBuilder {
    pub fn new(num_inputs: usize) -> Self {
        Self {
            gates: Vec::new(),
            next_wire: 0,
            num_inputs,
            unread_wires: HashSet::new(),
        }
    }

    /// Offset circuit wires by `amount`.
    ///
    /// * `amount`: The amount to offset the circuit by.
    pub fn offset(mut self, amount: usize) -> Self {
        self.gates.iter_mut().for_each(|g| {
            g.output += amount;
            g.inputs.iter_mut().for_each(|i| {
                *i += amount;
            });
        });
        self.unread_wires = self.unread_wires.iter().map(|x| x + amount).collect();
        self.next_wire += amount;
        self
    }

    /// Add a new gate to the circuit.
    ///
    /// * `gate`: The gate to add.
    pub fn add_gate(mut self, gate: Gate) -> Self {
        self.next_wire = gate.output;
        self.unread_wires.insert(gate.output);
        gate.inputs.iter().for_each(|i| {
            self.unread_wires.remove(i);
        });
        self.gates.push(gate);
        self
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
            .iter() // all the gates that are input gates.
            .filter(|g| g.inputs.iter().any(|&i| i < self.num_inputs))
            .flat_map(|g| g.inputs.iter().map(|_| g.domain))
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
        // assert_eq!(inputs.len(), self.num_inputs);
        let mut wires = vec![0; self.num_wires];
        for (i, input) in inputs.iter().enumerate() {
            wires[i] = *input;
        }
        for gate in &self.gates {
            let inputs = gate.inputs.iter().map(|&i| wires[i]);
            let output: u16 = match gate.kind {
                GateKind::Add => inputs.sum::<u16>() % gate.domain,
                GateKind::Mul(m) => inputs.map(|x| x * m).next().unwrap(),
                GateKind::Proj(ref p) => inputs.map(|x| p.project(x)).next().unwrap(),
                GateKind::And => inputs.map(|x| x & 1).next().unwrap(),
            };
            wires[gate.output] = output;
        }
        wires
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

pub fn verify_circuit(circuit: &Circuit) -> Result<(), CircuitError> {
    // assert!(circuit.input_domains.len() == circuit.num_inputs, "Input domain amount, doesn't match amount of inputs");
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
