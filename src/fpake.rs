use itertools::Itertools;

use crate::arith::*;

pub fn build_circuit(bitsize: usize, _threshold: u64) -> ArithCircuit {
    let mut gates: Vec<ArithGate> = Vec::new();
    let bitdomain = 2;
    let comparison_domain = bitsize as u64 / 2 + 1;

    // xor gates
    for i in 0..bitsize {
        let gate = ArithGate {
            inputs: vec![i, i + bitsize],
            output: i + 2 * bitsize,
            kind: ArithGateKind::Add,
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // proj gates
    let identity = |x: u64| x;
    for i in 0..bitsize {
        let gate = ArithGate {
            inputs: vec![i + 2 * bitsize],
            output: i + 3 * bitsize,
            kind: ArithGateKind::Proj(comparison_domain, identity),
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // sum
    let gate = ArithGate {
        kind: ArithGateKind::Add,
        inputs: (3 * bitsize..4 * bitsize).collect(),
        output: 4 * bitsize,
        domain: bitsize as u64,
    };
    gates.push(gate);

    // comparison
    let threshold = |x: u64| (x < 2) as u64; // TODO: Make threshold dynamic.
    let gate = ArithGate {
        kind: ArithGateKind::Proj(bitdomain, threshold),
        inputs: vec![4 * bitsize],
        output: 4 * bitsize + 1,
        domain: comparison_domain,
    };
    gates.push(gate);
    ArithCircuit {
        gates,
        num_inputs: bitsize * 2,
        num_outputs: 1,
        num_wires: 4 * bitsize + 2,
        input_domains: vec![bitdomain; bitsize * 2],
    }
}

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

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

fn verify_circuit(circuit: &ArithCircuit) -> Result<(), CircuitError> {
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

#[cfg(test)]
mod tests {
    use crate::{arith::*, fpake::build_circuit};

    fn garble_encode_eval_decode(c: &ArithCircuit, x: &Vec<u64>) -> Vec<u64> {
        const SECURITY: u64 = 128;
        let (f, e, d) = garble(c, SECURITY);
        let x = encode(&e, x);
        let z = evaluate(c, &f, x);
        decode(&d, z).unwrap()
    }

    #[test]
    fn simple_test() {
        let circuit = build_circuit(16, 1);
        println!("{:?}", circuit);
        let x = vec![
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 0,
        ];
        let res = garble_encode_eval_decode(&circuit, &x);
        assert!(res[0] == 1);
    }

    #[test]
    fn fpake() {
        const SECURITY: u64 = 256;
        let pwsd_a = vec![1, 1, 1, 1];
        let pwsd_b = vec![1, 1, 1, 0];

        // Alice's garbled circuit and Bob's eval
        let (out_b, one_a) = {
            // Round 1
            let circuit = build_circuit(4, 1);
            let (f, e, d) = garble(&circuit, SECURITY);
            let mut input = Vec::new();
            input.extend(&pwsd_a); // Provided by OT
            input.extend(&pwsd_b);
            let garbled_input = encode(&e, &input);
            let out = evaluate(&circuit, &f, garbled_input)[0].clone();
            (hash((circuit.num_wires - 1) as u64, 1, &out), d.hashes[0][1])
        };

        // Bob's garbled circuit and Alice's eval
        let (out_a, one_b) = {
            // Round 2
            let circuit = build_circuit(4, 1);
            let (f, e, d) = garble(&circuit, SECURITY);
            let mut input = Vec::new();
            input.extend(&pwsd_a); // Provided by OT
            input.extend(&pwsd_b);
            let garbled_input = encode(&e, &input);
            let out = evaluate(&circuit, &f, garbled_input)[0].clone();
            (hash((circuit.num_wires - 1) as u64, 1, &out), d.hashes[0][1])

        };
        let key_a = out_a ^ one_a;
        let key_b = out_b ^ one_b;
        assert_eq!(key_a, key_b)
    }
}
