use itertools::Itertools;

use crate::circuit::*;
use crate::garble::*;
use crate::util::*;

// TODO: fPAKE protocol

pub fn build_circuit(bitsize: usize, threshold: u16) -> Circuit {
    let mut gates: Vec<Gate> = Vec::new();
    let comparison_domain = bitsize as u16 / 2 + 1;
    let bitdomain = 2;

    // xor gates
    for i in 0..bitsize {
        let gate = Gate {
            inputs: vec![i, i + bitsize],
            output: i + 2 * bitsize,
            kind: GateKind::Add,
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // proj gates
    for i in 0..bitsize {
        let gate = Gate {
            inputs: vec![i + 2 * bitsize],
            output: i + 3 * bitsize,
            kind: GateKind::Proj(ProjKind::Map(comparison_domain)),
            domain: bitdomain,
        };
        gates.push(gate);
    }

    // sum
    let gate = Gate {
        kind: GateKind::Add,
        inputs: (3 * bitsize..4 * bitsize).collect(),
        output: 4 * bitsize,
        domain: bitsize as u16,
    };
    gates.push(gate);

    // comparison
    let gate = Gate {
        kind: GateKind::Proj(ProjKind::Less(threshold)),
        inputs: vec![4 * bitsize],
        output: 4 * bitsize + 1,
        domain: comparison_domain,
    };
    gates.push(gate);
    Circuit {
        gates,
        num_inputs: bitsize * 2,
        num_outputs: 1,
        num_wires: 4 * bitsize + 2,
        input_domains: vec![bitdomain; bitsize * 2],
    }
}

// TODO: Handle OT for encoding.

#[cfg(test)]
mod tests {
    use super::*;

    fn garble_encode_eval_decode(c: &Circuit, x: &Vec<u16>) -> Vec<u16> {
        let (f, e, d) = garble(c);
        let x = encode(&e, x);
        let z = evaluate(c, &f, x);
        decode(&d, z).unwrap()
    }

    #[test]
    fn simple_test() {
        let circuit = build_circuit(16, 2);
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
        let pwsd_a = vec![1, 1, 1, 1];
        let pwsd_b = vec![1, 1, 1, 0];

        // Alice's garbled circuit and Bob's eval
        let (out_b, one_a) = {
            // Round 1
            let circuit = build_circuit(4, 2);
            let (f, e, d) = garble(&circuit);
            let mut input = Vec::new();
            input.extend(&pwsd_a); // Provided by OT
            input.extend(&pwsd_b);
            let garbled_input = encode(&e, &input);
            let out = evaluate(&circuit, &f, garbled_input)[0].clone();
            (
                hash!(
                    (circuit.num_wires - 1).to_be_bytes(),
                    1u16.to_be_bytes(),
                    &out
                ),
                d.hashes[0][1],
            )
        };

        // Bob's garbled circuit and Alice's eval
        let (out_a, one_b) = {
            // Round 2
            let circuit = build_circuit(4, 2);
            let (f, e, d) = garble(&circuit);
            let mut input = Vec::new();
            input.extend(&pwsd_a); // Provided by OT
            input.extend(&pwsd_b);
            let garbled_input = encode(&e, &input);
            let out = evaluate(&circuit, &f, garbled_input)[0].clone();
            (
                hash!(
                    (circuit.num_wires - 1).to_be_bytes(),
                    1u16.to_be_bytes(),
                    &out
                ),
                d.hashes[0][1],
            )
        };
        let key_a = xor(out_a, one_a);
        let key_b = xor(out_b, one_b);
        assert_eq!(key_a, key_b)
    }
}
