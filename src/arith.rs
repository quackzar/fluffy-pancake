use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::mem::{transmute, MaybeUninit};
use std::fs::File;

use crate::wires::ArithWire;
use crate::wires::hash;
use crate::wires::hash_wire;

use crate::util::*;
// -------------------------------------------------------------------------------------------------
// Circuit Definition


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


// -------------------------------------------------------------------------------------------------
// PRF/Hash function


// -------------------------------------------------------------------------------------------------
// Helpers / Definitions



pub struct EncodingKey {
    wires: Vec<ArithWire>,
    delta: HashMap<u64, ArithWire>,
}

pub struct DecodingKey {
    pub(crate) hashes: Vec<Vec<u64>>,
    pub(crate) offset: usize,
}

#[derive(Debug)]
pub struct DecodeError {}

impl Error for DecodeError {}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error decoding result")
    }
}

// -------------------------------------------------------------------------------------------------
// Garbling Scheme Implementations

type ProjMap = HashMap<usize, Vec<ArithWire>>;

fn projection_identity(value: u64) -> u64 { value }
fn projection_less(value: u64, threshold: u64) -> u64 { (value < threshold) as u64 }

pub fn garble(circuit: &ArithCircuit, security: u64) -> (ProjMap, EncodingKey, DecodingKey) {
    // 1. Compute lambda & delta for the domains in the circuit
    let mut lambda = HashMap::new();
    let mut delta = HashMap::new();
    for gate in &circuit.gates {
        if let std::collections::hash_map::Entry::Vacant(e) = lambda.entry(gate.domain) {
            let lambda_domain = (security + log2(gate.domain) - 1) / log2(gate.domain);
            e.insert(lambda_domain);
            delta.insert(gate.domain, ArithWire::delta(gate.domain, lambda_domain));
        }

        match gate.kind {
            ArithGateKind::Map(target_domain) |
            ArithGateKind::Proj(target_domain, _) => {
                if let std::collections::hash_map::Entry::Vacant(e) = lambda.entry(target_domain) {
                    let lambda_domain = (security + log2(target_domain) - 1) / log2(target_domain);
                    e.insert(lambda_domain);
                    delta.insert(target_domain, ArithWire::delta(target_domain, lambda_domain));
                }
            },
            ArithGateKind::Less(_) => {
                let target_domain = 2;
                if let std::collections::hash_map::Entry::Vacant(e) = lambda.entry(target_domain) {
                    let lambda_domain = (security + log2(target_domain) - 1) / log2(target_domain);
                    e.insert(lambda_domain);
                    delta.insert(target_domain, ArithWire::delta(target_domain, lambda_domain));
                }
            },
            _ =>  {}
        }
    }

    // 2. Create wires for each of the inputs
    let mut wires = Vec::with_capacity(circuit.num_wires);
    for input in 0..circuit.num_inputs {
        let domain = circuit.input_domains[input];
        wires.push(ArithWire::new(domain, lambda[&domain]));
    }

    // 3. Encoding information
    let encode_key = EncodingKey {
        wires: wires[..circuit.num_inputs].to_vec(),
        delta: delta.clone(),
    };

    // 4. For each gate
    let outputs_start_at = circuit.num_wires - circuit.num_outputs;
    let mut f = HashMap::new();
    let mut d = Vec::with_capacity(circuit.num_outputs);
    for gate in &circuit.gates {
        let wire = match gate.kind {
            ArithGateKind::Add => gate.inputs.iter().map(|&input| wires[input].clone()).sum(),
            ArithGateKind::Mul(constant) => &wires[gate.inputs[0]] * constant,
            ArithGateKind::Proj(range, phi) => {
                let input_index = gate.inputs[0];
                let color = &wires[input_index].tau();

                let delta_m = &delta[&gate.domain];
                let delta_n = &delta[&range];

                let hashed_wire = hash_wire(gate.output, &(&wires[input_index] - &(delta_m * *color)), delta_n);
                let wire = &hashed_wire + &(delta_n * phi(gate.domain - color));
                let wire = -&wire;

                let mut g: Vec<ArithWire> = vec![ArithWire::empty(); gate.domain as usize];
                for x in 0..gate.domain {
                    let hashed_wire = hash_wire(gate.output, &(&wires[input_index] + &(delta_m * x)), &wire);
                    let ciphertext = &(&hashed_wire + &wire) + &(delta_n * phi(x));

                    g[((x + color) % gate.domain) as usize] = ciphertext;
                }

                f.insert(gate.output, g);
                wire
            },

            // Special cases of projection
            ArithGateKind::Map(range) => {
                let input_index = gate.inputs[0];
                let color = &wires[input_index].tau();

                let delta_m = &delta[&gate.domain];
                let delta_n = &delta[&range];

                let hashed_wire = hash_wire(gate.output, &(&wires[input_index] - &(delta_m * *color)), delta_n);
                let wire = &hashed_wire + &(delta_n * projection_identity(gate.domain - color));
                let wire = -&wire;

                let mut g: Vec<ArithWire> = vec![ArithWire::empty(); gate.domain as usize];
                for x in 0..gate.domain {
                    let hashed_wire = hash_wire(gate.output, &(&wires[input_index] + &(delta_m * x)), &wire);
                    let ciphertext = &(&hashed_wire + &wire) + &(delta_n * projection_identity(x));

                    g[((x + color) % gate.domain) as usize] = ciphertext;
                }

                f.insert(gate.output, g);
                wire
            },
            ArithGateKind::Less(threshold) => {
                let input_index = gate.inputs[0];
                let color = &wires[input_index].tau();

                let range = 2;
                let delta_m = &delta[&gate.domain];
                let delta_n = &delta[&range];

                let hashed_wire = hash_wire(gate.output, &(&wires[input_index] - &(delta_m * *color)), delta_n);
                let wire = &hashed_wire + &(delta_n * projection_less(gate.domain - color, threshold));
                let wire = -&wire;

                let mut g: Vec<ArithWire> = vec![ArithWire::empty(); gate.domain as usize];
                for x in 0..gate.domain {
                    let hashed_wire = hash_wire(gate.output, &(&wires[input_index] + &(delta_m * x)), &wire);
                    let ciphertext = &(&hashed_wire + &wire) + &(delta_n * projection_less(x, threshold));

                    g[((x + color) % gate.domain) as usize] = ciphertext;
                }

                f.insert(gate.output, g);
                wire
            },
        };
        wires.push(wire);

        // 5. Decoding information for outputs
        if gate.output >= outputs_start_at {
            let output_domain = match gate.kind {
                ArithGateKind::Add | ArithGateKind::Mul(_) => gate.domain,
                ArithGateKind::Proj(range, _) => range,
                ArithGateKind::Map(range) => range,
                ArithGateKind::Less(_) => 2,
            };

            let mut values = vec![0; output_domain as usize];
            for x in 0..output_domain {
                let hash = hash(gate.output as u64, x as u64, &(&wires[gate.output] + &(&delta[&output_domain] * x)));
                values[x as usize] = hash;
            }

            d.push(values);
        }
    }

    let decode_key = DecodingKey {
        hashes: d,
        offset: outputs_start_at,
    };

    (f, encode_key, decode_key)
}

pub fn evaluate(circuit: &ArithCircuit, f: &ProjMap, x: Vec<ArithWire>) -> Vec<ArithWire> {
    debug_assert_eq!(x.len(), circuit.num_inputs, "input length mismatch");

    let mut wires: Vec<MaybeUninit<ArithWire>> = Vec::with_capacity(circuit.num_wires);
    unsafe {
        wires.set_len(circuit.num_wires);
    }
    for i in 0..circuit.num_inputs {
        wires[i].write(x[i].clone());
    }

    for gate in &circuit.gates {
        let wire: ArithWire = match gate.kind {
            ArithGateKind::Add => gate
                .inputs
                .iter()
                .map(|&x| unsafe { wires[x].assume_init_ref() }.clone())
                .sum::<ArithWire>(),
            ArithGateKind::Mul(c) => unsafe { wires[gate.inputs[0]].assume_init_ref() * c },
            ArithGateKind::Map(_) |
            ArithGateKind::Less(_) |
            ArithGateKind::Proj(_, _) => {
                let wire = unsafe { wires[gate.inputs[0]].assume_init_ref() };
                let color = wire.tau();
                let cipher = &f[&gate.output][color as usize];
                let hw = hash_wire(gate.output, wire, cipher);
                cipher - &hw
            }
        };
        wires[gate.output].write(wire);
    }

    let wires: Vec<ArithWire> = unsafe { transmute(wires) };
    wires[(circuit.num_wires - circuit.num_outputs)..circuit.num_wires].to_vec()
}


pub fn encode(e: &EncodingKey, x: &Vec<u64>) -> Vec<ArithWire> {
    let wires = &e.wires;
    let delta = &e.delta;
    debug_assert_eq!(
        wires.len(),
        x.len(),
        "Wire and input vector lengths do not match"
    );

    let mut z = Vec::with_capacity(wires.len());
    for (wire, &x) in wires.iter().zip(x) {
        z.push(wire + &(&delta[&wire.domain] * x));
    }

    z
}


pub fn decode(d: &DecodingKey, z: Vec<ArithWire>) -> Result<Vec<u64>, DecodeError> {
    let mut y = vec![0; d.hashes.len()];
    for i in 0..z.len() {
        let output = d.offset + i;
        let hashes = &d.hashes[i];

        let mut success = false;
        for k in 0..z[i].domain {
            let hash = hash(output as u64, k, &z[i]);
            if hash == hashes[k as usize] {
                y[i as usize] = k;
                success = true;
                break;
            }
        }

        if !success {
            return Err(DecodeError {});
        }
    }

    Ok(y)
}

// -------------------------------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn garble_encode_eval_decode(c: &ArithCircuit, x: &Vec<u64>) -> Vec<u64> {
        const SECURITY: u64 = 128;
        let (f, e, d) = garble(c, SECURITY);
        let x = encode(&e, x);
        let z = evaluate(c, &f, x);
        decode(&d, z).unwrap()
    }

    #[test]
    fn sum_circuit() {
        let domain = 128;
        let circuit = ArithCircuit {
            gates: vec![ArithGate {
                kind: ArithGateKind::Add,
                inputs: vec![0, 1],
                output: 2,
                domain,
            }],
            num_inputs: 2,
            num_outputs: 1,
            num_wires: 3,
            input_domains: vec![domain, domain],
        };
        let inputs = vec![33, 66];
        let outputs = garble_encode_eval_decode(&circuit, &inputs);
        assert_eq!(outputs[0], 99);
    }

    #[test]
    fn sum_multiple_circuit() {
        let domain = 128;
        let circuit = ArithCircuit {
            gates: vec![ArithGate {
                kind: ArithGateKind::Add,
                inputs: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                output: 10,
                domain,
            }],
            num_inputs: 10,
            num_outputs: 1,
            num_wires: 11,
            input_domains: vec![domain; 10],
        };
        let inputs = vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let outputs = garble_encode_eval_decode(&circuit, &inputs);
        assert_eq!(outputs[0], 10, "Wrong result");
    }

    #[test]
    fn mult_circuit() {
        let domain = 600;
        let circuit = ArithCircuit {
            gates: vec![ArithGate {
                kind: ArithGateKind::Mul(9),
                inputs: vec![0],
                output: 1,
                domain,
            }],
            num_inputs: 1,
            num_outputs: 1,
            num_wires: 2,
            input_domains: vec![domain, domain],
        };
        let inputs = vec![57];
        let outputs = garble_encode_eval_decode(&circuit, &inputs);
        assert_eq!(outputs[0], 9 * 57);
    }

    #[test]
    fn proj_circuit_identity() {
        let target_domain = 8;
        let source_domain = 16;
        let circuit = ArithCircuit {
            gates: vec![ArithGate {
                kind: ArithGateKind::Map(target_domain),
                inputs: vec![0],
                output: 1,
                domain: source_domain,
            }],
            num_inputs: 1,
            num_outputs: 1,
            num_wires: 2,
            input_domains: vec![source_domain],
        };
        let input = vec![7];
        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], input[0]);
    }

    #[test]
    fn proj_circuit_shl() {
        let target_domain = 64;
        let source_domain = 64;
        let phi = |x| (x * 2);
        let circuit = ArithCircuit {
            gates: vec![ArithGate {
                kind: ArithGateKind::Proj(target_domain, phi),
                inputs: vec![0],
                output: 1,
                domain: source_domain,
            }],
            num_inputs: 1,
            num_outputs: 1,
            num_wires: 2,
            input_domains: vec![source_domain],
        };
        let input = vec![7];
        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], phi(input[0]));
    }

    #[test]
    fn proj_circuit_shr() {
        let target_domain = 64;
        let source_domain = 64;
        let phi = |x| (x / 2);
        let circuit = ArithCircuit {
            gates: vec![ArithGate {
                kind: ArithGateKind::Proj(target_domain, phi),
                inputs: vec![0],
                output: 1,
                domain: source_domain,
            }],
            num_inputs: 1,
            num_outputs: 1,
            num_wires: 2,
            input_domains: vec![source_domain],
        };
        let input = vec![7];
        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], phi(input[0]));
    }

    fn make_me_the_threshold() -> ArithCircuit {
        // 8 inputs, 4 "comparators"
        const INPUT_COUNT: usize = 8;
        const BIT_DOMAIN: u64 = 2;
        const COMAPRISON_DOMAIN: u64 = 8;

        let threshold = 2;
        ArithCircuit {
            // Comparison
            gates: vec![
                ArithGate {
                    kind: ArithGateKind::Add,
                    inputs: vec![0, 4],
                    output: 8,
                    domain: BIT_DOMAIN,
                },
                ArithGate {
                    kind: ArithGateKind::Add,
                    inputs: vec![1, 5],
                    output: 9,
                    domain: BIT_DOMAIN,
                },
                ArithGate {
                    kind: ArithGateKind::Add,
                    inputs: vec![2, 6],
                    output: 10,
                    domain: BIT_DOMAIN,
                },
                ArithGate {
                    kind: ArithGateKind::Add,
                    inputs: vec![3, 7],
                    output: 11,
                    domain: BIT_DOMAIN,
                },
                // Second half of comparison
                ArithGate {
                    kind: ArithGateKind::Map(COMAPRISON_DOMAIN),
                    inputs: vec![8],
                    output: 12,
                    domain: BIT_DOMAIN,
                },
                ArithGate {
                    kind: ArithGateKind::Map(COMAPRISON_DOMAIN),
                    inputs: vec![9],
                    output: 13,
                    domain: BIT_DOMAIN,
                },
                ArithGate {
                    kind: ArithGateKind::Map(COMAPRISON_DOMAIN),
                    inputs: vec![10],
                    output: 14,
                    domain: BIT_DOMAIN,
                },
                ArithGate {
                    kind: ArithGateKind::Map(COMAPRISON_DOMAIN),
                    inputs: vec![11],
                    output: 15,
                    domain: BIT_DOMAIN,
                },
                // Adder
                ArithGate {
                    kind: ArithGateKind::Add,
                    inputs: vec![12, 13, 14, 15],
                    output: 16,
                    domain: COMAPRISON_DOMAIN,
                },
                // Threshold
                ArithGate {
                    kind: ArithGateKind::Less(threshold),
                    inputs: vec![16],
                    output: 17,
                    domain: COMAPRISON_DOMAIN,
                },
            ],
            num_inputs: INPUT_COUNT,
            num_outputs: 1,
            num_wires: 18,
            input_domains: vec![BIT_DOMAIN; INPUT_COUNT],
        }
    }

    #[test]
    fn threshold_gate_zero() {
        let circuit = make_me_the_threshold();
        let input = vec![
            0, 1, 0, 1, // Alice bits
            0, 1, 0, 1,
        ]; // Bob bits

        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], 1);
    }

    #[test]
    fn threshold_gate_less() {
        let circuit = make_me_the_threshold();
        let input = vec![
            0, 1, 0, 1, // Alice bits
            1, 1, 0, 1,
        ]; // Bob bits

        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], 1);
    }

    #[test]
    fn threshold_gate_equal() {
        let circuit = make_me_the_threshold();
        let input = vec![
            1, 1, 0, 1, // Alice bits
            0, 0, 0, 1,
        ]; // Bob bits

        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], 0);
    }

    #[test]
    fn threshold_gate_above() {
        let circuit = make_me_the_threshold();
        let input = vec![
            1, 0, 1, 0, // Alice bits
            0, 1, 0, 1,
        ]; // Bob bits

        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], 0);
    }
}
