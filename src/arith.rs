use core::ops;
use itertools::Itertools;
use rand::Rng;
use ring::digest::Context;
use ring::digest::SHA256;
use std::collections::HashMap;
use std::collections::HashSet;
use std::cmp;
use std::error::Error;
use std::fmt;
use std::iter;
use std::mem::{transmute, MaybeUninit};

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

#[derive(Debug, PartialEq)]
pub(crate) enum ArithGateKind {
    ADD,
    MUL(u64),
    PROJ(u64, fn(u64) -> u64),
}

#[derive(Debug)]
pub(crate) struct ArithGate {
    pub kind: ArithGateKind,
    pub inputs: Vec<usize>,
    pub output: usize,
    pub domain: u64,
}

// -------------------------------------------------------------------------------------------------
// Wires

// TODO: Improve internal representation and implement from/into.
#[derive(Debug, Clone)]
pub struct ArithWire {
    lambda: u64,
    domain: u64,
    values: Vec<u64>,
}

impl ops::Add<&ArithWire> for &ArithWire {
    type Output = ArithWire;
    fn add(self, rhs: &ArithWire) -> ArithWire {
        debug_assert_eq!(self.lambda, rhs.lambda, "Lambdas doesn't match.");
        debug_assert_eq!(self.domain, rhs.domain, "Domain not matching");

        let domain = self.domain;
        let lambda = self.lambda;
        let values = self
            .values
            .iter()
            .zip(rhs.values.iter())
            .map(|(a, b)| (a + b) % domain)
            .collect();

        return ArithWire {
            domain,
            values,
            lambda,
        };
    }
}

impl ops::Sub<&ArithWire> for &ArithWire {
    type Output = ArithWire;
    fn sub(self, rhs: &ArithWire) -> Self::Output {
        debug_assert_eq!(self.lambda, rhs.lambda, "Lambdas doesn't match.");
        debug_assert_eq!(self.domain, rhs.domain, "Domain not matching");

        let domain = self.domain;
        let lambda = self.lambda;
        let values = self
            .values
            .iter()
            .zip(rhs.values.iter())
            .map(|(a, b)| (a + (domain - b)) % domain)
            .collect();

        return ArithWire {
            domain,
            values,
            lambda,
        };
    }
}

impl ops::Neg for &ArithWire {
    type Output = ArithWire;
    fn neg(self) -> ArithWire {
        return ArithWire {
            domain: self.domain,
            lambda: self.lambda, // this probably works
            values: self.values.iter().map(|x| self.domain - x).collect(),
        };
    }
}

impl ops::Mul<u64> for &ArithWire {
    type Output = ArithWire;
    #[inline]
    fn mul(self, rhs: u64) -> ArithWire {
        let domain = self.domain;
        let lambda = self.lambda;
        let values = self.values.iter().map(|x| (x * rhs) % domain).collect();
        return ArithWire {
            domain,
            values,
            lambda,
        };
    }
}

impl iter::Sum for ArithWire {
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let init = iter.next().unwrap();
        iter.fold(init, |acc: ArithWire, w: ArithWire| &acc + &w)
    }
}

impl ArithWire {
    fn empty() -> ArithWire {
        return ArithWire {
            domain: 0,
            lambda: 0,
            values: Vec::new()
        }
    }

    fn new(domain: u64, lambda: u64) -> ArithWire {
        let mut values = vec![0u64; lambda as usize];
        for i in 0..lambda {
            values[i as usize] = rng(domain + 1);
        }

        return ArithWire {
            values,
            lambda,
            domain,
        };
    }

    fn delta(domain: u64, lambda: u64) -> ArithWire {
        let mut values = vec![0u64; lambda as usize];
        for i in 0..lambda {
            values[i as usize] =  rng(domain + 1);
        }
        values[(lambda - 1) as usize] = 1;

        return ArithWire {
            values,
            lambda,
            domain,
        };
    }
}

// -------------------------------------------------------------------------------------------------
// PRF/Hash function

fn hash(index: u64, x: u64, wire: &ArithWire) -> u64 {
    let mut context = Context::new(&SHA256);
    context.update(&index.to_be_bytes());
    context.update(&x.to_be_bytes());
    context.update(&wire.lambda.to_be_bytes());
    context.update(&wire.domain.to_be_bytes());
    for value in &wire.values {
        context.update(&value.to_be_bytes());
    }

    let digest = context.finish();
    let bytes = digest.as_ref();

    return u64::from_be_bytes(bytes[..8].try_into().unwrap());
}

fn hash_wire(index: u64, wire: &ArithWire, target: &ArithWire) -> ArithWire {
    let mut context = Context::new(&SHA256);
    context.update(&index.to_be_bytes());
    context.update(&wire.lambda.to_be_bytes());
    context.update(&wire.domain.to_be_bytes());
    for v in &wire.values {
        context.update(&v.to_be_bytes());
    }

    let digest = context.finish();
    let bytes = digest.as_ref();

    // Makes values for the wire of target size from the output of the hash function, recall that
    // the hash function outputs 256 bits, which means that the number of values * the number of
    // bits in a value must be less than or equal to 256.
    let mut values = Vec::with_capacity(target.lambda as usize);
    let bits_per_value = log2(target.domain);
    debug_assert!(bits_per_value * target.lambda <= 256);

    let mut bits_in_byte = 8;
    let mut byte_idx = 0;
    let mut byte = bytes[0];
    for _ in 0..=target.lambda {
        let mut bits_wanted = bits_per_value;
        let mut value: u64 = 0;

        // Grab bits up until the next full byte
        if bits_in_byte != 8 {
            let bits_to_grab = cmp::min(bits_in_byte, bits_wanted);
            bits_wanted -= bits_to_grab;

            let mask_shift = 8 - bits_to_grab;
            let mask = ((0xFF << mask_shift) >> bits_to_grab) as u8;
            let bits = byte & mask;

            if bits_to_grab == bits_in_byte {
                bits_in_byte = 8;
                byte_idx += 1;
                byte = bytes[byte_idx];
            } else {
                bits_in_byte -= bits_to_grab;
            }

            value |= bits as u64;
            if bits_wanted != 0 {
                value <<= cmp::min(8, bits_wanted);
            }
        }

        // Grab as many full bytes as we need
        // From the previous code we know that at this point either we want no more bits or the
        // number of bits in the current byte from the hash will be equal to 8, thus we do not need
        // to update bits_in_byte.
        while bits_wanted >= 8 {
            value |= byte as u64;
            byte_idx += 1;
            byte = bytes[byte_idx];
            bits_wanted -= 8;

            if bits_wanted < 8 {
                value <<= bits_wanted;
                break;
            }

            value <<= 8;
        }

        // Grab any remaining bits
        if bits_wanted != 0 {
            let mask_shift = 8 - bits_wanted;
            let mask = ((0xFF << mask_shift) >> bits_wanted) as u8;
            let bits = (byte & mask) as u8;

            value |= bits as u64;
            bits_in_byte -= bits_wanted;
        }

        values.push(value % target.domain);
    }

    debug_assert_eq!(values.len(), (target.lambda + 1) as usize);
    debug_assert!(values.iter().all(|v| v < &target.domain), "value not under domain");

    return ArithWire {
        domain: target.domain,
        lambda: target.lambda,
        values,
    };
}

// -------------------------------------------------------------------------------------------------
// Helpers / Definitions

fn rng(max: u64) -> u64 {
    rand::thread_rng().gen_range(0..max)
}

#[inline]
fn tau(w : &ArithWire) -> u64 {
    w.values[(w.lambda - 1) as usize]
}

#[inline]
fn log2(x: u64) -> u64 {
    64 - (x.leading_zeros() as u64)
}

pub struct Encoding {
    wires: Vec<ArithWire>,
    delta: HashMap<u64, ArithWire>,
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

pub fn garble(circuit: &ArithCircuit, security: u64) -> (HashMap<usize, Vec<ArithWire>>, Encoding, Vec<Vec<u64>>) {
    // 1. Compute lambda & delta for the domains in the circuit
    let mut lambda = HashMap::new();
    let mut delta = HashMap::new();
    for gate in &circuit.gates {
        if !lambda.contains_key(&gate.domain) {
            let lambda_domain = (security + log2(gate.domain) - 1) / log2(gate.domain);
            lambda.insert(gate.domain, lambda_domain);
            delta.insert(gate.domain, ArithWire::delta(gate.domain, lambda_domain));
        }

        if let ArithGateKind::PROJ(target_domain, _) = gate.kind {
            if !lambda.contains_key(&target_domain) {
                let lambda_domain = (security + log2(target_domain) - 1) / log2(target_domain);
                lambda.insert(target_domain, lambda_domain);
                delta.insert(target_domain, ArithWire::delta(target_domain, lambda_domain));
            }
        }
    }

    // 2. Create wires for each of the inputs
    let mut wires = Vec::with_capacity(circuit.num_wires);
    for input in 0..circuit.num_inputs {
        let domain = circuit.input_domains[input];
        wires.push(ArithWire::new(domain, lambda[&domain]));
    }

    // 3. Create encoding information from the inputs
    // TODO(frm): Can we do this without having to clone delta?
    let encoding = Encoding {
        wires: wires[..circuit.num_inputs].to_vec(),
        delta: delta.clone(),
    };

    // 4. For each gate
    let outputs_start_at = circuit.num_wires - circuit.num_outputs;
    let mut f = HashMap::new();
    let mut d = Vec::with_capacity(circuit.num_outputs);
    for gate in &circuit.gates {
        let wire = match gate.kind {
            ArithGateKind::ADD => gate.inputs.iter().map(|&input| wires[input].clone()).sum(),
            ArithGateKind::MUL(constant) => &wires[gate.inputs[0]] * constant,
            ArithGateKind::PROJ(range, phi) => {
                let input_index = gate.inputs[0];
                let color = tau(&wires[input_index]);
                let output_index = gate.output as u64;

                let delta_m = &delta[&gate.domain];
                let delta_n = &delta[&range];

                let hashed_wire = hash_wire(output_index, &(&wires[input_index] - &(delta_m * color)), &delta_n);
                let wire = &hashed_wire + &(delta_n * phi(gate.domain - color));
                let wire = -&wire;

                let mut g: Vec<ArithWire> = vec![ArithWire::empty(); gate.domain as usize];
                for x in 0..gate.domain {
                    let hashed_wire = hash_wire(output_index, &(&wires[input_index] + &(delta_m * x)), &wire);
                    let ciphertext = &(&hashed_wire + &wire) + &(delta_n * phi(x));

                    g[((x + color) % gate.domain) as usize] = ciphertext;
                }

                f.insert(output_index as usize, g);
                wire
            }
        };
        wires.push(wire);

        // 5. Decoding information for outputs
        if gate.output >= outputs_start_at {
            let output_domain = match gate.kind {
                ArithGateKind::PROJ(range, _) => range,
                _ => gate.domain,
            };

            let mut values = vec![0; output_domain as usize];
            for x in 0..output_domain {
                let hash = hash(gate.output as u64, x as u64, &(&wires[gate.output] + &(&delta[&output_domain] * x)));
                values[x as usize] = hash;
            }

            d.push(values);
        }
    }

    return (f, encoding, d);
}

pub fn evaluate(circuit: &ArithCircuit, f: &HashMap<usize, Vec<ArithWire>>, x: &Vec<ArithWire>) -> Vec<ArithWire> {
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
            ArithGateKind::ADD => gate
                .inputs
                .iter()
                .map(|&x| unsafe { wires[x].assume_init_ref() }.clone())
                .sum::<ArithWire>(),
            ArithGateKind::MUL(c) => unsafe { wires[gate.inputs[0]].assume_init_ref() * c },
            ArithGateKind::PROJ(_, _) => {
                let wire = unsafe { wires[gate.inputs[0]].assume_init_ref() };
                let color = tau(wire);
                let cipher = &f[&gate.output][color as usize];
                let hw = hash_wire(gate.output as u64, wire, cipher);
                cipher - &hw
            }
        };
        wires[gate.output].write(wire);
    }

    let wires: Vec<ArithWire> = unsafe { transmute(wires) };
    return wires[(circuit.num_wires - circuit.num_outputs)..circuit.num_wires].to_vec();
}

pub fn encode(e: &Encoding, x: &Vec<u64>) -> Vec<ArithWire> {
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

    return z;
}

pub fn decode(num_wires: usize, decoding: &Vec<Vec<u64>>, z: &Vec<ArithWire>) -> Result<Vec<u64>, DecodeError> {
    let mut y = vec![0; decoding.len()];
    for i in 0..z.len() {
        let output = num_wires - z.len() + i;
        let hashes = &decoding[i];

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

    return Ok(y);
}

// -------------------------------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use crate::arith::{decode, encode, evaluate, garble, hash, Encoding, ArithWire};
    use std::collections::HashMap;
    use super::{ArithCircuit, ArithGate, ArithGateKind};

    fn garble_encode_eval_decode(c: &ArithCircuit, x: &Vec<u64>) -> Vec<u64> {
        const SECURITY: u64 = 128;
        let (f, e, d) = garble(&c, SECURITY);
        let x = encode(&e, x);
        let z = evaluate(c, &f, &x);
        return decode(c.num_wires, &d, &z).unwrap();
    }

    #[test]
    fn sum_circuit() {
        let domain = 128;
        let circuit = ArithCircuit {
            gates: vec![ArithGate {
                kind: ArithGateKind::ADD,
                inputs: vec![0, 1],
                output: 2,
                domain: domain,
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
                kind: ArithGateKind::ADD,
                inputs: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                output: 10,
                domain: domain,
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
                kind: ArithGateKind::MUL(9),
                inputs: vec![0],
                output: 1,
                domain: domain,
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
        let phi = |x : u64| x;
        let circuit = ArithCircuit {
            gates: vec![ArithGate {
                kind: ArithGateKind::PROJ(target_domain, phi),
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
                kind: ArithGateKind::PROJ(target_domain, phi),
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
                kind: ArithGateKind::PROJ(target_domain, phi),
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

        let id = |x| x;
        let threshold = |x| (x < 2) as u64;

        let circuit = ArithCircuit {
            // Comparison
            gates: vec![ArithGate {
                kind: ArithGateKind::ADD,
                inputs: vec![0, 4],
                output: 8,
                domain: BIT_DOMAIN,
            }, ArithGate {
                kind: ArithGateKind::ADD,
                inputs: vec![1, 5],
                output: 9,
                domain: BIT_DOMAIN,
            }, ArithGate {
                kind: ArithGateKind::ADD,
                inputs: vec![2, 6],
                output: 10,
                domain: BIT_DOMAIN,
            }, ArithGate {
                kind: ArithGateKind::ADD,
                inputs: vec![3, 7],
                output: 11,
                domain: BIT_DOMAIN,
            },
                        // Second half of comparison
            ArithGate {
                kind: ArithGateKind::PROJ(COMAPRISON_DOMAIN, id),
                inputs: vec![8],
                output: 12,
                domain: BIT_DOMAIN,
            },
                        ArithGate {
                kind: ArithGateKind::PROJ(COMAPRISON_DOMAIN, id),
                inputs: vec![9],
                output: 13,
                domain: BIT_DOMAIN,
            },
                        ArithGate {
                kind: ArithGateKind::PROJ(COMAPRISON_DOMAIN, id),
                inputs: vec![10],
                output: 14,
                domain: BIT_DOMAIN,
            },
                        ArithGate {
                kind: ArithGateKind::PROJ(COMAPRISON_DOMAIN, id),
                inputs: vec![11],
                output: 15,
                domain: BIT_DOMAIN,
            },
                        // Adder
            ArithGate {
                kind: ArithGateKind::ADD,
                inputs: vec![12, 13, 14, 15],
                output: 16,
                domain: COMAPRISON_DOMAIN,
            },
                        // Threshold
            ArithGate {
                kind: ArithGateKind::PROJ(BIT_DOMAIN, threshold),
                inputs: vec![16],
                output: 17,
                domain: COMAPRISON_DOMAIN,
            },
            ],
            num_inputs: INPUT_COUNT,
            num_outputs: 1,
            num_wires: 18,
            input_domains: vec![BIT_DOMAIN; INPUT_COUNT],
        };

        return circuit;
    }

    #[test]
    fn threshold_gate_zero() {
        let circuit = make_me_the_threshold();
        let input = vec![0, 1, 0, 1,  // Alice bits
                         0, 1, 0, 1]; // Bob bits

        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], 1);
    }

    #[test]
    fn threshold_gate_less() {
        let circuit = make_me_the_threshold();
        let input = vec![0, 1, 0, 1,  // Alice bits
                         1, 1, 0, 1]; // Bob bits

        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], 1);
    }

    #[test]
    fn threshold_gate_equal() {
        let circuit = make_me_the_threshold();
        let input = vec![1, 1, 0, 1,  // Alice bits
                         0, 0, 0, 1]; // Bob bits

        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], 0);
    }

    #[test]
    fn threshold_gate_above() {
        let circuit = make_me_the_threshold();
        let input = vec![1, 0, 1, 0,  // Alice bits
                         0, 1, 0, 1]; // Bob bits

        let output = garble_encode_eval_decode(&circuit, &input);
        assert_eq!(output[0], 0);
    }
}
