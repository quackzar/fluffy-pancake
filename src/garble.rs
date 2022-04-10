use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::mem::{transmute, MaybeUninit};

use crate::circuit::*;
use crate::util::*;
use crate::wires::hash_wire;
use crate::wires::Wire;
use crate::wires::{hash, Domain};

// -------------------------------------------------------------------------------------------------
// Helpers / Definitions

// TODO: Const generic? force domain to bits?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingKey {
    wires: Vec<Wire>,
    delta: HashMap<u16, Wire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryEncodingKey(pub Vec<Wire>, pub Vec<Wire>);

impl EncodingKey {
    pub fn encode(&self, x: &[u16]) -> Vec<Wire> {
        let wires = &self.wires;
        let delta = &self.delta;
        debug_assert_eq!(
            wires.len(),
            x.len(),
            "Wire and input vector lengths do not match"
        );

        let mut z = Vec::with_capacity(x.len());
        for (wire, &x) in wires.iter().zip(x) {
            z.push(wire + &(&delta[&wire.domain()] * x));
        }

        z
    }
}

impl From<EncodingKey> for BinaryEncodingKey {
    fn from(key: EncodingKey) -> Self {
        assert!(key.wires.iter().all(|w| w.domain() == 2));
        let delta = key.delta[&2].clone();
        let zeros = key.wires;
        let ones: Vec<Wire> = zeros.iter().map(|w| w + &delta).collect();
        let ones = TryInto::try_into(ones).unwrap(); // should never fail
        Self(zeros, ones)
    }
}

impl From<BinaryEncodingKey> for EncodingKey {
    fn from(key: BinaryEncodingKey) -> Self {
        let mut delta = HashMap::new();
        let d = &key.0[0] + &key.1[0];
        delta.insert(2, d);
        let wires = key.0;
        Self { wires, delta }
    }
}

impl BinaryEncodingKey {
    pub fn encode(&self, bits: &[bool]) -> Vec<Wire> {
        assert_eq!(bits.len(), self.0.len());
        let mut wires = Vec::new();
        for (i, bit) in bits.iter().enumerate() {
            let wire = if *bit {
                self.1[i].clone()
            } else {
                self.0[i].clone()
            };
            wires.push(wire);
        }
        wires
    }

    pub fn zipped(&self) -> Vec<[Wire; 2]> {
        let mut wires = Vec::new();
        for i in 0..self.0.len() {
            wires.push([self.0[i].clone(), self.1[i].clone()]);
        }
        wires
    }

    pub fn unzipped(zipped: &[[Wire; 2]]) -> Self {
        let (zero, one) = zipped
            .iter()
            .map(|[w0, w1]| (w0.clone(), w1.clone()))
            .unzip();
        Self(zero, one)
    }
}

#[derive(Debug, Clone)]
pub struct DecodingKey {
    pub(crate) hashes: Vec<Vec<WireBytes>>,
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

impl DecodingKey {
    pub fn decode(&self, z: &[Wire]) -> Result<Vec<u16>, DecodeError> {
        let mut y = Vec::with_capacity(z.len());
        for (i, z) in z.iter().enumerate() {
            let output = self.offset + i;
            let hashes = &self.hashes[i];

            let mut success = false;
            for k in 0..z.domain() {
                let hash = hash(output, k, z);
                if hash == hashes[k as usize] {
                    y.push(k);
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
}

// -------------------------------------------------------------------------------------------------
// Garbling Scheme Implementations

// TODO: Proper struct for serialize/deserialize.
type ProjMap = HashMap<usize, Vec<Wire>>;

pub fn garble(circuit: &Circuit) -> (GarbledCircuit, EncodingKey, DecodingKey) {
    // 1. Compute lambda & delta for the domains in the circuit
    let mut delta = HashMap::new();
    for gate in &circuit.gates {
        delta
            .entry(gate.domain)
            .or_insert_with(|| Wire::delta(gate.domain));

        if let GateKind::Proj(p) = &gate.kind {
            match *p {
                ProjKind::Map(target_domain) => {
                    delta
                        .entry(target_domain)
                        .or_insert_with(|| Wire::delta(target_domain));
                }
                ProjKind::Less(_) => {
                    let target_domain = 2;
                    delta
                        .entry(target_domain)
                        .or_insert_with(|| Wire::delta(target_domain));
                }
            }
        }
    }

    // 2. Create wires for each of the inputs
    let mut wires = Vec::with_capacity(circuit.num_wires);
    for &domain in circuit.input_domains.iter() {
        wires.push(Wire::new(domain));
    }

    // 3. Encoding information
    let encode_key = EncodingKey {
        wires: wires[..circuit.num_inputs].to_vec(),
        delta: delta.clone(),
    };

    // 4. For each gate
    let outputs_start_at = circuit.num_wires - circuit.num_outputs;
    let mut f = HashMap::new();
    let mut f_halfgate = HashMap::new();
    let mut d = Vec::with_capacity(circuit.num_outputs);
    let mut j0: usize = 0;
    let mut j1: usize = 0;
    for gate in &circuit.gates {
        let wire = match &gate.kind {
            GateKind::Add => gate.inputs.iter().map(|&input| wires[input].clone()).sum(),
            GateKind::Mul(constant) => &wires[gate.inputs[0]] * *constant,

            // Special cases of projection
            GateKind::Proj(proj) => {
                let range = proj.domain();
                let input_index = gate.inputs[0];
                let color = wires[input_index].color();

                let delta_m = &delta[&gate.domain];
                let delta_n = &delta[&range];

                let hashed_wire = hash_wire(
                    gate.output,
                    &(&wires[input_index] - &(delta_m * color)),
                    delta_n,
                );

                let wire = &hashed_wire + &(delta_n * proj.project(gate.domain - color));
                let wire = -&wire;

                let mut g: Vec<Wire> = vec![Wire::empty(); gate.domain as usize];
                for x in 0..gate.domain {
                    let hashed_wire =
                        hash_wire(gate.output, &(&wires[input_index] + &(delta_m * x)), &wire);
                    let ciphertext = &(&hashed_wire + &wire) + &(delta_n * proj.project(x));

                    g[((x + color) % gate.domain) as usize] = ciphertext;
                }

                f.insert(gate.output, g);
                wire
            }
            GateKind::And => {
                let delta = &delta[&2];
                let w_a = &wires[gate.inputs[0]];
                let w_b = &wires[gate.inputs[1]];
                let p_a = w_a.color() != 0;
                let p_b = w_b.color() != 0;
                j0 += 1;
                j1 += 1;

                // first half gate
                let t_g = &Wire::from_array(hash!(w_a, j0.to_be_bytes()), Domain::Binary)
                    + &Wire::from_array(hash!(w_a + delta, j0.to_be_bytes()), Domain::Binary);
                let t_g = if p_b { &t_g + delta } else { t_g };

                let w_g = Wire::from_array(hash!(w_a, j0.to_be_bytes()), Domain::Binary);
                let w_g = if p_a { &w_g + &t_g } else { w_g };

                // second half gate
                let t_e = &Wire::from_array(hash!(w_b, j1.to_be_bytes()), Domain::Binary)
                    + &Wire::from_array(hash!(w_b + delta, j1.to_be_bytes()), Domain::Binary);
                let t_e = &t_e + w_a;

                let w_e = Wire::from_array(hash!(w_b, j1.to_be_bytes()), Domain::Binary);
                let w_e = if p_b { &w_e + &(&t_e + w_a) } else { w_e };

                f_halfgate.insert(gate.output, (t_g, t_e));
                &w_g + &w_e
            }
        };
        wires.push(wire);

        // 5. Decoding information for outputs
        if gate.output >= outputs_start_at {
            let output_domain = gate.output_domain();
            let mut values = vec![[0u8; 32]; output_domain as usize];
            for x in 0..output_domain {
                let hash = hash(
                    gate.output,
                    x,
                    &(&wires[gate.output] + &(&delta[&output_domain] * x)),
                );
                values[x as usize] = hash;
            }

            d.push(values);
        }
    }

    let decode_key = DecodingKey {
        hashes: d,
        offset: outputs_start_at,
    };

    let gc = GarbledCircuit {
        circuit: circuit.clone(),
        f,
        f_halfgate,
    };

    (gc, encode_key, decode_key)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GarbledCircuit {
    pub circuit: Circuit,
    f: ProjMap,
    f_halfgate: HashMap<usize, (Wire, Wire)>,
}

pub fn evaluate(circuit: &GarbledCircuit, x: &[Wire]) -> Vec<Wire> {
    let f = &circuit.f;
    let f_halfgate = &circuit.f_halfgate;
    let circuit = &circuit.circuit;
    debug_assert_eq!(x.len(), circuit.num_inputs, "input length mismatch");

    let mut wires: Vec<MaybeUninit<Wire>> = Vec::with_capacity(circuit.num_wires);
    unsafe {
        wires.set_len(circuit.num_wires);
    }
    for i in 0..circuit.num_inputs {
        wires[i].write(x[i].clone());
    }

    let mut j1: usize = 0;
    let mut j0: usize = 0;
    for gate in &circuit.gates {
        let wire: Wire = match gate.kind {
            GateKind::Add => gate
                .inputs
                .iter()
                .map(|&x| unsafe { wires[x].assume_init_ref() }.clone())
                .sum::<Wire>(),
            GateKind::Mul(c) => unsafe { wires[gate.inputs[0]].assume_init_ref() * c },
            GateKind::Proj(_) => {
                let wire = unsafe { wires[gate.inputs[0]].assume_init_ref() };
                let color = wire.color();
                let cipher = &f[&gate.output][color as usize];
                let hw = hash_wire(gate.output, wire, cipher);
                cipher - &hw
            }
            GateKind::And => {
                let a = gate.inputs[0];
                let b = gate.inputs[1];
                let w_a = unsafe { wires[a].assume_init_ref() };
                let w_b = unsafe { wires[b].assume_init_ref() };
                let s_a = w_a.color() != 0;
                let s_b = w_b.color() != 0;
                j0 += 1;
                j1 += 1;
                let (t_g, t_e) = &f_halfgate[&gate.output];

                let w_g = Wire::from_array(hash!(w_a, j0.to_be_bytes()), Domain::Binary);
                let w_g = if s_a { &w_g + t_g } else { w_g };

                let w_e = Wire::from_array(hash!(w_b, j1.to_be_bytes()), Domain::Binary);

                let w_e = if s_b { &w_e + &(t_e + w_a) } else { w_e };

                &w_g + &w_e
            }
        };
        wires[gate.output].write(wire);
    }

    let wires: Vec<Wire> = unsafe { transmute(wires) };
    wires[(circuit.num_wires - circuit.num_outputs)..circuit.num_wires].to_vec()
}

pub fn encode(e: &EncodingKey, x: &[u16]) -> Vec<Wire> {
    let wires = &e.wires;
    let delta = &e.delta;
    debug_assert_eq!(
        wires.len(),
        x.len(),
        "Wire and input vector lengths do not match"
    );

    let mut z = Vec::with_capacity(wires.len());
    for (wire, &x) in wires.iter().zip(x) {
        z.push(wire + &(&delta[&wire.domain()] * x));
    }

    z
}

pub fn decode(d: &DecodingKey, z: &[Wire]) -> Result<Vec<u16>, DecodeError> {
    let mut y = vec![0; d.hashes.len()];
    for i in 0..z.len() {
        let output = d.offset + i;
        let hashes = &d.hashes[i];

        let mut success = false;
        for k in 0..z[i].domain() {
            let hash = hash(output, k, &z[i]);
            println!("hash: {:?}", hash);
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

    fn garble_encode_eval_decode(c: &Circuit, x: &[u16]) -> Vec<u16> {
        let (gc, e, d) = garble(c);
        let x = encode(&e, x);
        let z = evaluate(&gc, &x);
        decode(&d, &z).unwrap()
    }

    #[test]
    fn sum_circuit() {
        let domain = 128;
        let circuit = Circuit {
            gates: vec![Gate {
                kind: GateKind::Add,
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
        let circuit = Circuit {
            gates: vec![Gate {
                kind: GateKind::Add,
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
        let circuit = Circuit {
            gates: vec![Gate {
                kind: GateKind::Mul(9),
                inputs: vec![0],
                output: 1,
                domain,
            }],
            num_inputs: 1,
            num_outputs: 1,
            num_wires: 2,
            input_domains: vec![domain],
        };
        let inputs = vec![57];
        let outputs = garble_encode_eval_decode(&circuit, &inputs);
        assert_eq!(outputs[0], 9 * 57);
    }

    #[test]
    fn proj_circuit_identity() {
        let target_domain = 8;
        let source_domain = 16;
        let circuit = Circuit {
            gates: vec![Gate {
                kind: GateKind::Proj(ProjKind::Map(target_domain)),
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
    fn and_circuit() {
        let circuit = CircuitBuilder::new(2)
            .add_gate(Gate {
                output: 2,
                domain: 2,
                inputs: vec![0, 1],
                kind: GateKind::And,
            })
            .build();
        println!("{:?}", circuit.input_domains);
        verify_circuit(&circuit).unwrap();
        let out = garble_encode_eval_decode(&circuit, &[1, 1]);
        assert_eq!(out[0], 1);
        let out = garble_encode_eval_decode(&circuit, &[0, 1]);
        assert_eq!(out[0], 0);
        let out = garble_encode_eval_decode(&circuit, &[0, 0]);
        assert_eq!(out[0], 0);
    }

    fn make_me_the_threshold() -> Circuit {
        // 8 inputs, 4 "comparators"
        const INPUT_COUNT: usize = 8;
        const BIT_DOMAIN: u16 = 2;
        const COMPARISON_DOMAIN: u16 = 8;

        let threshold = 2;
        use crate::circuit::GateKind::*;
        use crate::circuit::ProjKind::*;
        Circuit {
            // Comparison
            gates: vec![
                Gate {
                    kind: Add,
                    inputs: vec![0, 4],
                    output: 8,
                    domain: BIT_DOMAIN,
                },
                Gate {
                    kind: Add,
                    inputs: vec![1, 5],
                    output: 9,
                    domain: BIT_DOMAIN,
                },
                Gate {
                    kind: Add,
                    inputs: vec![2, 6],
                    output: 10,
                    domain: BIT_DOMAIN,
                },
                Gate {
                    kind: Add,
                    inputs: vec![3, 7],
                    output: 11,
                    domain: BIT_DOMAIN,
                },
                // Second half of comparison
                Gate {
                    kind: Proj(Map(COMPARISON_DOMAIN)),
                    inputs: vec![8],
                    output: 12,
                    domain: BIT_DOMAIN,
                },
                Gate {
                    kind: Proj(Map(COMPARISON_DOMAIN)),
                    inputs: vec![9],
                    output: 13,
                    domain: BIT_DOMAIN,
                },
                Gate {
                    kind: Proj(Map(COMPARISON_DOMAIN)),
                    inputs: vec![10],
                    output: 14,
                    domain: BIT_DOMAIN,
                },
                Gate {
                    kind: Proj(Map(COMPARISON_DOMAIN)),
                    inputs: vec![11],
                    output: 15,
                    domain: BIT_DOMAIN,
                },
                // Adder
                Gate {
                    kind: Add,
                    inputs: vec![12, 13, 14, 15],
                    output: 16,
                    domain: COMPARISON_DOMAIN,
                },
                // Threshold
                Gate {
                    kind: Proj(Less(threshold)),
                    inputs: vec![16],
                    output: 17,
                    domain: COMPARISON_DOMAIN,
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

    #[test]
    fn binary_encode_test() {
        let circuit = Circuit {
            gates: vec![Gate {
                kind: GateKind::Add,
                inputs: vec![0, 1, 2, 3, 5],
                output: 6,
                domain: 2,
            }],
            num_inputs: 6,
            num_outputs: 1,
            num_wires: 7,
            input_domains: vec![2; 6],
        };

        let zeros = vec![0, 0, 0, 0, 0, 0];
        let ones = vec![1, 1, 1, 1, 1, 1];
        let (_, enc, _) = garble(&circuit);
        let bin_enc = BinaryEncodingKey::from(enc.clone());
        let new_enc = EncodingKey::from(bin_enc.clone());
        for i in 0..6 {
            assert!(
                enc.wires[i] == new_enc.wires[i],
                "new and old doesn't match'"
            );
        }
        let ones = encode(&enc, &ones);
        let zeros = encode(&enc, &zeros);
        for (i, one) in ones.iter().enumerate() {
            assert_eq!(one, &bin_enc.1[i], "encoding bad!");
        }
        for (i, zero) in zeros.iter().enumerate() {
            assert_eq!(zero, &bin_enc.0[i], "encoding bad!");
        }
    }
}
