#![allow(dead_code)]

// -------------------------------------------------------------------------------------------------
// Circuit stuff
#[derive(PartialEq)]
enum GateKind {
    // Unary
    NOT,

    // Binary
    AND,
    OR,
    XOR,

    // Special
    IN,
}

struct Gate {
    kind: GateKind,
    output: usize,
    inputs: Vec<usize>,
}

struct Circuit {
    gates: Vec<Gate>,
    num_inputs: usize,
    num_outputs: usize,
    num_wires: usize,
}

impl Circuit {
    fn evaluate(&self, input: Vec<bool>) -> Vec<bool> {
        let mut wires = vec![false; self.num_wires];

        for i in 0..input.len() {
            wires[i] = input[i];
        }

        // TODO: Support magic several input gates
        for gate in &self.gates {
            wires[gate.output] = match gate.kind {
                GateKind::NOT => !wires[gate.inputs[0]],
                GateKind::AND => wires[gate.inputs[0]] && wires[gate.inputs[1]],
                GateKind::XOR => wires[gate.inputs[0]] ^ wires[gate.inputs[1]],
                GateKind::OR => wires[gate.inputs[0]] || wires[gate.inputs[1]],
                _ => false,
            };
        }

        return wires[(wires.len() - self.num_outputs)..wires.len()].to_vec();
    }
}

// -------------------------------------------------------------------------------------------------
// Yao stuff

const SECURITY_BYTES: usize = 16;
type Primitive = [u8; SECURITY_BYTES];

type Primitives = [Primitive; 2];

fn xor(left: Primitive, right: Primitive) -> Primitive {
    let mut result = [0u8; SECURITY_BYTES];
    for i in 0..SECURITY_BYTES {
        result[i] = left[i] ^ right[i];
    }

    return result;
}

use sha2ni::Digest;
fn G(left: Primitive, right: Primitive, index: usize) -> (Primitive, Primitive) {
    // TODO(frm): This is probably not the best way to do it!
    let mut sha = sha2ni::Sha256::new();
    sha.input(left);
    sha.input(right);

    use std::mem::transmute;
    let index: [u8; 4] = unsafe { transmute((index as u32).to_be()) };
    sha.input(index);

    // TODO(frm): What if the sizes are out of bounds?
    let digest = sha.result();
    let mut l_result = [0u8; SECURITY_BYTES];
    let mut r_result = [0u8; SECURITY_BYTES];
    for i in 0..SECURITY_BYTES {
        l_result[i] = digest[i];
        r_result[i] = digest[16 - i];
    }

    return (l_result, r_result);
}

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
fn random_primitives() -> [Primitive; 2] {
    let random = SystemRandom::new();

    let mut left = [0u8; SECURITY_BYTES];
    let _ = random.fill(&mut left);

    let mut right = [0u8; SECURITY_BYTES];
    let _ = random.fill(&mut right);

    return [left, right];
}

fn yao_garble(circuit: &Circuit) -> (Vec<Primitives>, Vec<Primitives>) {
    let mut k: Vec<Primitives> = Vec::with_capacity(circuit.num_wires);

    // 1. Pick key pairs for the inputs wires
    for _ in 0..circuit.num_wires {
        k.push(random_primitives());
    }
    let e = k[..circuit.num_inputs].to_vec();

    // 2. Gooble garble
    for i in 0..circuit.gates.len() {
        let gate = &circuit.gates[i];

        // TODO(frm): NOT gates are special

        // Binary gates
        // TODO(frm): Magic many input gates?
        let mut c: [Primitives; 4] = [[[0u8; SECURITY_BYTES]; 2]; 4];
        let combinations = [(0, 0), (0, 1), (1, 0), (1, 1)];
        for j in 0..combinations.len() {
            let (left, right) = combinations[j];
            let gate_value = match gate.kind {
                GateKind::NOT => {
                    if left == 1 {
                        0
                    } else {
                        1
                    }
                }
                GateKind::AND => left & right,
                GateKind::XOR => left ^ right,
                GateKind::OR => left | right,
                _ => 0,
            };
            let garbled_value = k[gate.output][gate_value];
            let (g_left, g_right) = G(k[gate.inputs[0]][left], k[gate.inputs[1]][right], i);
            c[1 * left + 2 * right] = [xor(g_left, garbled_value), g_right];
        }
    }
    // TODO(frm): Return something with F

    // 3. Decoding information
    let d = k[(circuit.num_wires - circuit.num_outputs)..].to_vec();
    return (e, d);
}

fn yao_encode(circuit: &Circuit) {}

fn yao_evaluate(circuit: &Circuit) {}

fn yao_decode(circuit: &Circuit) {}

// -------------------------------------------------------------------------------------------------
// fun times ahead
fn main() {
    let circuit = Circuit {
        gates: vec![Gate {
            kind: GateKind::AND,
            inputs: vec![0, 1],
            output: 2,
        }],
        num_inputs: 2,
        num_outputs: 1,
        num_wires: 3,
    };

    let (e, d) = yao_garble(&circuit);
    println!("IT IS NOW IN USE! {}", e.len() + d.len());

    let result = circuit.evaluate(vec![true, true]);

    println!("Result is {}", result[0]);
}
