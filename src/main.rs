#![allow(dead_code)]
#![allow(unused_variables)]

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

fn eq(left: Primitive, right: Primitive) -> bool {
    for i in 0..SECURITY_BYTES {
        if left[i] != right[i] {
            return false;
        }
    }

    return true;
}

fn zero(p: Primitive) -> bool {
    for i in 0..SECURITY_BYTES {
        if p[i] != 0x00 {
            return false;
        }
    }

    return true;
}

use std::vec;
use sha2ni::Digest;
fn prf(left: Primitive, right: Primitive, index: usize) -> (Primitive, Primitive) {
    // TODO(frm): This is probably not the best way to do it!
    let mut sha = sha2ni::Sha256::new();
    sha.input(left);
    sha.input(right);

    // TODO(frm): This is super not nice :(
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

use ring::rand::{SecureRandom, SystemRandom};
fn random_primitives() -> [Primitive; 2] {
    let random = SystemRandom::new();

    let mut left = [0u8; SECURITY_BYTES];
    let _ = random.fill(&mut left);

    let mut right = [0u8; SECURITY_BYTES];
    let _ = random.fill(&mut right);

    return [left, right];
}

fn yao_garble(circuit: &Circuit) -> (Vec<Primitives>, Vec<Primitives>, Vec<[Primitives; 4]>) {
    let mut k: Vec<Primitives> = vec![[[0; SECURITY_BYTES]; 2]; circuit.num_wires];

    // 1. Pick key pairs for the inputs wires
    for i in 0..circuit.num_wires {
        k[i] = random_primitives();
    }
    let e = k[..circuit.num_inputs].to_vec();

    // 2. Gooble garble
    let mut f: Vec<[Primitives; 4]> = vec![[[[0; SECURITY_BYTES]; 2]; 4]; circuit.num_wires];
    for gate in &circuit.gates {
        // TODO(frm): We can optimize NOT gates

        // Binary gates
        // TODO(frm): Magic many input gates?
        let mut c: [Primitives; 4] = [[[0u8; SECURITY_BYTES]; 2]; 4];
        let combinations = [(false, false), (false, true), (true, false), (true, true)];
        for j in 0..combinations.len() {
            let (left, right) = combinations[j];
            let gate_value = match gate.kind {
                GateKind::NOT => !left,
                GateKind::AND => left && right,
                GateKind::XOR => left ^ right,
                GateKind::OR => left || right,
            };
            let garbled_value = k[gate.output as usize][gate_value as usize];
            let (g_left, g_right) = prf(
                k[gate.inputs[0]][left as usize],
                k[gate.inputs[1]][right as usize],
                gate.output
            );
            c[j] = [xor(g_left, garbled_value), g_right];
        }

        // TODO(frm): Permute c !!!
        f[gate.output] = c;
    }
    // TODO(frm): Return something with F

    // 3. Decoding information
    let d = k[(circuit.num_wires - circuit.num_outputs)..].to_vec();
    return (e, d, f);
}

fn yao_encode(circuit: &Circuit, e: Vec<Primitives>, x: Vec<bool>) -> Vec<Primitive> {
    assert_eq!(x.len(), circuit.num_inputs);
    assert_eq!(e.len(), circuit.num_inputs);

    let mut z: Vec<Primitive> = vec![[0; SECURITY_BYTES]; circuit.num_inputs];
    for i in 0..circuit.num_inputs {
        z[i] = e[i][if x[i] { 1 } else { 0 }];
    }

    return z;
}

fn yao_evaluate(circuit: &Circuit, f: Vec<[Primitives; 4]>, x: Vec<Primitive>) -> Vec<Primitive> {
    assert_eq!(x.len(), circuit.num_inputs);

    // 1. Set the inputs
    let mut wire: Vec<Primitive> = vec![[0; SECURITY_BYTES]; circuit.num_wires];
    for i in 0..circuit.num_inputs {
        wire[i] = x[i];
    }

    // 2. Compute gates
    for gate in &circuit.gates {
        // TODO(frm): What about NOT gates?
        let (gate_left, gate_right) = prf(wire[gate.inputs[0]], wire[gate.inputs[1]], gate.output);

        let mut found = false;
        for j in 0..4 {
            let c = f[gate.output][j];
            let (c_left, c_right) = (c[0], c[1]);

            let k = xor(gate_left, c_left);
            let t = xor(gate_right, c_right);
            if zero(t) {
                wire[gate.output] = k;
                found = true;
                break;
            }
        }

        if !found {
            eprintln!("Cannot find solution for gate {}, no match with table!", gate.output);
        }
    }

    // 3. Result
    let z = wire[(circuit.num_wires - circuit.num_outputs)..].to_vec();
    return z;
}

fn yao_decode(circuit: &Circuit, d: Vec<Primitives>, z: Vec<Primitive>) -> Vec<bool> {
    assert_eq!(z.len(), circuit.num_outputs);
    assert_eq!(d.len(), circuit.num_outputs);

    let mut y: Vec<bool> = vec![false; circuit.num_outputs];
    for i in 0..circuit.num_outputs {
        if eq(d[i][0], z[i]) {
            y[i] = false;
        }
        else if eq(d[i][1], z[i]) {
            y[i] = true;
        }
        else {
            eprintln!("Error decoding output {}, no match with decoding information!", i)
        }
    }

    // TODO(frm): We would like some way to be able to reflect an error case!
    return y;
}

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

    let input = vec![true, true];
    let expected = circuit.evaluate(input.clone());

    let (e, d, f) = yao_garble(&circuit);
    let x = yao_encode(&circuit, e, input);
    let z = yao_evaluate(&circuit, f, x);
    let y = yao_decode(&circuit, d, z);

    assert_eq!(y.len(), expected.len());
    for i in 0..y.len() {
        println!("Output {}> {} ?= {} => {}", i, y[i], expected[i], y[i] == expected[i]);
    }
}
