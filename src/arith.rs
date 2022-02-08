pub struct NewCircuit {
    // TODO(frm): usize, u32?
    num_wires: usize,
    num_inputs: usize,
    num_outputs: usize,
    gates: Vec<NewGate>,
    input_domains: Vec<u64>,
}

#[derive(PartialEq)]
enum NewGateKind {
    ADD,
    MUL(u64),
    PROJ(u64, fn(u64) -> u64),
}

struct NewGate {
    kind: NewGateKind,
    output: usize,
    inputs: Vec<usize>,
    domain: u64,
}

fn log2(x: u64) -> u64 {
    (std::mem::size_of::<u64>() as u64) * 8 - (x.leading_zeros() as u64)
}

fn hash(a: u64, b: u64, w: &Wire) -> u64 {
    // This is super nice 😎
    use ring::digest::Context;
    use ring::digest::SHA256;

    let mut context = Context::new(&SHA256);
    context.update(&a.to_be_bytes());
    context.update(&b.to_be_bytes());
    context.update(&w.lambda.to_be_bytes());
    context.update(&w.domain.to_be_bytes());
    for v in &w.values {
        context.update(&v.to_be_bytes());
    }
    let digest = context.finish();
    let bytes = digest.as_ref();
    let num = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    return num;
}

#[derive(Clone, Debug)]
pub struct Wire {
    lambda: u64,
    values: Vec<u64>,
    domain: u64,
}

use core::ops;
use std::iter;

impl ops::Add<&Wire> for &Wire {
    type Output = Wire;
    fn add(self, _rhs: &Wire) -> Wire {
        assert_eq!(self.lambda, _rhs.lambda);
        assert_eq!(self.domain, _rhs.domain);
        let domain = self.domain;
        let lambda = self.lambda;
        let values = self
            .values
            .iter()
            .zip(_rhs.values.iter())
            .map(|(a, b)| (a + b) % domain)
            .collect();
        return Wire {
            domain,
            values,
            lambda,
        };
    }
}

impl ops::Mul<u64> for &Wire {
    type Output = Wire;
    #[inline]
    fn mul(self, _rhs: u64) -> Wire {
        let domain = self.domain;
        let lambda = self.lambda;
        let values = self.values.iter().map(|x| (x * _rhs) % domain).collect();
        return Wire {
            domain,
            values,
            lambda,
        };
    }
}

impl iter::Sum for Wire {
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let init = iter.next().unwrap();
        iter.fold(init, |acc: Wire, w: Wire| &acc + &w)
    }
}

impl Wire {
    fn new(domain: u64, lambda: u64) -> Wire {
        let mut values = vec![0u64; lambda as usize];
        for i in 0..lambda {
            values[i as usize] = rng(domain + 1);
        }
        return Wire {
            values,
            lambda,
            domain,
        };
    }

    fn delta(domain: u64, lambda: u64) -> Wire {
        let mut values = vec![0u64; lambda as usize];
        for i in 0..lambda {
            values[i as usize] = (rng(domain + 1)) | 0b1;
        }
        return Wire {
            values,
            lambda,
            domain,
        };
    }
}

use itertools::Itertools;
use math::round::ceil;
use rand::Rng;

// Domains (in bits, 2^n) for inputs and wires
const INPUTDOMAIN: u64 = 4;
const WIREDOMAIN: u64 = 8;
const OUTPUTDOMAIN: u64 = 8;
const GATEDOMAIN: u64 = WIREDOMAIN;
// TODO(frm): Gate domain?

fn rng(max: u64) -> u64 {
    rand::thread_rng().gen_range(0..max)
}

#[inline]
fn lsb(a: u64) -> u64 {
    (a & 1 == 1) as u64
}

pub struct Encoding {
    wires: Vec<Wire>,
    delta: HashMap<u64, Wire>,
}

pub struct Decoding {
    map: Vec<Vec<u64>>,
    ids: Vec<usize>,
    domains: Vec<u64>,
}

use std::collections::HashMap;

fn garble(circuit: &NewCircuit, k: u64) -> (Vec<u64>, Encoding, Decoding) {
    // 1. For each domain (we only have one)

    ceil((k as f64) / (WIREDOMAIN as f64), 0) as u64;

    let lambda: HashMap<_, _> = circuit
        .gates
        .iter()
        .map(|g| g.domain)
        .unique()
        .map(|m| (m, (k + log2(m) - 1) / log2(m)))
        .collect();

    let delta: HashMap<_, _> = circuit
        .gates
        .iter()
        .map(|g: &NewGate| g.domain)
        .unique()
        .map(|m| (m, Wire::delta(m, lambda[&m])))
        .collect();

    // 2. For each input

    let inputs = 0..circuit.num_inputs;
    let mut wires = Vec::with_capacity(circuit.num_wires);
    for i in inputs {
        let m = circuit.input_domains[i];
        wires.push(Wire::new(m, lambda[&m]));
    }

    // 3. Encoding
    let encoding = Encoding {
        wires: wires[..circuit.num_inputs].to_vec(),
        delta: delta.clone(),
    };

    // 4. For each gate
    let f = Vec::with_capacity(circuit.num_wires);
    for gate in &circuit.gates {
        let w = match gate.kind {
            NewGateKind::ADD => gate.inputs.iter().map(|&x| wires[x].clone()).sum(),
            NewGateKind::MUL(c) => &wires[gate.inputs[0]] * c,
            // NewGateKind::PROJ(range, phi) => {
            //     let a = gate.inputs[0];
            //     let tau = lsb(wires[a]);
            //     wires[i] -= hash(i as u64, wires[a] + (tau * delta[i]));
            //     wires[i] -= phi( -(tau as i64) as u64)*delta[a];
            //     for x
            // },
            _ => {
                panic!("Unsupported gate type");
            }
        };
        wires.push(w);
    }

    // 5. Decoding / outputs
    let outputs = (circuit.num_wires - circuit.num_outputs)..circuit.num_wires;
    let outputs: Vec<&NewGate> = circuit
        .gates
        .iter()
        .filter(|g| outputs.contains(&g.output))
        .collect();

    let mut d = Vec::with_capacity(circuit.num_outputs);
    let mut ids = Vec::with_capacity(circuit.num_outputs);
    let mut domains = Vec::with_capacity(circuit.num_outputs);
    for gate in outputs {
        let id = gate.output;
        let domain = gate.domain;
        let mut values = vec![0; domain as usize];
        for k in 0..domain {
            let hash = hash(id as u64, k as u64, &(&wires[id] + &(&delta[&domain] * k)));
            values[k as usize] = hash;
        }
        d.push(values);
        ids.push(id);
        domains.push(domain);
    }
    let decoding = Decoding {
        map: d,
        ids,
        domains,
    };
    return (f, encoding, decoding);
}

fn evaluate(circuit: &NewCircuit, _f: &Vec<u64>, x: &Vec<Wire>) -> Vec<Wire> {
    use std::mem::{transmute, MaybeUninit};
    let mut wires: Vec<MaybeUninit<Wire>> = Vec::with_capacity(circuit.num_wires);
    unsafe {
        wires.set_len(circuit.num_wires);
    }
    for i in 0..circuit.num_inputs {
        wires[i].write(x[i].clone());
    }
    for gate in &circuit.gates {
        let w: Wire = match gate.kind {
            NewGateKind::ADD => gate
                .inputs
                .iter()
                .map(|&x| unsafe { wires[x].assume_init_ref() }.clone())
                .sum::<Wire>(),
            NewGateKind::MUL(c) => unsafe { wires[gate.inputs[0]].assume_init_ref() * c },
            // TODO(frm): Projections! Yay!
            _ => {
                panic!("Unsupported gate type");
            }
        };
        wires[gate.output].write(w);
    }
    let wires: Vec<Wire> = unsafe { transmute(wires) };
    return wires[(circuit.num_wires - circuit.num_outputs)..circuit.num_wires].to_vec();
}

pub fn encode(e: &Encoding, x: &Vec<u64>) -> Vec<Wire> {
    let wires = &e.wires;
    let delta = &e.delta;
    assert_eq!(
        wires.len(),
        x.len(),
        "Wire and input vector lengths do not match"
    );
    let mut z = Vec::with_capacity(wires.len());
    for (w, &x) in wires.iter().zip(x) {
        let domain = w.domain;
        z.push(w + &(&delta[&domain] * x));
    }
    return z;
}

use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct DecodeError {}
impl Error for DecodeError {}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error decoding result")
    }
}

pub fn decode(decoding: &Decoding, z: &Vec<Wire>) -> Result<Vec<u64>, DecodeError> {
    let d = &decoding.map;
    let ids = &decoding.ids;
    let domains = &decoding.domains;
    assert_eq!(d.len(), z.len());
    assert_eq!(d.len(), ids.len());
    let mut y = vec![0u64; d.len()];
    for i in 0..d.len() {
        let mut success = false;
        let id = ids[i];
        let h = &d[i];
        for k in 0..domains[i] {
            let hash = hash(id as u64, k, &z[i]);
            if hash == h[k as usize] {
                y[i] = k;
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

#[cfg(test)]
mod tests {
    use crate::arith::{decode, encode, evaluate, garble, hash, Decoding, Encoding, Wire};
    use std::collections::HashMap;

    use super::{NewCircuit, NewGate, NewGateKind};

    fn garble_encode_eval_decode(c: &NewCircuit, x: &Vec<u64>) -> Vec<u64> {
        const SECURITY: u64 = 128;
        let (f, e, d) = garble(&c, SECURITY);
        let x = encode(&e, x);
        let z = evaluate(c, &f, &x);
        return decode(&d, &z).unwrap();
    }

    #[test]
    fn encode_decode() {
        let id: usize = 0;
        let lambda = 8;
        let domain = 128;
        let mut map = HashMap::new();
        let delta = Wire::delta(domain, lambda);
        map.insert(domain, delta.clone());
        let wire = Wire::new(domain, lambda);
        let e = Encoding {
            wires: vec![wire.clone()],
            delta: map,
        };
        let hashes: Vec<u64> = (0..domain)
            .map(|k| hash(id as u64, k, &(&wire + &(&delta * k))))
            .collect();
        let d = Decoding {
            domains: vec![domain],
            ids: vec![id],
            map: vec![hashes],
        };
        let input = vec![69];
        let x = encode(&e, &input);
        let y = decode(&d, &x).unwrap();
        assert_eq!(input, y)
    }

    #[test]
    fn sum_circuit() {
        let domain = 128;
        let circuit = NewCircuit {
            gates: vec![NewGate {
                kind: NewGateKind::ADD,
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
    fn mult_circuit() {
        let domain = 600;
        let circuit = NewCircuit {
            gates: vec![NewGate {
                kind: NewGateKind::MUL(9),
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
}
