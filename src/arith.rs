struct NewCircuit {
    // TODO(frm): usize, u32?
    num_wires: usize,
    num_inputs: usize,
    num_outputs: usize,

    gates : Vec<NewGate>,
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
}



fn log2(x : u64) -> u64 {
    (std::mem::size_of::<u64>() as u64) * 8 - (x.leading_zeros() as u64)
}

fn hash(a: u64, b: u64, w: &Wire) -> u64 {
    // This is super nice 😎
    use ring::digest::SHA256;
    use ring::digest::Context;

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

struct GarbledGadget {
    projs : Vec<Vec<u64>>,
    encoding : (Vec<u64>, Vec<u64>),
    decoding : Vec<Vec<u64>>,


}

#[derive(Clone)]
struct Wire {
    lambda: u64,
    values : Vec<u64>,
    domain : u64,
}

use core::ops;
use std::iter;
use std::iter::Sum;

impl ops::Add<&Wire> for &Wire {
    type Output = Wire;
    fn add(self, _rhs : &Wire) -> Wire {
        assert_eq!(self.lambda, _rhs.lambda);
        assert_eq!(self.domain, _rhs.domain);
        let domain = self.domain;
        let lambda = self.lambda;
        let values = self.values.iter()
            .zip(_rhs.values.iter())
            .map(|(a, b)| a + b % domain).collect();
        return Wire {domain, values, lambda};
    }
}

impl ops::Mul<u64> for Wire {
    type Output = Wire;
    fn mul(self, _rhs : u64) -> Wire {
        let domain = self.domain;
        let lambda = self.lambda;
        let values = self.values.iter()
            .map(|x| x * _rhs % domain).collect();
        return Wire {domain, values, lambda};
    }
}

impl ops::Mul<u64> for &Wire {
    type Output = Wire;
    fn mul(self, _rhs : u64) -> Wire {
        let domain = self.domain;
        let lambda = self.lambda;
        let values = self.values.iter()
            .map(|x| x * _rhs % domain).collect();
        return Wire {domain, values, lambda};
    }
}


impl iter::Sum for Wire {
    fn sum<I: Iterator<Item=Self>>(mut iter: I) -> Self {
        let mut acc = iter.next().unwrap();
        iter.fold(acc, |acc, w| &acc + w)
    }
}

impl Wire {
    fn new(domain : u64, lambda: u64) -> Wire {
        let mut values = vec![0u64; lambda as usize];
        for i in 0..lambda {
            values[i as usize] = rng((1 << (domain + 1)) + 1);
        }
        return Wire{values, lambda, domain};
    }

    fn delta(domain : u64, lambda: u64) -> Wire {
        let mut values = vec![0u64; lambda as usize];
        for i in 0..lambda {
            values[i as usize] = (rng((1 << (domain + 1))) << 1) | 0b1;
        }
        return Wire{values, lambda, domain};
    }

    fn empty() -> Wire {
        return Wire{
            values : vec![],
            domain : 0,
            lambda : 0,
        }
    }
}

use math::round::ceil;
use rand::Rng;

// Domains (in bits, 2^n) for inputs and wires
const INPUTDOMAIN:  u32 = 4;
const WIREDOMAIN:   u32 = 8;
const OUTPUTDOMAIN: u32 = 8;
const GATEDOMAIN:   u32 = WIREDOMAIN;
// TODO(frm): Gate domain?

fn rng(max : u64) -> u64 {
    rand::thread_rng().gen_range(0..max)
}
fn lsb(a : u64) -> u64 {
    (a & 1 == 1) as u64
}

fn garble(circuit: &NewCircuit, k: u64) -> (Vec<u64>, (Vec<Wire>, Vec<Wire>), Vec<Vec<u64>>) {
    // 1. For each domain (we only have one)
    let lambda = ceil((k as f64) / (WIREDOMAIN as f64), 0) as u64;

    let mut delta = Vec::new();
    for i in 0..lambda {
        delta.push(Wire::delta(1 << WIREDOMAIN as u64, lambda));
    }

    // 2. For each input
    let mut wires = Vec::new();
    for i in 0..circuit.num_inputs {
        wires.push(Wire::new(1 << WIREDOMAIN as u64, lambda));
    }

    // 3. Encoding
    let e = (
        wires[..circuit.num_inputs].to_vec(),
        delta,
    );

    // 4. For each gate
    let f = Vec::with_capacity(circuit.num_wires);
    for gate in &circuit.gates {
        let g = match gate.kind {
            NewGateKind::ADD => {
                wires[gate.output] = gate.inputs.iter()
                    .map(|&x| wires[x])
                    .sum();
            },
            NewGateKind::MUL(c) => wires[gate.output] = &wires[gate.inputs[0]] * c,
            // NewGateKind::PROJ(range, phi) => {
            //     let a = gate.inputs[0];
            //     let tau = lsb(wires[a]);
            //     wires[i] -= hash(i as u64, wires[a] + (tau * delta[i]));
            //     wires[i] -= phi( -(tau as i64) as u64)*delta[a];
            //     for x 
            // },
            _ => {}
        };
    }

    // 5. Decoding / outputs
    let mut d = Vec::with_capacity(circuit.num_outputs);
    for i in (circuit.num_wires - circuit.num_outputs)..circuit.num_wires {
        let mut values = vec![0; (1 << OUTPUTDOMAIN)];
        for k in 0..(1 << OUTPUTDOMAIN) {
            let hash = hash(i as u64, k as u64, &(&wires[i] + &delta[i] * k));
            values[k as usize] = hash;
        }

        d.push(values);
    }

    return (f, e, d);
}

fn evaluate(circuit: &NewCircuit, f: &Vec<u64>, x: &Vec<Wire>) -> Vec<Wire> {
    let mut wires = vec![Wire::empty(); circuit.num_wires];
    for i in 0..circuit.num_inputs {
        wires[i] = x[i];
    }

    for gate in &circuit.gates {
        match gate.kind {
            NewGateKind::ADD => {
                wires[gate.output] = gate.inputs.iter()
                    .map(|&x| wires[x])
                    .sum();
            },
            NewGateKind::MUL(c) => wires[gate.output] = wires[gate.inputs[0]] * c,
            // TODO(frm): Projections! Yay!
            _ => {}
        }
    }
    return wires[(circuit.num_wires - circuit.num_outputs)..circuit.num_wires].to_vec()
}

fn encode(e: &(Vec<Wire>, Vec<Wire>), x: &Vec<u64>) -> Vec<Wire> {
    let (w, d) = e;
    assert_eq!(w.len(), d.len());
    assert_eq!(w.len(), x.len());

    let mut z = Vec::with_capacity(w.len());
    for i in 0..w.len() {
        z.push(w[i] +  d[i] * x[i]);
    }

    return z;
}

fn decode(circuit: &NewCircuit, d: &Vec<Vec<u64>>, z: &Vec<Wire>) -> (bool, Vec<u64>) {
    assert_eq!(d.len(), z.len());

    let mut success = false;
    let mut y = vec![0u64; d.len()];
    for i in 0..d.len() {
        let g = circuit.num_wires - circuit.num_outputs + i;
        let h = &d[i];
        let mut found = false;
        for k in 0..(1 << OUTPUTDOMAIN) {
            let hash = hash(g as u64, k, &z[i]);
            if hash == h[k as usize] {
                y[i] = k;
                success = true;
                break;
            }
        }
    }

    return (success, y);
}

pub fn funfunfunfun() {
    let circuit = NewCircuit {
        gates: vec![NewGate {
            kind: NewGateKind::MUL(1),
            inputs: vec![0],
            output: 1,
        }],
        num_inputs: 1,
        num_outputs: 1,
        num_wires: 2,
    };
    let inputs = vec![2];

    const SECURITY: u64 = 128;
    let (f, e, d) = garble(&circuit, SECURITY);

    let x = encode(&e, &inputs);
    let z = evaluate(&circuit, &f, &x);
    let (success, y) = decode(&circuit, &d, &z);
    if !success {
        println!("\x1b[31mError decoding, no match found!\x1b[0m");
    }

    for i in 0..y.len() {
        println!("Output {} is {}", i, y[i]);
    }
}
