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
    domain : u64,
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

#[derive(Clone, Debug)]
struct Wire {
    lambda: u64,
    values : Vec<u64>,
    domain : u64,
}

use core::ops;
use std::iter;


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
        let init = iter.next().unwrap();
        iter.fold(init, |acc : Wire, w : Wire| &acc + &w)
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
            values[i as usize] = (rng(1 << domain + 1) << 1) | 0b1;
        }
        return Wire{values, lambda, domain};
    }
}

use itertools::Itertools;
use math::round::ceil;
use rand::Rng;


// Domains (in bits, 2^n) for inputs and wires
const INPUTDOMAIN:  u64 = 4;
const WIREDOMAIN:   u64 = 8;
const OUTPUTDOMAIN: u64 = 8;
const GATEDOMAIN:   u64 = WIREDOMAIN;
// TODO(frm): Gate domain?

fn rng(max : u64) -> u64 {
    rand::thread_rng().gen_range(0..max)
}
fn lsb(a : u64) -> u64 {
    (a & 1 == 1) as u64
}

struct Encoding {
    wires : Vec<Wire>,
    delta : HashMap<u64, Wire>,
}

struct Decoding {
    map : Vec<Vec<u64>>,
}

use std::collections::HashMap;


fn garble(circuit: &NewCircuit, k: u64) -> (Vec<u64>, Encoding, Decoding) {
    // 1. For each domain (we only have one)
    let lambda = ceil((k as f64) / (WIREDOMAIN as f64), 0) as u64;
    let outputs = (circuit.num_wires - circuit.num_outputs)..circuit.num_wires;
    let outputs : Vec<&NewGate> = circuit.gates.iter()
        .filter(|g| outputs.contains(&g.output))
        .collect();

    let inputs = 0..circuit.num_inputs;
    let _inputs : Vec<&NewGate> = circuit.gates.iter()
        .filter(|g| 
            g.inputs.iter()
                .any(|i| inputs.contains(i))
        )
        .collect();

    let delta : HashMap<_,_> = circuit.gates.iter()
        .map(|g : &NewGate| g.domain)
        .unique()
        .map(|d| (d, Wire::delta(d, lambda)))
        .collect();
    //delta.insert(Wire::delta(WIREDOMAIN as u64, lambda));

    // 2. For each input
    let mut wires = Vec::with_capacity(circuit.num_wires);
    for _ in 0..circuit.num_inputs {
        wires.push(Wire::new(WIREDOMAIN as u64, lambda));
    }

    // 3. Encoding
    let encoding = Encoding{
        wires : wires[..circuit.num_inputs].to_vec(),
        delta : delta.clone(),
    };

    // 4. For each gate
    let f = Vec::with_capacity(circuit.num_wires);
    for gate in &circuit.gates {
        let w = match gate.kind {
            NewGateKind::ADD => {
                gate.inputs.iter()
                    .map(|&x| wires[x].clone())
                    .sum()
            },
            NewGateKind::MUL(c) => {
                &wires[gate.inputs[0]] * c
            },
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
    let mut d = Vec::with_capacity(circuit.num_outputs);
    for gate in outputs {
        let i = gate.output;
        let domain = gate.domain;
        let mut values = vec![0; 1 << domain];
        for k in 0..(1 << domain) {
            let hash = hash(i as u64, k as u64, &(&wires[i] + &(&delta[&domain] * k)));
            values[k as usize] = hash;
        }
        d.push(values);
    }
    let decoding = Decoding{map : d};
    return (f, encoding, decoding);
}


fn evaluate(circuit: &NewCircuit, _f: &Vec<u64>, x: &Vec<Wire>) -> Vec<Wire> {
    use std::mem::{MaybeUninit, transmute};
    println!("{}", circuit.num_wires);
    let mut wires : Vec<MaybeUninit<Wire>> = Vec::with_capacity(circuit.num_wires);
    unsafe { wires.set_len(circuit.num_wires); }
    for i in 0..circuit.num_inputs {
        wires[i].write(x[i].clone());
    }
    for gate in &circuit.gates {
        let w : Wire = match gate.kind {
            NewGateKind::ADD => {
                gate.inputs.iter()
                    .map(|&x| unsafe{ wires[x].assume_init_ref() }.clone())
                    .sum::<Wire>()
            },
            NewGateKind::MUL(c) => unsafe{ wires[gate.inputs[0]].assume_init_ref() * c },
            // TODO(frm): Projections! Yay!
            _ => {panic!("Unsupported gate type");}
        };
        wires[gate.output].write(w);
    }
    let wires : Vec<Wire> = unsafe{transmute(wires)};
    return wires[(circuit.num_wires - circuit.num_outputs)..circuit.num_wires].to_vec()
}

fn encode(e: &Encoding, x: &Vec<u64>) -> Vec<Wire> {
    let wires = &e.wires;
    let delta = &e.delta;
    assert_eq!(wires.len(), x.len(), "Wire and input vector lengths do not match");
    let mut z = Vec::with_capacity(wires.len());
    for (w,&x) in wires.iter().zip(x) {
        let domain = w.domain;
        z.push(w + &(&delta[&domain] * x));
    }
    return z;
}

use std::error::Error;
use std::fmt;

#[derive(Debug)]
struct DecodeError {}
impl Error for DecodeError {}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error decoding result")
    }
}

fn decode(circuit: &NewCircuit, decoding: &Decoding, z: &Vec<Wire>) -> Result<Vec<u64>, DecodeError> {
    let d = &decoding.map;
    assert_eq!(d.len(), z.len());

    let mut success = false;
    let mut y = vec![0u64; d.len()];
    for i in 0..d.len() {
        let g = circuit.num_wires - circuit.num_outputs + i;
        let h = &d[i];
        for k in 0..(1 << OUTPUTDOMAIN) {
            let hash = hash(g as u64, k, &z[i]);
            if hash == h[k as usize] {
                y[i] = k;
                success = true;
                break;
            }
        }
    }

    if success { Ok(y) } else { Err(DecodeError{}) }
}

pub fn funfunfunfun() {
    let circuit = NewCircuit {
        gates: vec![NewGate {
            kind: NewGateKind::MUL(1),
            inputs: vec![0],
            output: 1,
            domain: WIREDOMAIN,
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
    match decode(&circuit, &d, &z) {
        Ok(y) => {
            for i in 0..y.len() {
                println!("Output {} is {}", i, y[i]);
            }
        },
        Err(_) => println!("\x1b[31mError decoding, no match found!\x1b[0m"),
    }
}
