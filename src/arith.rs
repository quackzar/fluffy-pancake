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

fn hash(a : u64, b : u64) -> u64 {
    // This is super nice 😎
    use ring::digest::SHA256;
    use ring::digest::Context;

    let mut context = Context::new(&SHA256);
    context.update(&a.to_be_bytes());
    context.update(&b.to_be_bytes());
    let digest = context.finish();
    let bytes = digest.as_ref();
    let num = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    return num;
}

macro_rules! hash {
    () =>
    {
        0
    };
    ($a:expr) =>
    {
        hash($a, 0)
    };
    ($a:expr, $b:expr) =>
    {
        hash($a, $b)
    };
    ( $x:expr $( , $more:expr )* ) => (
        hash($x, hash!( $( $more ),* ))
    )
}

struct GarbledGadget {
    projs : Vec<Vec<u64>>,
    encoding : (Vec<u64>, Vec<u64>),
    decoding : Vec<Vec<u64>>,


}


use math::round::ceil;
use rand::Rng;

// Domains (in bits, 2^n) for inputs and wires
const INPUTDOMAIN:  u32 =  1;
const WIREDOMAIN:   u32 = 16;
const OUTPUTDOMAIN: u32 = 16;
const GATEDOMAIN:   u32 = WIREDOMAIN;
// TODO(frm): Gate domain?

fn rng(max : u64) -> u64 {
    rand::thread_rng().gen_range(0..max)
}
fn lsb(a : u64) -> u64 {
    (a & 1 == 1) as u64
}

fn garble(circuit: &NewCircuit, k: u64) -> (Vec<u64>, (Vec<u64>, Vec<u64>), Vec<Vec<u64>>) {
    // 1. For each wire
    let mut lambda = Vec::with_capacity(circuit.num_inputs);
    let mut delta  = Vec::with_capacity(circuit.num_inputs);
    for i in 0..circuit.num_wires {
        let bits = ceil((k as f64) / (WIREDOMAIN as f64), 0) as u64;
        lambda.push((1 << bits) + 1);

        // TODO(frm): We might want to not add an additional bit here (consider using first bit).
        delta.push(rng(bits + 1) | 0b1);
    }

    // 2. For each input
    let mut wires = vec![0u64; circuit.num_wires];
    for i in 0..circuit.num_inputs {
        wires.push(rng(lambda[i]));
    }

    // 3. Encoding
    let e = (
        wires[..circuit.num_inputs].to_vec(),
        delta[..circuit.num_inputs].to_vec(),
    );

    // 4. For each gate
    let f = Vec::with_capacity(circuit.num_wires);
    for gate in &circuit.gates {
        let g = match gate.kind {
            NewGateKind::ADD => {
                wires[gate.output] = gate.inputs.iter()
                    .map(|&x| wires[x])
                    .fold(0, |acc, x| acc + x) % (1 << GATEDOMAIN);
            },
            NewGateKind::MUL(c) => wires[gate.output] = (c * wires[gate.inputs[0]]) % (1 << GATEDOMAIN),
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
            values[k] = hash!(i as u64, k as u64, wires[i] + k as u64 * delta[i]);
        }

        d.push(values);
    }

    return (f, e, d);
}

fn evaluate(circuit: &NewCircuit, f: &Vec<u64>, x: &Vec<u64>) -> Vec<u64> {
    let mut wires = vec![0u64; circuit.num_wires];
    for i in 0..circuit.num_inputs {
        wires[i] = x[i];
    }

    for gate in &circuit.gates {
        match gate.kind {
            NewGateKind::ADD => {
                wires[gate.output] = gate.inputs.iter()
                    .map(|&x| wires[x])
                    .fold(0u64, |acc, x| acc + x) % (1 << GATEDOMAIN);
            },
            NewGateKind::MUL(c) => wires[gate.output] = wires[gate.inputs[0]] * c,
            // TODO(frm): Projections! Yay!
            _ => {}
        }
    }

    let mut z = Vec::with_capacity(circuit.num_outputs);
    for i in (circuit.num_wires - circuit.num_outputs)..circuit.num_wires {
        z.push(wires[i]);
    }

    return z;
}

fn encode(e: &(Vec<u64>, Vec<u64>), x: &Vec<u64>) -> Vec<u64> {
    let (w, d) = e;
    assert_eq!(w.len(), d.len());
    assert_eq!(w.len(), x.len());

    let mut z = vec![0u64; w.len()];
    for i in 0..w.len() {
        z[i] = w[i] + x[i] * d[i];
    }

    return z;
}

fn decode(d: &Vec<Vec<u64>>, z: &Vec<u64>) -> (bool, Vec<u64>) {
    assert_eq!(d.len(), z.len());

    let mut success = true;
    let mut y = vec![0u64; d.len()];
    for i in 0..d.len() {
        let h = &d[i];
        let mut found = false;
        for k in 0..(1 << OUTPUTDOMAIN) {
            if hash!(i as u64, k, z[i]) == h[i] {
                y[i] = k;
                found = true;
            }
        }

        success &= found;
    }

    return (success, y);
}

pub fn funfunfunfun() {
    /*
    let circuit = NewCircuit {
        gates: vec![NewGate {
            kind: NewGateKind::ADD,
            inputs: vec![0, 1],
            output: 2,
        }],
        num_inputs: 2,
        num_outputs: 1,
        num_wires: 3,
    };
    */

    let circuit = NewCircuit {
        gates: vec![NewGate {
            kind: NewGateKind::MUL(2),
            inputs: vec![0],
            output: 1,
        }],
        num_inputs: 1,
        num_outputs: 1,
        num_wires: 2,
    };

    const SECURITY: u64 = 128;
    let (f, e, d) = garble(&circuit, SECURITY);

    //let inputs = vec![4, 9];
    let inputs = vec![2];
    let x = encode(&e, &inputs);
    let z = evaluate(&circuit, &f, &x);
    let (success, y) = decode(&d, &z);
    if !success {
        println!("\x1b[31mError decoding, no match found!\x1b[0m");
    }

    println!("HELLO WORLD !!!");
}
