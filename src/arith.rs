struct NewCircuit {
    wiredomains: Vec<u64>,
    inputdomains : Vec<u64>,
    num_inputs : usize,
    gates : Vec<NewGate>
}

#[derive(PartialEq)]
enum NewGateKind {
    ADD,
    MULT(u64),
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
    let mut digest = Context::new(&SHA256);
    digest.update(&a.to_be_bytes());
    digest.update(&b.to_be_bytes());
    return u64::from_be_bytes(digest.finish().as_ref().try_into().unwrap());
}

use rand::Rng;

fn garble(k : u64, circuit : NewCircuit) {
    fn rng(max : u64) -> u64 {
        rand::thread_rng().gen_range(0..4)
    }
    fn lsb(a : u64) -> u64 {
        (a & 1 == 1) as u64
    }
    let mut lambda = Vec::new();
    let mut delta = Vec::new();
    for (i,&m) in circuit.wiredomains.iter().enumerate() {
        lambda.push(k / log2(m));
        delta.push(rng(lambda[i] + 1) | 0b1 );
    }
    let mut domains = Vec::new();
    let mut wires = Vec::new();
    for (i,dom) in circuit.inputdomains.iter().enumerate() {
        domains.push(dom);
        wires.push(rng(lambda[i] + 1)); // 5 is randomly chosen
    }
    let encoding = (&wires[..circuit.num_inputs], &delta[..circuit.num_inputs]);
    for (i, gate) in circuit.gates.iter().enumerate() {
        let domain = 999; //gate.domain;
        match gate.kind {
            NewGateKind::ADD => {
                wires[i] = gate.inputs.iter()
                    .map(|&x| wires[x])
                    .fold(0, |acc, x| acc + x % domain);
            },
            NewGateKind::MULT(c) => {
                let a = gate.inputs[0];
                wires[i] = c * wires[a];
            },
            _ => {}
            // NewGateKind::PROJ(range, phi) => {
            //     let a = gate.inputs[0];
            //     let tau = lsb(wires[a]);
            //     wires[i] -= hash(i as u64, wires[a] + (tau * delta[i]));
            //     wires[i] -= phi( -(tau as i64) as u64)*delta[a];
            //     for x 
            // }
        }
    }
}

