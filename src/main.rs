use std;

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
    inputs: Vec<usize>
}


struct Circuit
{
    gates: Vec<Gate>,
    num_inputs: usize,
    num_outputs: usize,
    num_wires : usize,
}

impl Circuit
{
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
                GateKind::XOR => wires[gate.inputs[0]]  ^ wires[gate.inputs[1]],
                GateKind::OR  => wires[gate.inputs[0]] || wires[gate.inputs[1]],
                _ => false
            };
        }

        return wires[(wires.len() - self.num_outputs)..wires.len()].to_vec()
    }
}

// -------------------------------------------------------------------------------------------------
// Yao stuff






// -------------------------------------------------------------------------------------------------
// fun times ahead
fn main() {
    let circuit = Circuit {
        gates: vec!(Gate {
            kind: GateKind::AND,
            inputs: vec!(0, 1),
            output: 2
        }),
        num_inputs:  2,
        num_outputs: 1,
        num_wires:   3,
    };

    let result = circuit.evaluate(vec!(true, true));

    println!("Result is {}", result[0]);
}
