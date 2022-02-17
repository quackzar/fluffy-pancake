// -------------------------------------------------------------------------------------------------
// Circuit stuff
#[derive(PartialEq)]
pub enum GateKind {
    // Unary
    NOT,

    // Binary
    AND,
    OR,
    XOR,
}

pub struct Gate {
    pub kind: GateKind,
    pub output: usize,
    pub inputs: Vec<usize>,
}

pub struct Circuit {
    pub gates: Vec<Gate>,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub num_wires: usize,
}

impl Circuit {
    pub fn evaluate(&self, input: Vec<bool>) -> Vec<bool> {
        let mut wires = vec![false; self.num_wires];
        wires[..input.len()].copy_from_slice(&input);

        // TODO: Support magic several input gates
        for gate in &self.gates {
            wires[gate.output] = match gate.kind {
                GateKind::NOT => !wires[gate.inputs[0]],
                GateKind::AND => wires[gate.inputs[0]] && wires[gate.inputs[1]],
                GateKind::XOR => wires[gate.inputs[0]] ^ wires[gate.inputs[1]],
                GateKind::OR => wires[gate.inputs[0]] || wires[gate.inputs[1]],
            };
        }

        wires[(wires.len() - self.num_outputs)..wires.len()].to_vec()
    }
}
