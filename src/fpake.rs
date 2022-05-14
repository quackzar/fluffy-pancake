use crate::circuit::build_circuit;
use crate::common::*;
use crate::garble::*;
use crate::instrument;
use crate::instrument::E_PROT_COLOR;
use crate::ot::apricot_avx2 as apricot;
use crate::ot::chou_orlandi;
use crate::ot::common::Message as MessagePair;
use crate::ot::common::*;
use crate::util::*;
use crate::wires::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct HalfKey(pub WireBytes);
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Key(pub WireBytes);

impl HalfKey {
    pub fn garbler(password: &[u8], threshold: u16, ch: &TChannel) -> Result<Self, Error> {
        instrument::begin("Garbler", E_PROT_COLOR);

        let password = u8_vec_to_bool_vec(password);
        let n = password.len();

        // Building circuit
        let circuit = build_circuit(n, threshold);
        let (gc, e, d) = garble(&circuit);

        let e = BinaryEncodingKey::from(e).zipped();
        let e_own = e[..n].to_vec(); //.iter().map(|[w0, w1]| [w0.as_ref(), w1.as_ref()]).collect();
        let e_theirs = e[n..].to_vec(); // encoding for receiver's password'
        let e_theirs: Vec<_> = e_theirs
            .iter()
            .map(|[w0, w1]| [w0.to_bytes().to_vec(), w1.to_bytes().to_vec()])
            .collect();

        let msg = MessagePair::from_zipped(&e_theirs);
        let ot = apricot::Sender {
            bootstrap: Box::new(chou_orlandi::Receiver),
        };
        ot.exchange(&msg, ch)?;
        let (s, _) = ch;

        // send garbled circuit.
        s.send_raw(&bincode::serialize(&gc)?)?;

        let e_own = BinaryEncodingKey::unzipped(&e_own);
        let enc_password = e_own.encode(&password);
        // send garbled password.
        s.send_raw(&bincode::serialize(&enc_password)?)?;

        instrument::end();
        Ok(Self(d.hashes[0][1]))
    }

    pub fn evaluator(password: &[u8], ch: &TChannel) -> Result<Self, Error> {
        instrument::begin("Evaluator", E_PROT_COLOR);

        let password = u8_vec_to_bool_vec(password);
        let ot = apricot::Receiver {
            bootstrap: Box::new(chou_orlandi::Sender),
        };
        let enc_password = ot.exchange(&password, ch)?;
        let (_, r) = ch;

        let enc_password: Vec<Wire> = enc_password
            .iter()
            .map(|b| to_array(b))
            .map(|b: [u8; 32]| Wire::from_array(b, Domain::Binary))
            .collect();

        let our_password = enc_password;
        // receive garbled circuit.
        let gc = bincode::deserialize(&r.recv_raw()?)?;
        // receive garbled password.
        let their_password: Vec<Wire> = bincode::deserialize(&r.recv_raw()?)?;

        // eval circuit
        let mut input = Vec::<Wire>::new();
        input.extend(their_password);
        input.extend(our_password);
        let output = evaluate(&gc, &input);

        instrument::end();
        Ok(Self(hash!(
            (gc.circuit.num_wires - 1).to_be_bytes(),
            1u16.to_be_bytes(),
            &output[0]
        )))
    }

    pub fn combine(self, other: Self) -> Key {
        Key(xor(self.0, other.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::Circuit;
    use mock::new_local_channel;

    #[test]
    fn test_fpake_api() {
        use std::thread;

        let password = b"password";
        let threshold = 0;

        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s2, r1);
        let ch2 = (s1, r2);
        let h1 = thread::spawn(move || {
            // Party 1
            let k1 = HalfKey::garbler(password, threshold, &ch1).unwrap();
            let k2 = HalfKey::evaluator(password, &ch1).unwrap();
            k1.combine(k2)
        });

        let h2 = thread::spawn(move || {
            // Party 2
            let k2 = HalfKey::evaluator(password, &ch2).unwrap();
            let k1 = HalfKey::garbler(password, threshold, &ch2).unwrap();
            k1.combine(k2)
        });

        let k1 = h1.join().unwrap();
        let k2 = h2.join().unwrap();
        assert_eq!(k1, k2);
    }

    fn garble_encode_eval_decode(c: &Circuit, x: &[u16]) -> Vec<u16> {
        let (gc, e, d) = garble(c);
        let x = encode(&e, x);
        let z = evaluate(&gc, &x);
        decode(&d, &z).unwrap()
    }

    #[test]
    fn simple_test() {
        let circuit = build_circuit(16, 2);
        println!("{:?}", circuit);
        let x = vec![
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 0,
        ];
        let res = garble_encode_eval_decode(&circuit, &x);
        assert!(res[0] == 1);
    }
}
