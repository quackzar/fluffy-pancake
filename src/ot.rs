// Library for fast OT.
// use curve25519_dalek::edwards;
#![allow(unused_imports)]
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::edwards::{EdwardsPoint,CompressedEdwardsY};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::hash;

// Common
pub type CiphertextPair = [Vec<u8>; 2];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload(Vec<CiphertextPair>);


pub type PlaintextPair = [Vec<u8>; 2];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message(Vec<PlaintextPair>);

impl Message {
    pub fn new(msg : &[PlaintextPair]) -> Message {
        Message(msg.to_vec())
    }

    pub fn from(msg : &[[&[u8]; 2]]) -> Message {
        let mut vec = Vec::with_capacity(msg.len());
        for m in msg {
            let m0 = m[0].to_vec();
            let m1 = m[1].to_vec();
            let pair : PlaintextPair = [m0, m1];
            vec.push(pair);
        }
        Message(vec)
    }

}


#[derive(Debug, Clone)]
pub struct Public(Vec<CompressedEdwardsY>);

impl From<&[[u8; 32]]> for Public {
    fn from(bytes : &[[u8; 32]]) -> Public {
        let mut vec = Vec::with_capacity(bytes.len());
        for b in bytes {
            let p = CompressedEdwardsY::from_slice(b);
            vec.push(p);
        }
        Public(vec)
    }
}

// === Sender ====
pub struct ObliviousSender {
    secrets: Vec<Scalar>,
    publics: Public,
    messages: Message,
}

impl ObliviousSender {
    pub fn new(messages: &Message) -> Self {
        // FUTURE: Take randomness as input.
        let n = messages.0.len();
        let mut rng = ChaCha12Rng::from_entropy();
        let secrets = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
        let publics = secrets
            .iter()
            .map(|secret| &ED25519_BASEPOINT_TABLE * secret)
            .map(|public| public.compress())
            .collect::<Vec<_>>();
        let secrets = secrets.try_into().unwrap();
        let publics = Public(publics.try_into().unwrap());
        Self {
            secrets,
            publics,
            messages: messages.clone(),
        }
    }

    pub fn public(&self) -> Public {
        self.publics.clone()
    }

    pub fn accept(&self, their_public: &Public) -> Payload {
        let n = self.messages.0.len();
        let secrets = &self.secrets;
        let publics = &self.publics;
        let messages = &self.messages;
        let mut payload: Vec<[Vec<u8>; 2]> = Vec::with_capacity(n);
        for i in 0..n {
            // TODO: Use maybe uninit.
            // TODO: Proper error handling.
            let their_public = &their_public.0[i].decompress().unwrap();
            let public = &publics.0[i].decompress().unwrap();
            let secret = &secrets[i];
            let [m0, m1] = &messages.0[i];

            // Compute the two shared keys.
            let mut hasher = Sha256::new();
            hasher.update((their_public * secret).to_montgomery().as_bytes());
            let k0 = hasher.finalize();
            let mut hasher = Sha256::new();
            hasher.update(
                ((their_public - public) * secret)
                    .to_montgomery()
                    .as_bytes(),
            );
            let k1 = hasher.finalize();

            // Encrypt the messages.
            // TODO: Error handling
            let cipher = Aes256Gcm::new(Key::from_slice(&k0));
            let nonce = Nonce::from_slice(b"unique nonce");
            let e0 = cipher.encrypt(nonce, m0.as_slice()).unwrap().to_vec();
            let cipher = Aes256Gcm::new(Key::from_slice(&k1));
            let nonce = Nonce::from_slice(b"unique nonce");
            let e1 = cipher.encrypt(nonce, m1.as_slice()).unwrap().to_vec();

            payload.push([e0, e1]);
        }
        Payload(payload.try_into().unwrap())
    }
}

// === Receiver ===

pub struct Init;

pub struct RetrievingPayload {
    keys: Vec<Vec<u8>>,
    publics: Public,
}

pub struct ObliviousReceiver<S> {
    state: S,
    secrets: Vec<Scalar>,
    choices: Vec<bool>,
}

impl ObliviousReceiver<Init> {
    pub fn new(choices: &[bool]) -> Self {
        // FUTURE: Take randomness as input.
        let n = choices.len();
        let mut rng = ChaCha12Rng::from_entropy();
        let secrets = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
        let secrets = secrets.try_into().unwrap();
        let choices = choices.to_vec();
        Self {
            state: Init,
            secrets,
            choices,
        }
    }

    pub fn accept(&self, their_publics: &Public) -> ObliviousReceiver<RetrievingPayload> {
        let n = their_publics.0.len();
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(n);
        let mut publics = Vec::with_capacity(n);
        for i in 0..n {
            // TODO: Use maybe uninit
            let their_public = their_publics.0[i].decompress().unwrap();
            let public = if self.choices[i] {
                their_public + (&ED25519_BASEPOINT_TABLE * &self.secrets[i])
            } else {
                &ED25519_BASEPOINT_TABLE * &self.secrets[i]
            };
            let mut hasher = Sha256::new();
            hasher.update(
                (their_public * self.secrets[i])
                    .to_montgomery()
                    .as_bytes(),
            );
            let key = hasher.finalize().to_vec();
            keys.push(key);
            publics.push(public.compress());
        }
        let keys = keys;
        let publics = Public(publics);

        ObliviousReceiver {
            state: RetrievingPayload { keys, publics },
            secrets: self.secrets.clone(),
            choices: self.choices.clone(),
        }
    }
}

impl ObliviousReceiver<RetrievingPayload> {
    pub fn public(&self) -> Public {
        self.state.publics.clone()
    }

    pub fn receive(&self, payload: &Payload) -> Vec<Vec<u8>> {
        let n = payload.0.len();
        let mut messages: Vec<Vec<u8>> = Vec::with_capacity(n);
        for i in 0..n {
            let [e0, e1] = &payload.0[i];
            let key = Key::from_slice(&self.state.keys[i]);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(b"unique nonce"); // HACK: hardcoded, has to be 96-bit.
            let m = cipher
                .decrypt(nonce, (if self.choices[i] { e1 } else { e0 }).as_ref())
                .unwrap();
            messages.push(m);
        }
        messages.try_into().unwrap()
    }
}

// 1-to-n extensions for OT :D
// https://dl.acm.org/doi/pdf/10.1145/301250.301312
fn xor_bytes(left: &mut [u8; 32], right: &[u8; 32]) {
    for i in 0..32 {
        left[i] ^= right[i];
    }
}

fn fk(key: &[u8; 32], choice: u16) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(choice.to_be_bytes());
    hasher.update(key);
    let result = hasher.finalize();
    return <[u8; 32]>::try_from(result.as_ref()).unwrap();
}

// How to 1-to-n:
// 1. Initiate
// 2. Challenge respond
// 3. Choose
// 4. Finish

const WIRE_BYTES: usize = 32;

// Bob: Initiate 1-to-n OT (initiated by the sender, Bob):
// - Prepares keys and uses these to generate the required y values sent to Alice
// - Creates challenges for Alice
fn one_to_n_challenge_create(domain: u16, messages: &Vec<[u8; WIRE_BYTES]>) -> (Vec<ObliviousSender>, Vec<Public>, Vec<[u8; WIRE_BYTES]>)
{
    // 1. B: Prepare random keys
    let l = messages.len();
    debug_assert!(l == (1 << domain));

    let mut rng = ChaCha12Rng::from_entropy();
    let mut keys: Vec<[[u8; WIRE_BYTES]; 2]> = Vec::with_capacity(l);
    for i in 0..l {
        let left = Scalar::random(&mut rng).to_bytes();
        let right = Scalar::random(&mut rng).to_bytes();

        keys.push([left, right]);
    }

    let domain_max = 1 << domain; // 2^domain
    let mut y = Vec::with_capacity(domain_max);
    for i in 0..domain_max {
        let mut value = messages[i];
        for j in 0..domain {
            let bit = (i & (1 << j)) >> j;
            let hash = fk(&keys[j as usize][bit as usize], i as u16);
            xor_bytes(&mut value, &hash);
        }

        y.push(value);
    }

    // 2. Initiate 1-out-of-2 OTs by sending challenges
    let mut senders = Vec::with_capacity(l);
    let mut challenges = Vec::with_capacity(l);
    for i in 0..l {
        let m0 = keys[i as usize][0].to_vec();
        let m1 = keys[i as usize][1].to_vec();

        let message = Message::new(&[[m0, m1]]);
        let sender = ObliviousSender::new(&message);

        challenges.push(sender.public());
        senders.push(sender);
    }

    return (senders, challenges, y);
}

// Alice: Respond to challenge from Bob
// - Setup receivers
// - Create responses for Bob
fn one_to_n_challenge_respond(domain: u16, choice: u16, challenges: &Vec<Public>) -> (Vec<ObliviousReceiver<RetrievingPayload>>, Vec<Public>) {
    let l = 1 << domain;

    println!();
    let mut initial_receivers = Vec::with_capacity(l);
    for i in 0..l {
        let bit = (choice & (1 << i)) >> i;
        let receiver = ObliviousReceiver::new(&[bit == 1]);
        initial_receivers.push(receiver);
    }

    // NOTE: This assume we get them in order!
    debug_assert!(initial_receivers.len() == challenges.len());
    debug_assert!(challenges.len() == l);
    let mut responses = Vec::with_capacity(l);
    let mut receivers = Vec::with_capacity(l);
    for i in 0..l {
        let receiver = initial_receivers[i].accept(&challenges[i]);
        responses.push(receiver.public());
        receivers.push(receiver);
    }

    return (receivers, responses);
}

// Bob: Create payloads for Alice
fn one_to_n_create_payloads(domain: u16, senders: &Vec<ObliviousSender>, responses: &Vec<Public>) -> Vec<Payload> {
    let l = 1 << domain;

    let mut payloads: Vec<Payload> = Vec::with_capacity(l);
    debug_assert!(responses.len() == l);
    for i in 0..l {
        let payload = senders[i].accept(&responses[i]);
        payloads.push(payload);
    }

    // 3. B: Send the strings Y to A
    return payloads;
}

// Alice: Chose a value
fn one_to_n_choose(domain: u16, choice: u16, receivers: &Vec<ObliviousReceiver<RetrievingPayload>>, payloads: &Vec<Payload>, y: &Vec<[u8; WIRE_BYTES]>) -> [u8; 32] {
    let l = 1 << domain;

    println!();

    // Convert payloads to keys
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(l);
    for i in 0..l {
        let messages = receivers[i].receive(&payloads[i]);
        let message = &messages[0];
        debug_assert!(messages.len() == 1);
        debug_assert!(message.len() == WIRE_BYTES);

        let mut key = [0u8; WIRE_BYTES];
        for j in 0..WIRE_BYTES {
            key[j] = message[j];
        }

        keys.push(key);
    }

    // Reconstruct X from keys and choice
    let mut x = y[choice as usize];
    for i in 0..domain {
        let hash = fk(&keys[i as usize], choice);
        xor_bytes(&mut x, &hash);
    }

    return x;
}

#[cfg(test)]
mod tests {
    use crate::util::log2;
    use super::*;

    #[test]
    fn test_1_to_n() {
        let n = 8u8;
        let domain = log2(n) as u16;
        let mut messages = Vec::with_capacity(n as usize);
        for i in 0u8..n {
            messages.push([i; WIRE_BYTES]);
        }
        let choice = 4;

        // Initiate the OT by creating and responding to challenges
        let (senders, challenges, y) = one_to_n_challenge_create(domain, &messages);
        let (receivers, responses) = one_to_n_challenge_respond(domain, choice, &challenges);

        // Bob: Creates payloads for Alice
        let payloads = one_to_n_create_payloads(domain, &senders, &responses);

        // Alice: Choose a value
        let output = one_to_n_choose(domain, choice, &receivers, &payloads, &y);

        // Check that we actually got the thing we wanted
        for i in 0..WIRE_BYTES {
            assert_eq!(messages[choice as usize][i], output[i]);
        }
    }

    #[test]
    fn test_ot_protocol_zero() {
        let m0 = b"Hello, world!".to_vec();
        let m1 = b"Hello, sweden!".to_vec();

        // round 0
        let receiver = ObliviousReceiver::new(&[false]);
        let sender = ObliviousSender::new(&Message(vec![[m0.clone(), m1.clone()]]));

        // round 1
        let receiver = receiver.accept(&sender.public());

        // round 2
        let payload = sender.accept(&receiver.public());

        let msg = receiver.receive(&payload);

        assert!(msg[0] == m0);
    }

    #[test]
    fn test_ot_protocol_one() {
        let m0 = b"Hello, world!".to_vec();
        let m1 = b"Hello, sweden!".to_vec();

        // round 0
        let receiver = ObliviousReceiver::new(&[true]);
        let sender = ObliviousSender::new(&Message(vec![[m0.clone(), m1.clone()]]));

        // round 1
        let receiver = receiver.accept(&sender.public());

        // round 2
        let payload = sender.accept(&receiver.public());

        let msg = receiver.receive(&payload);

        assert!(msg[0] == m1);
    }

    #[test]
    fn test_n_ots() {
        let m : [[Vec<u8>; 2]; 5] = [
           [vec![1], vec![6]],
           [vec![2], vec![7]],
           [vec![3], vec![8]],
           [vec![4], vec![9]],
           [vec![5], vec![10]],
        ];

        let msg = Message::new(&m);

        let c = [true, false, true, false, true];
        let receiver = ObliviousReceiver::new(&c);
        let sender = ObliviousSender::new(&msg);

        // round 1
        let receiver = receiver.accept(&sender.public());

        // round 2
        let payload = sender.accept(&receiver.public());

        let msg = receiver.receive(&payload);
        for m in &msg {
            println!("{:?}", m);
        }
        for (i,&b) in c.iter().enumerate() {
            assert!(msg[i] == m[i][b as usize],
                "b={} has {:?} =! {:?} at i={}", b, msg[i], m[i][b as usize], i);
        }
    }

    #[allow(non_snake_case)]
    #[test]
    fn oblivious_transfer() {
        let mut rng = ChaCha12Rng::from_entropy();
        let m0 = vec![0; 8];
        let m1 = vec![1; 8];
        let c = 0; // Choice

        let g = &ED25519_BASEPOINT_TABLE;
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let A = g * &a;
        let B = if c == 0 { g * &b } else { A + (g * &b) }; // send B back to sender.
        let mut hasher = Sha256::new();
        hasher.update((B * a).to_montgomery().as_bytes());
        let k0 = hasher.finalize();
        let mut hasher = Sha256::new();
        hasher.update(((B - A) * a).to_montgomery().as_bytes());
        let k1 = hasher.finalize();

        let cipher = Aes256Gcm::new(Key::from_slice(&k0));
        let nonce = Nonce::from_slice(b"unique nonce");
        let e0 = cipher.encrypt(nonce, m0.as_slice()).unwrap();
        let cipher = Aes256Gcm::new(Key::from_slice(&k1));
        let nonce = Nonce::from_slice(b"unique nonce");
        let e1 = cipher.encrypt(nonce, m1.as_slice()).unwrap();

        // send the e0, e1 to receiver.
        let mut hasher = Sha256::new();
        hasher.update((A * b).to_montgomery().as_bytes());
        let kR = hasher.finalize();

        let key = Key::from_slice(&kR);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(b"unique nonce");
        let m_c = if c == 0 {
            cipher.decrypt(nonce, e0.as_ref()).unwrap()
        } else {
            cipher.decrypt(nonce, e1.as_ref()).unwrap()
        };
        assert_eq!(m_c, m0);
    }

    #[allow(non_snake_case)]
    #[test]
    fn diffie_hellman() {
        let mut rng = ChaCha12Rng::from_entropy();
        let g = &ED25519_BASEPOINT_TABLE;
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let g_a = (g * &a).to_montgomery();
        let g_b = (g * &b).to_montgomery();
        let g_ab = g_a * b;
        let g_ba = g_b * a;
        let mut hasher = Sha256::new();
        hasher.update(g_ab.as_bytes());
        let k_A = hasher.finalize();
        let mut hasher = Sha256::new();
        hasher.update(g_ba.as_bytes());
        let k_B = hasher.finalize();

        // key encryption test.
        let key = Key::from_slice(&k_A);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(b"unique nonce");
        let ciphertext = cipher.encrypt(nonce, b"Hello!".as_ref()).unwrap();

        // key decryption test.
        let key = Key::from_slice(&k_B);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(b"unique nonce");
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        let plaintext = std::str::from_utf8(&plaintext).unwrap();
        assert_eq!(plaintext, "Hello!");
    }
}
