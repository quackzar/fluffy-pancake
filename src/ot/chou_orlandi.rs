// Library for fast OT.
// use curve25519_dalek::edwards;
#![allow(unused_imports)]
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use crate::hash;
use crate::util::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use rayon::prelude::*;

// Common
pub type CiphertextPair = [Vec<u8>; 2];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload(Vec<CiphertextPair>);

pub type PlaintextPair = [Vec<u8>; 2];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message(Vec<PlaintextPair>);

impl Message {
    pub fn new(msg: &[PlaintextPair]) -> Message {
        Message(msg.to_vec())
    }

    pub fn from(msg: &[[&[u8]; 2]]) -> Message {
        let mut vec = Vec::with_capacity(msg.len());
        for m in msg {
            let m0 = m[0].to_vec();
            let m1 = m[1].to_vec();
            let pair: PlaintextPair = [m0, m1];
            vec.push(pair);
        }
        Message(vec)
    }
}

#[derive(Debug, Clone)]
pub struct Public(Vec<CompressedEdwardsY>);

impl From<&[WireBytes]> for Public {
    fn from(bytes: &[WireBytes]) -> Public {
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
            .par_iter()
            .map(|secret| &ED25519_BASEPOINT_TABLE * secret)
            .map(|public| public.compress())
            .collect::<Vec<_>>();
        let publics = Public(publics);
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
        let secrets = &self.secrets;
        let publics = &self.publics;
        assert!(publics.0.len() == their_public.0.len());
        let messages = &self.messages;
        let payload = messages
            .0
            .par_iter()
            .enumerate()
            .map(|(i, [m0, m1])| -> CiphertextPair {
                let their_public = &their_public.0[i].decompress().unwrap();
                let public = &publics.0[i].decompress().unwrap();
                let secret = &secrets[i];

                // Compute the two shared keys.
                let mut hasher = Sha256::new();
                hasher.update((their_public * secret).compress().as_bytes());
                let k0 = hasher.finalize();
                let mut hasher = Sha256::new();
                hasher.update(((their_public - public) * secret).compress().as_bytes());
                let k1 = hasher.finalize();

                // Encrypt the messages.
                // TODO: Error handling
                let cipher = Aes256Gcm::new(Key::from_slice(&k0));
                let nonce = Nonce::from_slice(b"unique nonce"); // TODO: Something with nonce.
                let e0 = cipher.encrypt(nonce, m0.as_slice()).unwrap().to_vec();
                let cipher = Aes256Gcm::new(Key::from_slice(&k1));
                let nonce = Nonce::from_slice(b"unique nonce");
                let e1 = cipher.encrypt(nonce, m1.as_slice()).unwrap().to_vec();
                [e0, e1]
            })
            .collect();
        Payload(payload)
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
        let choices = choices.to_vec();
        Self {
            state: Init,
            secrets,
            choices,
        }
    }

    pub fn accept(&self, their_publics: &Public) -> ObliviousReceiver<RetrievingPayload> {
        assert!(self.choices.len() == their_publics.0.len());
        let (publics, keys): (Vec<CompressedEdwardsY>, _) = their_publics
            .0
            .par_iter()
            .enumerate()
            .map(|(i, p)| -> (CompressedEdwardsY, Vec<u8>) {
                let their_public = &p.decompress().unwrap();
                let public = if self.choices[i] {
                    their_public + (&ED25519_BASEPOINT_TABLE * &self.secrets[i])
                } else {
                    &ED25519_BASEPOINT_TABLE * &self.secrets[i]
                };
                let mut hasher = Sha256::new();
                hasher.update((their_public * self.secrets[i]).compress().as_bytes());
                let key = hasher.finalize().to_vec();

                (public.compress(), key)
            })
            .unzip();
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
        assert!(self.choices.len() == payload.0.len());
        payload
            .0
            .par_iter()
            .enumerate()
            .map(|(i, [e0, e1])| -> Vec<u8> {
                let key = Key::from_slice(&self.state.keys[i]);
                let cipher = Aes256Gcm::new(key);
                let nonce = Nonce::from_slice(b"unique nonce"); // HACK: hardcoded, has to be 96-bit.
                cipher
                    .decrypt(nonce, (if self.choices[i] { e1 } else { e0 }).as_ref())
                    .expect("Failed to decrypt")
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{log2, LENGTH};

    #[test]
    fn test_ot_protocol_zero() {
        let m0 = b"Hello, world!".to_vec();
        let m1 = b"Hello, sweden!".to_vec();

        // round 0
        let receiver = ObliviousReceiver::new(&[false]);
        let sender = ObliviousSender::new(&Message(vec![[m0.clone(), m1]]));

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
        let sender = ObliviousSender::new(&Message(vec![[m0, m1.clone()]]));

        // round 1
        let receiver = receiver.accept(&sender.public());

        // round 2
        let payload = sender.accept(&receiver.public());

        let msg = receiver.receive(&payload);

        assert!(msg[0] == m1);
    }

    #[test]
    fn test_n_ots() {
        let m: [[Vec<u8>; 2]; 5] = [
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
        for (i, &b) in c.iter().enumerate() {
            assert!(
                msg[i] == m[i][b as usize],
                "b={} has {:?} =! {:?} at i={}",
                b,
                msg[i],
                m[i][b as usize],
                i
            );
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
