// Library for fast OT.
// use curve25519_dalek::edwards;
#![allow(unused_imports)]
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Common
type CiphertextPair = [Vec<u8>; 2];
#[derive(Debug, Clone)]
pub struct Payload<const N: usize>([CiphertextPair; N]);


type PlaintextPair = [Vec<u8>; 2];
#[derive(Debug, Clone)]
pub struct Message<const N: usize>([PlaintextPair; N]);

impl<const N : usize> Message<N> {
    pub fn new(msg : [CiphertextPair; N]) -> Message<N> {
        Message(msg)
    }
}

#[derive(Debug, Clone)]
pub struct Public<const N: usize>([EdwardsPoint; N]);

// === Sender ====
pub struct ObliviousSender<const N: usize> {
    secrets: [Scalar; N],
    publics: Public<N>,
    messages: Message<N>,
}

impl<const N: usize> ObliviousSender<N> {
    pub fn new(messages: &Message<N>) -> Self {
        // FUTURE: Take randomness as input.
        let mut rng = ChaCha12Rng::from_entropy();
        let secrets = (0..N).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
        let publics = secrets
            .iter()
            .map(|secret| &ED25519_BASEPOINT_TABLE * secret)
            .collect::<Vec<_>>();
        let secrets = secrets.try_into().unwrap();
        let publics = Public(publics.try_into().unwrap());
        Self {
            secrets,
            publics,
            messages: messages.clone(),
        }
    }

    pub fn public(&self) -> Public<N> {
        self.publics.clone()
    }

    pub fn accept(&self, their_public: &Public<N>) -> Payload<N> {
        let secrets = self.secrets;
        let publics = &self.publics;
        let messages = &self.messages;
        let mut payload: Vec<[Vec<u8>; 2]> = Vec::with_capacity(N);
        for i in 0..N {
            // TODO: Use maybe uninit
            let their_public = &their_public.0[i];
            let public = &publics.0[i];
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

pub struct RetrievingPayload<const N: usize> {
    keys: [Vec<u8>; N],
    publics: Public<N>,
}

pub struct ObliviousReceiver<S, const N: usize> {
    state: S,
    secrets: [Scalar; N],
    choices: [bool; N],
}

impl<const N: usize> ObliviousReceiver<Init, N> {
    pub fn new(choices: [bool; N]) -> Self {
        // FUTURE: Take randomness as input.
        let mut rng = ChaCha12Rng::from_entropy();
        let secrets = (0..N).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
        let secrets = secrets.try_into().unwrap();
        Self {
            state: Init,
            secrets,
            choices,
        }
    }

    pub fn accept(&self, their_publics: &Public<N>) -> ObliviousReceiver<RetrievingPayload<N>, N> {
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(N);
        let mut publics: Vec<EdwardsPoint> = Vec::with_capacity(N);
        for i in 0..N {
            // TODO: Use maybe uninit
            let public = if self.choices[i] {
                their_publics.0[i] + (&ED25519_BASEPOINT_TABLE * &self.secrets[i])
            } else {
                &ED25519_BASEPOINT_TABLE * &self.secrets[i]
            };
            let mut hasher = Sha256::new();
            hasher.update(
                (their_publics.0[i] * self.secrets[i])
                    .to_montgomery()
                    .as_bytes(),
            );
            let key = hasher.finalize().to_vec();
            keys.push(key);
            publics.push(public);
        }
        let keys = keys.try_into().unwrap();
        let publics = Public(publics.try_into().unwrap());

        ObliviousReceiver {
            state: RetrievingPayload { keys, publics },
            secrets: self.secrets,
            choices: self.choices,
        }
    }
}

impl<const N: usize> ObliviousReceiver<RetrievingPayload<N>, N> {
    pub fn public(&self) -> Public<N> {
        self.state.publics.clone()
    }

    pub fn receive(&self, payload: &Payload<N>) -> [Vec<u8>; N] {
        let mut messages: Vec<Vec<u8>> = Vec::with_capacity(N);
        for i in 0..N {
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_ot_protocol_zero() {
        let m0 = b"Hello, world!".to_vec();
        let m1 = b"Hello, sweden!".to_vec();

        // round 0
        let receiver = ObliviousReceiver::new([false]);
        let sender = ObliviousSender::new(&Message([[m0.clone(), m1.clone()]]));

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
        let receiver = ObliviousReceiver::new([true]);
        let sender = ObliviousSender::new(&Message([[m0.clone(), m1.clone()]]));

        // round 1
        let receiver = receiver.accept(&sender.public());

        // round 2
        let payload = sender.accept(&receiver.public());

        let msg = receiver.receive(&payload);

        assert!(msg[0] == m1);
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
