// Library for fast OT.
// use curve25519_dalek::edwards;
#![allow(unused_imports)]
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use bincode::deserialize;
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

use rand::{Rng, SeedableRng};
use rand_chacha::{ChaCha12Rng, ChaCha20Rng};
use serde::de::Visitor;

use crate::hash;
use crate::util::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use rayon::prelude::*;

use crate::common::*;
use crate::ot::common::*;

// Channel Impl.
pub struct OTSender;
pub struct OTReceiver;

impl ObliviousSender for OTSender {
    fn exchange(&self, msg: &Message, ch: &Channel<Vec<u8>>) -> Result<(), Error> {
        let pb = TransactionProperties {
            msg_size: msg.len(),
            protocol: "Chou-Orlandi".to_string(),
        };
        validate_properties(&pb, ch)?;
        let (s, r) = ch;

        let n = msg.0.len();
        let mut rng = ChaCha12Rng::from_entropy();
        let secrets = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
        let publics = secrets
            .par_iter()
            .map(|secret| &ED25519_BASEPOINT_TABLE * secret)
            .map(|public| public.compress())
            .collect::<Vec<_>>();
        let publics = Public(publics);

        // round 1
        let pbs = publics.0.iter().map(|&p| p.to_bytes());
        for pb in pbs {
            s.send(pb.to_vec())?;
        }

        // round 2
        let n = msg.0.len();
        let pb = (0..n)
            .map(|_| r.recv().unwrap())
            .map(|p| CompressedEdwardsY::from_slice(&p))
            .collect();
        let pb = Public(pb);

        // round 3
        let their_public = &pb;
        assert!(publics.0.len() == their_public.0.len());
        let payload : Vec<_> = msg
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
                let mut stream = ChaCha20Rng::from_seed(k0.try_into().unwrap());
                let size = m0.len();
                let cipher: Vec<u8> = (0..size).map(|_| stream.gen::<u8>()).collect();
                let e0 = xor_bytes(m0, &cipher);

                let mut stream = ChaCha20Rng::from_seed(k1.try_into().unwrap());
                let size = m1.len();
                let cipher: Vec<u8> = (0..size).map(|_| stream.gen::<u8>()).collect();
                let e1 = xor_bytes(m1, &cipher);
                [e0, e1]
            })
            .collect();

        let msg = bincode::serialize(&payload)?;
        s.send(msg)?;
        Ok(())
    }
}

impl ObliviousReceiver for OTReceiver {
    fn exchange(&self, choices: &[bool], ch: &Channel<Vec<u8>>) -> Result<Payload, Error> {
        let pb = TransactionProperties {
            msg_size: choices.len(),
            protocol: "Chou-Orlandi".to_string(),
        };
        validate_properties(&pb, ch)?;
        let (s, r) = ch;

        let n = choices.len();
        let mut rng = ChaCha12Rng::from_entropy();
        let secrets = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
        let choices = choices.to_vec();

        // round 1
        let pb = (0..n)
            .map(|_| r.recv().unwrap())
            .map(|p| CompressedEdwardsY::from_slice(&p))
            .collect();
        let their_publics = Public(pb);

        debug_assert_eq!(choices.len(), their_publics.0.len());
        let (publics, keys): (Vec<CompressedEdwardsY>, Vec<_>) = their_publics
            .0
            .par_iter()
            .enumerate()
            .map(|(i, p)| -> (CompressedEdwardsY, [u8; 32]) {
                let their_public = &p.decompress().unwrap();
                let public = if choices[i] {
                    their_public + (&ED25519_BASEPOINT_TABLE * &secrets[i])
                } else {
                    &ED25519_BASEPOINT_TABLE * &secrets[i]
                };
                let mut hasher = Sha256::new();
                hasher.update((their_public * secrets[i]).compress().as_bytes());
                let key: [u8; 32] = hasher.finalize().try_into().unwrap();

                (public.compress(), key)
            })
            .unzip();
        let publics = Public(publics);

        // round 2
        let pbs = publics.0.iter().map(|&p| p.to_bytes());
        for pb in pbs {
            s.send(pb.to_vec())?;
        }

        // round 3
        let payload = r.recv()?;
        let payload : EncryptedPayload = bincode::deserialize(&payload)?;

        let msg = payload
            .0
            .par_iter()
            .enumerate()
            .map(|(i, [e0, e1])| -> Vec<u8> {
                let e = if choices[i] { e1 } else { e0 };
                let k = keys[i];
                let mut stream = ChaCha20Rng::from_seed(k);
                let size = e.len();
                let cipher: Vec<u8> = (0..size).map(|_| stream.gen::<u8>()).collect();
                xor_bytes(e, &cipher)
            })
            .collect();

        Ok(msg)

    }
}

// Old (state-machine) Impl.

#[derive(Debug, Clone)]
pub struct Public(Vec<CompressedEdwardsY>);

impl Serialize for Public {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        for p in &self.0 {
            bytes.extend_from_slice(p.as_bytes());
        }
        serializer.serialize_bytes(&bytes)
    }
}

struct PublicVisitor;

impl<'de> Visitor<'de> for PublicVisitor {
    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut vec = Vec::with_capacity(v.len() / 32);
        for i in 0..v.len() / 32 {
            let p = CompressedEdwardsY::from_slice(&v[i * 32..(i + 1) * 32]);
            vec.push(p);
        }
        Ok(Public(vec))
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bytes(v)
    }

    type Value = Public;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a very special map")
    }
}

impl<'de> Deserialize<'de> for Public {
    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Default implementation just delegates to `deserialize` impl.
        *place = Deserialize::deserialize(deserializer)?;
        Ok(())
    }

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PublicVisitor)
    }
}

pub type CiphertextPair = [Vec<u8>; 2];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload(pub Vec<CiphertextPair>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{log2, LENGTH};

    #[test]
    fn test_channel_version() {
        let (s1, r1) = ductile::new_local_channel();
        let (s2, r2) = ductile::new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);

        use std::thread;
        let h1 = thread::spawn(move || {
            let sender = OTSender;
            let msg = Message::from_unzipped(&[b"Hello"], &[b"World"]);
            sender.exchange(&msg, &ch1).unwrap();
        });

        let h2 = thread::spawn(move || {
            let receiver = OTReceiver;
            let choices = [true];
            let msg = receiver.exchange(&choices, &ch2).unwrap();
            assert_eq!(msg[0], b"World");
        });

        h1.join().unwrap();
        h2.join().unwrap();
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

    #[test]
    fn test_public_serialize() {
        let public = Public(
            (0..8)
                .map(|i| CompressedEdwardsY::from_slice(&[i; 32]))
                .collect(),
        );
        let serialized = bincode::serialize(&public).unwrap();
        let deserialized: Public = bincode::deserialize(&serialized).unwrap();
        for (p0, p1) in public.0.iter().zip(deserialized.0.iter()) {
            assert_eq!(p0, p1);
        }
    }
}
