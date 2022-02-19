// Library for fast OT.
// use curve25519_dalek::edwards;
#![allow(unused_imports)]
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_TABLE, ED25519_BASEPOINT_TABLE};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
// use curve25519_dalek::edwards;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use sha2::{Digest, Sha256};

// TODO: Create protocol for this.

struct ObliviousSender<S> {
    state : S,
    secret: Scalar,
    m0: Vec<u8>,
    m1: Vec<u8>,
}

struct Init;

struct Receiving {
    public : EdwardsPoint,
}


struct Retrieving {
    public : EdwardsPoint,
    key: Vec<u8>,
}

struct Complete {
    e0 : Vec<u8>,
    e1 : Vec<u8>,
}

struct Done { m : Vec<u8> }

struct ObliviousReceiver<S> {
    state : S,
    secret: Scalar,
    choice: bool,
}

impl ObliviousSender<Receiving> {
    fn new(m0 : Vec<u8>, m1: Vec<u8> ) -> Self {
        // FUTURE: Take randomness as input.
        let mut rng = ChaCha12Rng::from_entropy();
        let secret = Scalar::random(&mut rng);
        let public = &ED25519_BASEPOINT_TABLE * &secret;
        Self {
            state: Receiving { public },
            secret,
            m0,
            m1,
        }
    }

    fn public(&self) -> EdwardsPoint {
        self.state.public
    }


    fn accept(&self, their_public : EdwardsPoint) -> ObliviousSender<Complete> {
        let secret = self.secret;
        let public = self.state.public;
        let m0 = &self.m0;
        let m1 = &self.m1;

        let mut hasher = Sha256::new();
        hasher.update((their_public * secret).to_montgomery().as_bytes());
        let k0 = hasher.finalize();
        let mut hasher = Sha256::new();
        hasher.update(((their_public - public) * secret).to_montgomery().as_bytes());
        let k1 = hasher.finalize();

        let cipher = Aes256Gcm::new(Key::from_slice(&k0));
        let nonce = Nonce::from_slice(b"unique nonce");
        let e0 = cipher.encrypt(nonce, m0.as_slice()).unwrap().to_vec();
        let cipher = Aes256Gcm::new(Key::from_slice(&k1));
        let nonce = Nonce::from_slice(b"unique nonce");
        let e1 = cipher.encrypt(nonce, m1.as_slice()).unwrap().to_vec();

        ObliviousSender {
            state: Complete{ e0, e1 },
            secret,
            m0: m0.clone(),
            m1: m1.clone(),
        }
    }
}

impl ObliviousReceiver<Init> {
    fn new(choice : bool) -> Self {
        // FUTURE: Take randomness as input.
        let mut rng = ChaCha12Rng::from_entropy();
        let secret = Scalar::random(&mut rng);
        Self {
            state: Init,
            secret,
            choice,
        }
    }
    
    fn accept(&self, their_public : EdwardsPoint) -> ObliviousReceiver<Retrieving>{
        let public = if self.choice {
            &ED25519_BASEPOINT_TABLE * &self.secret
        } else {
            their_public + (&ED25519_BASEPOINT_TABLE * &self.secret)
        };
        
        let mut hasher = Sha256::new();
        hasher.update((their_public * &self.secret).to_montgomery().as_bytes());
        let key = hasher.finalize().to_vec();
        ObliviousReceiver {
            state: Retrieving { public, key },
            secret: self.secret,
            choice: self.choice,
        }
    }
}

impl ObliviousReceiver<Retrieving> {

    fn public(&self) -> EdwardsPoint {
        self.state.public
    }

    fn receive(&self, e0 : Vec<u8>, e1 : Vec<u8>) -> ObliviousReceiver<Done> {
        let key = Key::from_slice(&self.state.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(b"unique nonce"); // HACK: hardcoded, has to be 96-bit.
        let m = if self.choice {
            cipher.decrypt(nonce, e1.as_ref()).unwrap()
        } else {
            cipher.decrypt(nonce, e0.as_ref()).unwrap()
        };
        ObliviousReceiver {
            state: Done { m },
            secret: self.secret,
            choice: self.choice,
        }
    }
}



#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_ot_protocol() {
        let m0 = b"Hello, world!";
        let m1 = b"Hello, sweden!";
        let receiver = ObliviousReceiver::new(true);
        let sender = ObliviousSender::new(m0.to_vec(), m1.to_vec());

        let receiver = receiver.accept(sender.public());
        let sender = sender.accept(receiver.public());

        let receiver = receiver.receive(sender.state.e0, sender.state.e1);

        assert!(receiver.state.m == m1.to_vec());
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
        let B = if c == 0 {
            g * &b
        } else {
            A + (g * &b)
        }; // send B back to sender.
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
        let nonce = Nonce::from_slice(b"unique nonce"); // HACK: hardcoded, has to be 96-bit.
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
        let nonce = Nonce::from_slice(b"unique nonce"); // HACK: hardcoded, has to be 96-bit.
        let ciphertext = cipher.encrypt(nonce, b"Hello!".as_ref()).unwrap();

        // key decryption test.
        let key = Key::from_slice(&k_B);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(b"unique nonce"); // HACK: hardcoded, has to be 96-bit.
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        let plaintext = std::str::from_utf8(&plaintext).unwrap();
        assert_eq!(plaintext, "Hello!");
    }
}
