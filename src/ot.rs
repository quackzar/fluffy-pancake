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

// // First message
// struct ObliviousInit {
//     g_a : MontgomeryPoint,
// }

// // Second message
// struct ObliviousRequest {
//     g_b : MontgomeryPoint,
// }

// // Third message
// struct ObliviousResponse {
//     e0 : Vec<u8>,
//     e1 : Vec<u8>,
// }

// #[derive(Debug)]
// struct SenderTranscript {
//     a : Scalar,
//     g_a : MontgomeryPoint,
//     m0 : Vec<u8>,
//     m1 : Vec<u8>,
// }


// fn generate_point() -> Scalar {
//     let mut rng = ChaCha12Rng::from_entropy();
//     Scalar::random(&mut rng) // INFO: Maybe use edwards or ristretto?
// }

// impl SenderTranscript {
//     pub fn new(m0 : Vec<u8>, m1 : Vec<u8>) -> SenderTranscript {
//         let g = &RISTRETTO_BASEPOINT_TABLE;
//         let a = generate_point();
//         let g_a = g * &a;
//         SenderTranscript {
//             a, g_a, m0, m1,
//         }
//     }

//     pub fn init(&self) -> ObliviousInit {
//         let g_a = self.g_a;
//         ObliviousInit { g_a }
//     }

//     pub fn retrieve(&self, ObliviousRequest { g_b }: ObliviousRequest) -> ObliviousResponse  {
//         let a = self.a;
//         let g_a = self.g_a;
//         let g = &RISTRETTO_BASEPOINT_TABLE;
//         let mut hasher = Sha256::new();
//         let g_ba = g_b * a;
//         hasher.update(g_ba);
//         let k0 = hasher.finalize();
//         let mut hasher = Sha256::new();
//         let g_ba = (g_b - g_a) * a;
//         hasher.update(g_ba);
//         let k1 = hasher.finalize();

//         // Encryption part
//         let m0 = &self.m0;
//         let m1 = &self.m1;

//         let cipher = Aes256Gcm::new(Key::from_slice(&k0));
//         let nonce = Nonce::from_slice(b"unique nonce");
//         let e0 = cipher.encrypt(nonce, m0.as_slice()).unwrap();
//         let cipher = Aes256Gcm::new(Key::from_slice(&k1));
//         let nonce = Nonce::from_slice(b"unique nonce");
//         let e1 = cipher.encrypt(nonce, m1.as_slice()).unwrap();
//         ObliviousResponse{e0, e1}
//     }
// }


// #[derive(Debug)]
// struct ReceiverTranscript {
//     b : Scalar,
//     g_b : MontgomeryPoint,
//     g_a : MontgomeryPoint,
//     c : bool,
// }

// impl ReceiverTranscript {
//     pub fn new(c : bool) -> ReceiverTranscript {
//         let g = &RISTRETTO_BASEPOINT_TABLE;
//         let b = generate_point();
//         let g_a = MontgomeryPoint::default();
//         let g_b = MontgomeryPoint::default();
//         ReceiverTranscript {
//             b, g_b, g_a, c,
//         }
//     }

//     pub fn request(&mut self, ObliviousInit { g_a }: ObliviousInit) -> ObliviousRequest {
//         let c = self.c;
//         let b = &self.b;
//         let g = &ED25519_BASEPOINT_TABLE;

//         let g_b = if c {
//             g * b
//         } else {
//             g_a + (g * b)
//         };
//         self.g_b = g_b;
//         self.g_a = g_a;
//         ObliviousRequest { g_b }
//     }

//     pub fn receive(&self, ObliviousResponse { e0, e1 }: ObliviousResponse) -> Vec<u8> {
//         let b = self.b;
//         let g_a = self.g_b;

//         // Decryption part
//         let mut hasher = Sha256::new();
//         hasher.update(g_a * b);
//         let k_r = hasher.finalize();

//         let e = if self.c {e1} else {e0};
//         let cipher = Aes256Gcm::new(Key::from_slice(&k_r));
//         let nonce = Nonce::from_slice(b"unique nonce");
//         println!("{:?}", self);
//         let m = cipher.decrypt(nonce, e.as_ref()).unwrap(); // TODO: Proper error handling.
//         m
//     }

// }

#[cfg(test)]
mod tests {

    use super::*;

    // #[allow(non_snake_case)]
    // #[test]
    // fn ot_api_test() {
    //     let m0 = b"Hello World!";
    //     let m1 = b"Hello Friend!";
    //     let c = false;
    //     let sender = SenderTranscript::new(m0.to_vec(), m1.to_vec());
    //     let mut receiver = ReceiverTranscript::new(c);
    //     let A = sender.init();
    //     let B = receiver.request(A);
    //     let e0e1 = sender.retrieve(B);
    //     let m = receiver.receive(e0e1);
    //     assert_eq!(m, m0);
    // }
    
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
