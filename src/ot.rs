// Library for fast OT.
// use curve25519_dalek::edwards;
use curve25519_dalek::scalar::Scalar;
// use curve25519_dalek::edwards;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};


use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use sha2::{Sha256, Digest};

// fn send(m0 : &[u8], m1 : &[u8]) {

// }

// fn receive(c : bool) -> [u8] {
//     
// }
//
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn diffie_hellman() {
        let mut rng = ChaCha12Rng::from_entropy();
        let g = Scalar::random(&mut rng);
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let g_a = g * a;
        let g_b = g * b;
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
