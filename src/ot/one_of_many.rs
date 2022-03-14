// Library for fast OT.
// use curve25519_dalek::edwards;
use crate::ot::common::*;
use crate::{
    ot::chou_orlandi::*,
    util::{random_bytes, xor_bytes, LENGTH},
};
use sha2::{Digest, Sha256};
// 1-to-n extensions for OT :D
// https://dl.acm.org/doi/pdf/10.1145/301250.301312
fn fk(key: &[u8], choice: u16) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(choice.to_be_bytes());
    hasher.update(key);
    let result = hasher.finalize().to_vec();

    let mut output = Vec::with_capacity(key.len());
    for i in 0..key.len() {
        output.push(result[i % result.len()]);
    }

    output
}

// How to 1-to-n:
// 1. Initiate
// 2. Challenge respond
// 3. Choose
// 4. Finish

// Bob: Initiate 1-to-n OT (initiated by the sender, Bob):
// - Prepares keys and uses these to generate the required y values sent to Alice
// - Creates challenges for Alice
pub fn one_to_n_challenge_create(
    domain: u16,
    messages: &[Vec<u8>],
) -> (Sender, Public, Vec<Vec<u8>>) {
    let byte_length = messages[0].len();

    // 1. B: Prepare random keys
    let l = messages.len();
    debug_assert!(l == (1 << domain));

    let mut keys: Vec<[Vec<u8>; 2]> = Vec::with_capacity(l);
    for _i in 0..l {
        let mut left = vec![0u8; byte_length];
        let mut right = vec![0u8; byte_length];

        random_bytes(&mut left);
        random_bytes(&mut right);

        keys.push([left, right]);
    }

    let domain_max = 1 << domain; // 2^domain
    let mut y = Vec::with_capacity(domain_max);
    for i in 0..domain_max {
        let mut value = messages[i].to_vec();
        for j in 0..domain {
            let bit = (i & (1 << j)) >> j;
            let hash = fk(&keys[j as usize][bit as usize], i as u16);
            value = xor_bytes(&value, &hash);
        }

        y.push(value.to_vec());
    }

    // 2. Initiate 1-out-of-2 OTs by sending challenges
    let mut messages = Vec::with_capacity(l);
    for i in 0..l {
        let m0 = keys[i as usize][0].to_vec();
        let m1 = keys[i as usize][1].to_vec();
        messages.push([m0, m1]);
    }

    let message = Message::new2(messages.as_slice());
    let sender = Sender::new(&message);
    let challenge = sender.public();

    (sender, challenge, y)
}

// Alice: Respond to challenge from Bob
// - Setup receivers
// - Create responses for Bob
pub fn one_to_n_challenge_respond(
    domain: u16,
    choice: u16,
    challenge: &Public,
) -> (Receiver<RetrievingPayload>, Public) {
    let l = 1 << domain;

    let mut choices: Vec<bool> = Vec::with_capacity(l);
    for i in 0..l {
        let bit = (choice & (1 << i)) >> i;
        choices.push(bit == 1);
    }
    let receiver = Receiver::new(choices.as_slice());
    let receiver = receiver.accept(challenge);
    let response = receiver.public();

    (receiver, response)
}

// Bob: Create payloads for Alice
pub fn one_to_n_create_payloads(sender: &Sender, response: &Public) -> EncryptedPayload {
    sender.accept(response)
}

// Alice: Chose a value
pub fn one_to_n_choose(
    domain: u16,
    choice: u16,
    receiver: &Receiver<RetrievingPayload>,
    payload: &EncryptedPayload,
    y: &Vec<Vec<u8>>,
) -> Vec<u8> {
    let l = 1 << domain;

    // Convert payloads to keys
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(l);
    let messages = receiver.receive(payload);
    for i in 0..l {
        let message = &messages[i];
        debug_assert_eq!(message.len() % LENGTH, 0);

        let mut key = Vec::with_capacity(message.len());
        for j in 0..message.len() {
            key.push(message[j]);
        }

        keys.push(key);
    }

    // Reconstruct X from keys and choice
    let mut x = y[choice as usize].to_vec();
    for i in 0..domain {
        let hash = fk(&keys[i as usize], choice);
        x = xor_bytes(&x, &hash);
    }

    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{log2, LENGTH};

    #[test]
    fn test_1_to_n() {
        let n = 8u8;
        let domain = log2(n) as u16;
        let mut messages = Vec::with_capacity(n as usize);
        for i in 0u8..n {
            messages.push(vec![i; LENGTH]);
        }
        let choice = 4;

        // Initiate the OT by creating and responding to challenges
        let (sender, challenge, y) = one_to_n_challenge_create(domain, &messages);
        let (receiver, response) = one_to_n_challenge_respond(domain, choice, &challenge);

        // Bob: Creates payloads for Alice
        let payload = one_to_n_create_payloads(&sender, &response);

        // Alice: Choose a value
        let output = one_to_n_choose(domain, choice, &receiver, &payload, &y);

        // Check that we actually got the thing we wanted
        for i in 0..LENGTH {
            assert_eq!(messages[choice as usize][i], output[i]);
        }
    }
}
