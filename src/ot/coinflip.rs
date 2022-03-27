use rand::Rng;
use crate::hash;

use super::common::{Channel, Error};

#[derive(Debug)]
enum CoinFlipError {
    WrongMessageLength,
    InvalidCommitment,

}
impl std::error::Error for CoinFlipError {}

impl std::fmt::Display for CoinFlipError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            CoinFlipError::WrongMessageLength => write!(f, "Wrong message length"),
            CoinFlipError::InvalidCommitment => write!(f, "Invalid commitment"),
        }
    }
}

// TODO: Parameterize RNG.
/// Coin flip protocol for generating N random bytes.
/// This part first randomly selects N bytes, commits to them and sends a that commit
/// It then opens the commitment.
/// It then receives N bytes which it then XORs with its own random bytes.
pub fn coinflip_sender<const N : usize>((s,r) : &Channel<Vec<u8>>) -> Result<[u8; N], Error> {
    let mut rng = rand::thread_rng();
    let v : [u8; N] = rng.gen();
    let commit = hash!(v);
    s.send(commit.to_vec())?;
    let u = r.recv()?;
    if u.len() != N {
        return Err(CoinFlipError::WrongMessageLength.into());
    }
    s.send(v.to_vec())?;
    let mut w = [0u8; N];
    for i in 0..N { // You could vectorize this more but I'm not sure it's worth it.
        w[i] = v[i] ^ u[i];
    }
    Ok(w)
}

/// Coin flip protocol for generating N random bytes.
/// This first waits for a sender to send a commitment,
/// then it picks N random bytes and sends them.
/// The commitment is then opened and XORed with the bytes.
pub fn coinflip_receiver<const N : usize>((s,r) : &Channel<Vec<u8>>) -> Result<[u8; N], Error> {
    let mut rng = rand::thread_rng();
    let u : [u8; N] = rng.gen();
    let commit = r.recv()?;
    s.send(u.to_vec())?;
    let v = r.recv()?;
    if v.len() != N {
        return Err(CoinFlipError::WrongMessageLength.into());
    }
    if commit != hash!(&v) {
        return Err(CoinFlipError::InvalidCommitment.into());
    }
    let mut w = [0u8; N];
    for i in 0..N {
        w[i] = u[i] ^ v[i];
    }

    Ok(w)
}

#[cfg(test)]
mod tests {
    use crate::ot::coinflip::{coinflip_sender, coinflip_receiver};

    #[test]
    fn test_coinflip() {
        let (s1, r1) = ductile::new_local_channel();
        let (s2, r2) = ductile::new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);


        use std::thread;
        let h1 = thread::Builder::new()
            .name("Sender".to_string())
            .spawn(move || {
                coinflip_sender::<8>(&ch1).unwrap()
            });

        let h2 = thread::Builder::new()
            .name("Receiver".to_string())
            .spawn(move || {
                coinflip_receiver::<8>(&ch2).unwrap()
            });

        let w1 = h1.unwrap().join().unwrap();
        let w2 = h2.unwrap().join().unwrap();
        assert_eq!(w1, w2);
    }
}

