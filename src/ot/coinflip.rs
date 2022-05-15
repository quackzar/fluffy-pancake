use crate::hash;
use rand::Rng;

use crate::common::*;

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
pub fn coinflip_sender<const N: usize>((s, r): &TChannel) -> Result<[u8; N], Error> {
    let mut rng = rand::thread_rng();
    let v: [u8; N] = rng.gen();
    let commit = hash!(v);
    s.send_raw(&commit.to_vec())?;
    let u = r.recv_raw()?;
    if u.len() != N {
        return Err(CoinFlipError::WrongMessageLength.into());
    }
    s.send_raw(&v.to_vec())?;
    let mut w = [0u8; N];
    for i in 0..N {
        // You could vectorize this more but I'm not sure it's worth it.
        w[i] = v[i] ^ u[i];
    }
    Ok(w)
}

/// Coin flip protocol for generating N random bytes.
/// This first waits for a sender to send a commitment,
/// then it picks N random bytes and sends them.
/// The commitment is then opened and XORed with the bytes.
pub fn coinflip_receiver<const N: usize>((s, r): &TChannel) -> Result<[u8; N], Error> {
    let mut rng = rand::thread_rng();
    let u: [u8; N] = rng.gen();
    let commit = r.recv_raw()?;
    s.send_raw(&u.to_vec())?;
    let v = r.recv_raw()?;
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
    use crate::common::*;
    use crate::ot::coinflip::{coinflip_receiver, coinflip_sender};

    #[test]
    fn test_coinflip() {
        let (ch1, ch2) = raw::local_channel_pair();

        use std::thread;
        let h1 = thread::Builder::new()
            .name("Sender".to_string())
            .spawn(move || coinflip_sender::<8>(&ch1).unwrap());

        let h2 = thread::Builder::new()
            .name("Receiver".to_string())
            .spawn(move || coinflip_receiver::<8>(&ch2).unwrap());

        let w1 = h1.unwrap().join().unwrap();
        let w2 = h2.unwrap().join().unwrap();
        assert_eq!(w1, w2);
    }
}
