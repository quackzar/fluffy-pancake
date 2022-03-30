use serde::{Deserialize, Serialize};
use crate::common::*;

/// Pair of plaintexts
pub type PlaintextPair = [Vec<u8>; 2];

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct TransactionProperties {
    pub msg_size: usize,
    pub protocol: String,
}

pub(crate) fn validate_properties(
    pb: &TransactionProperties,
    (s, r): &Channel<Vec<u8>>,
) -> Result<(), Error> {
    s.send(bincode::serialize(pb)?)?;
    let pb2 = r.recv()?;
    let pb2 = bincode::deserialize(&pb2)?;
    if pb2 != *pb {
        Err(Box::new(OTError::BadProperties(pb.clone(), pb2)))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum OTError {
    BadProperties(TransactionProperties, TransactionProperties),
    PolychromaticInput(),
}

impl std::error::Error for OTError {}
impl std::fmt::Display for OTError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OTError::BadProperties(pb1, pb2) => write!(f, "Bad properties: {:?} != {:?}", pb1, pb2),
            OTError::PolychromaticInput() => write!(f, "Polychromatic input, cheating receiver."),
        }
    }
}

/// Set of message
#[derive(Debug, Clone)]
pub struct Message(pub Vec<PlaintextPair>);

impl Message {
    pub fn new2<T: AsRef<[u8]>>(msg: &[[T; 2]]) -> Self {
        let mut vec = Vec::with_capacity(msg.len());
        for m in msg {
            vec.push([m[0].as_ref().to_vec(), m[1].as_ref().to_vec()]);
        }
        Message(vec)
    }

    pub fn new<T: AsRef<[u8]>>(m0: &[T], m1: &[T]) -> Self {
        assert!(m0.len() == m1.len());
        let mut m = Vec::with_capacity(m0.len());
        for i in 0..m0.len() {
            m.push([m0[i].as_ref().to_vec(), m1[i].as_ref().to_vec()]);
        }
        Message(m)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub trait ObliviousSender {
    fn exchange(&self, msg: &Message, channel: &Channel<Vec<u8>>) -> Result<(), Error>;
}

pub type Payload = Vec<Vec<u8>>;

pub trait ObliviousReceiver {
    fn exchange(&self, choices: &[bool], channel: &Channel<Vec<u8>>) -> Result<Payload, Error>;
}
