use ductile::{ChannelReceiver, ChannelSender};
pub type Channel<S> = (ChannelSender<S>, ChannelReceiver<S>);

pub type Error = Box<dyn std::error::Error>;

/// Pair of plaintexts
pub type PlaintextPair = [Vec<u8>; 2];

/// Set of messag
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
