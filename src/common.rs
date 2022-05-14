use ductile::{ChannelReceiver, ChannelSender};
pub type Channel<S> = (ChannelSender<S>, ChannelReceiver<S>);

pub trait TChannelSender: Send + Sync {
    fn send_raw(&self, data: &[u8]) -> Result<(), Error>;
}

pub trait TChannelReceiver: Send + Sync {
    fn recv_raw(&self) -> Result<Vec<u8>, Error>;
}

// pub struct TChannel(pub Box<dyn TChannelSender>, pub Box<dyn TChannelReceiver>);

pub type TChannel = (Box<dyn TChannelSender>, Box<dyn TChannelReceiver>);


// TODO: Make actual versions that do something.
pub mod mock {
    use std::net::ToSocketAddrs;
    use super::*;

    struct Sender {}
    struct Receiver {}

    impl super::TChannelSender for Sender {
        fn send_raw(&self, data: &[u8]) -> Result<(), super::Error> {
            Ok(())
        }
    }

    impl super::TChannelReceiver for Receiver {
        fn recv_raw(&self) -> Result<Vec<u8>, super::Error> {
            Ok(vec![])
        }
    }

    // Local channels
    pub fn local_channel_pair() -> (TChannel, TChannel) {
        ((Box::new(Sender {}), Box::new(Receiver {})), (Box::new(Sender {}), Box::new(Receiver {})))
    }

    pub fn new_local_channel() -> TChannel {
        (Box::new(Sender {}), Box::new(Receiver {}))
    }

    // Remote channels
    pub struct ChannelServer {}
    
    impl ChannelServer {
        pub fn bind(addr: impl ToSocketAddrs) -> Result<ChannelServer, Error> {
            Ok(ChannelServer {})
        }

        pub fn next(&mut self) -> Result<super::TChannel, Error> {
            Ok((Box::new(Sender {}), Box::new(Receiver {})))
        }
    }

    pub fn connect_channel(addr: impl ToSocketAddrs) -> Result<TChannel, Error> {
        Ok(new_local_channel())
    }

}

pub type Error = Box<dyn std::error::Error>;

fn test(t : TChannel) {
    todo!()
}
