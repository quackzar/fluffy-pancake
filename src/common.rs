use ductile::{ChannelReceiver, ChannelSender};
pub type Channel<S> = (ChannelSender<S>, ChannelReceiver<S>);

pub trait TChannelSender: Send {
    fn send_raw(&self, data: &[u8]) -> Result<(), Error>;
}

pub trait TChannelReceiver: Send {
    fn recv_raw(&self) -> Result<Vec<u8>, Error>;
}

// pub struct TChannel(pub Box<dyn TChannelSender>, pub Box<dyn TChannelReceiver>);

pub type TChannel = (Box<dyn TChannelSender>, Box<dyn TChannelReceiver>);


pub mod raw {
    use std::net::ToSocketAddrs;
    use super::*;

    struct Sender (ductile::ChannelSender<Vec<u8>>);

    struct Receiver (ductile::ChannelReceiver<Vec<u8>>);

    impl super::TChannelSender for Sender {
        fn send_raw(&self, data: &[u8]) -> Result<(), super::Error> {
            self.0.send_raw(&data)?;
            Ok(())
        }
    }

    impl super::TChannelReceiver for Receiver {
        fn recv_raw(&self) -> Result<Vec<u8>, super::Error> {
            let data = self.0.recv_raw()?;
            Ok(data)
        }
    }

    // Local channels
    pub fn local_channel_pair() -> (TChannel, TChannel) {
        let (s1,r1) = new_local_channel();
        let (s2,r2) = new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);
        (ch1, ch2)
    }

    pub fn new_local_channel() -> TChannel {
        let (s,r) = ductile::new_local_channel();
        (Box::new(Sender(s)), Box::new(Receiver(r)))
    }

    // Remote channels
    pub struct ChannelServer (ductile::ChannelServer<Vec<u8>, Vec<u8>>);
    
    impl ChannelServer {
        pub fn bind(addr: impl ToSocketAddrs) -> Result<ChannelServer, Error> {
            let s = ductile::ChannelServer::bind(addr)?;
            Ok(ChannelServer(s))
        }

        pub fn next(&mut self) -> Option<super::TChannel> {
            let (s,r,_) = self.0.next()?;
            Some((Box::new(Sender(s)), Box::new(Receiver(r))))
        }
    }

    pub fn connect_channel(addr: impl ToSocketAddrs) -> Result<TChannel, Error> {
        Ok(new_local_channel())
    }

}

pub type Error = Box<dyn std::error::Error>;
