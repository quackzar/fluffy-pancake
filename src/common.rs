// Common functionality for all modules.
pub type Error = Box<dyn std::error::Error>;
// TODO: Make result type more pleasant and maybe switch to anyhow.

pub trait TChannelSender: Send {
    fn send_raw(&self, data: &[u8]) -> Result<(), Error>;
}

pub trait TChannelReceiver: Send {
    fn recv_raw(&self) -> Result<Vec<u8>, Error>;
}

pub type TChannel = (Box<dyn TChannelSender>, Box<dyn TChannelReceiver>);

pub mod raw {
    use super::*;
    use std::net::ToSocketAddrs;

    struct RawChannelSender(ductile::ChannelSender<Vec<u8>>);

    struct RawChannelReceiver(ductile::ChannelReceiver<Vec<u8>>);

    impl super::TChannelSender for RawChannelSender {
        fn send_raw(&self, data: &[u8]) -> Result<(), super::Error> {
            self.0.send_raw(&data)?;
            Ok(())
        }
    }

    impl super::TChannelReceiver for RawChannelReceiver {
        fn recv_raw(&self) -> Result<Vec<u8>, super::Error> {
            let data = self.0.recv_raw()?;
            Ok(data)
        }
    }

    // Local channels
    pub fn local_channel_pair() -> (TChannel, TChannel) {
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);
        (ch1, ch2)
    }

    pub fn new_local_channel() -> TChannel {
        let (s, r) = ductile::new_local_channel();
        (
            Box::new(RawChannelSender(s)),
            Box::new(RawChannelReceiver(r)),
        )
    }

    // Remote channels
    pub struct ChannelServer(ductile::ChannelServer<Vec<u8>, Vec<u8>>);

    impl ChannelServer {
        pub fn bind(addr: impl ToSocketAddrs) -> Result<ChannelServer, Error> {
            let s = ductile::ChannelServer::bind(addr)?;
            Ok(ChannelServer(s))
        }

        pub fn next(&mut self) -> Option<super::TChannel> {
            let (s, r, _) = self.0.next()?;
            Some((
                Box::new(RawChannelSender(s)),
                Box::new(RawChannelReceiver(r)),
            ))
        }
    }

    pub fn connect_channel(addr: impl ToSocketAddrs) -> Result<TChannel, Error> {
        let (s, r) = ductile::connect_channel(addr)?;
        Ok((
            Box::new(RawChannelSender(s)),
            Box::new(RawChannelReceiver(r)),
        ))
    }
}

/// Module for channels in which messages are authenticated.
pub mod auth {
    // TODO: Test this module.
    use std::net::ToSocketAddrs;

    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    struct AuthChannelSender {
        s: ductile::ChannelSender<Vec<u8>>,
        key: [u8; 32],
    }

    struct AuthChannelReceiver {
        r: ductile::ChannelReceiver<Vec<u8>>,
        key: [u8; 32],
    }

    impl super::TChannelSender for AuthChannelSender {
        fn send_raw(&self, data: &[u8]) -> Result<(), super::Error> {
            let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
            mac.update(data);
            let code = mac.finalize();
            let code = code.into_bytes();
            self.s.send_raw(&data)?;
            self.s.send_raw(&code)?;
            Ok(())
        }
    }

    impl super::TChannelReceiver for AuthChannelReceiver {
        fn recv_raw(&self) -> Result<Vec<u8>, super::Error> {
            let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
            let data = self.r.recv_raw()?;
            let code = self.r.recv_raw()?;
            mac.update(&data);
            mac.verify_slice(&code)?;
            Ok(data)
        }
    }

    // Local channels
    pub fn local_channel_pair() -> (TChannel, TChannel) {
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);
        (ch1, ch2)
    }

    fn new_local_channel() -> TChannel {
        let key: [u8; 32] = rand::random();
        let (s, r) = ductile::new_local_channel();
        let sender = AuthChannelSender {
            s,
            key: key.clone(),
        };
        let receiver = AuthChannelReceiver { r, key };
        (Box::new(sender), Box::new(receiver))
    }

    pub struct ChannelServer(ductile::ChannelServer<Vec<u8>, Vec<u8>>);

    use rand_core::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    impl ChannelServer {
        pub fn bind(addr: impl ToSocketAddrs) -> Result<ChannelServer, Error> {
            let s = ductile::ChannelServer::bind(addr)?;
            Ok(ChannelServer(s))
        }

        pub fn next(&mut self) -> Option<super::TChannel> {
            let (s, r, _) = self.0.next()?;
            let secret = EphemeralSecret::new(OsRng);
            let public = PublicKey::from(&secret);

            // TODO: Proper error handling.
            s.send_raw(public.as_bytes()).unwrap();
            let theirs = r.recv_raw().unwrap();
            let theirs: [u8; 32] = theirs.try_into().unwrap();
            let theirs = PublicKey::try_from(theirs).unwrap();
            let key = secret.diffie_hellman(&theirs);
            let key = key.to_bytes();

            let sender = Box::new(AuthChannelSender { s, key });
            let receiver = Box::new(AuthChannelReceiver { r, key });
            Some((sender, receiver))
        }
    }

    pub fn connect_channel(addr: impl ToSocketAddrs) -> Result<TChannel, Error> {
        let (s, r) = ductile::connect_channel(addr)?;
        let secret = EphemeralSecret::new(OsRng);
        let public = PublicKey::from(&secret);

        let theirs = r.recv_raw().unwrap();
        let theirs: [u8; 32] = theirs.try_into().unwrap();
        let theirs = PublicKey::try_from(theirs).unwrap();
        s.send_raw(public.as_bytes())?;
        let key = secret.diffie_hellman(&theirs);
        let key = key.to_bytes();

        let sender = Box::new(AuthChannelSender { s, key });
        let receiver = Box::new(AuthChannelReceiver { r, key });
        Ok((sender, receiver))
    }
}
