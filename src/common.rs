// Common functionality for all modules.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub trait ChannelSender: Send {
    fn send(&self, data: &[u8]) -> Result<()>;
}

pub trait ChannelReceiver: Send {
    fn recv(&self) -> Result<Vec<u8>>;
}

pub type Channel = (Box<dyn ChannelSender>, Box<dyn ChannelReceiver>);

pub mod raw {
    use super::*;
    use std::net::ToSocketAddrs;

    struct RawChannelSender(ductile::ChannelSender<Vec<u8>>);

    struct RawChannelReceiver(ductile::ChannelReceiver<Vec<u8>>);

    impl super::ChannelSender for RawChannelSender {
        fn send(&self, data: &[u8]) -> Result<()> {
            self.0.send_raw(&data)?;
            Ok(())
        }
    }

    impl super::ChannelReceiver for RawChannelReceiver {
        fn recv(&self) -> Result<Vec<u8>> {
            let data = self.0.recv_raw()?;
            Ok(data)
        }
    }

    // Local channels
    pub fn local_channel_pair() -> (Channel, Channel) {
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);
        (ch1, ch2)
    }

    pub fn new_local_channel() -> Channel {
        let (s, r) = ductile::new_local_channel();
        (
            Box::new(RawChannelSender(s)),
            Box::new(RawChannelReceiver(r)),
        )
    }

    // Remote channels
    pub struct ChannelServer(ductile::ChannelServer<Vec<u8>, Vec<u8>>);

    impl ChannelServer {
        pub fn bind(addr: impl ToSocketAddrs) -> Result<ChannelServer> {
            let s = ductile::ChannelServer::bind(addr)?;
            Ok(ChannelServer(s))
        }

        pub fn next(&mut self) -> Option<super::Channel> {
            let (s, r, _) = self.0.next()?;
            Some((
                Box::new(RawChannelSender(s)),
                Box::new(RawChannelReceiver(r)),
            ))
        }
    }

    pub fn connect_channel(addr: impl ToSocketAddrs) -> Result<Channel> {
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

    impl super::ChannelSender for AuthChannelSender {
        fn send(&self, data: &[u8]) -> Result<()> {
            let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
            mac.update(data);
            let code = mac.finalize();
            let code = code.into_bytes();
            self.s.send_raw(&data)?;
            self.s.send_raw(&code)?;
            Ok(())
        }
    }

    impl super::ChannelReceiver for AuthChannelReceiver {
        fn recv(&self) -> Result<Vec<u8>> {
            let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
            let data = self.r.recv_raw()?;
            let code = self.r.recv_raw()?;
            mac.update(&data);
            mac.verify_slice(&code)?;
            Ok(data)
        }
    }

    // Local channels
    pub fn local_channel_pair() -> (Channel, Channel) {
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);
        (ch1, ch2)
    }

    fn new_local_channel() -> Channel {
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
        pub fn bind(addr: impl ToSocketAddrs) -> Result<ChannelServer> {
            let s = ductile::ChannelServer::bind(addr)?;
            Ok(ChannelServer(s))
        }

        pub fn next(&mut self) -> Option<super::Channel> {
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

    pub fn connect_channel(addr: impl ToSocketAddrs) -> Result<Channel> {
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

    mod tests {
        #[test]
        fn test_auth_channel() {
            use super::*;
            let (ch1, ch2) = local_channel_pair();

            let h1 = std::thread::spawn(move || -> Result<_> {
                let (s, r) = ch1;
                s.send(&[1, 2, 3, 4])?;
                r.recv()?;
                Ok(())
            });

            let h2 = std::thread::spawn(move || -> Result<_> {
                let (s, r) = ch2;
                s.send(&[5, 6, 7, 8])?;
                r.recv()?;
                Ok(())
            });

            h1.join().unwrap().unwrap();
            h2.join().unwrap().unwrap();
        }
    }
}

mod signed {
    use std::net::ToSocketAddrs;

    use super::*;
    use ed25519_dalek::*;

    struct SignedChannelSender {
        s: ductile::ChannelSender<Vec<u8>>,
        keypair: Keypair,
    }

    struct SignedChannelReceiver {
        r: ductile::ChannelReceiver<Vec<u8>>,
        public_key: PublicKey,
    }

    impl super::ChannelSender for SignedChannelSender {
        fn send(&self, data: &[u8]) -> Result<()> {
            let signature = self.keypair.sign(data);
            let signature = signature.to_bytes();
            self.s.send_raw(&data)?;
            self.s.send_raw(&signature)?;
            Ok(())
        }
    }

    impl super::ChannelReceiver for SignedChannelReceiver {
        fn recv(&self) -> Result<Vec<u8>> {
            let data = self.r.recv_raw()?;
            let signature = self.r.recv_raw()?;
            let signature = Signature::from_bytes(&signature).unwrap();
            let public_key = self.public_key;
            public_key.verify(&data, &signature)?;
            Ok(data)
        }
    }

    // Local channels
    pub fn local_channel_pair() -> (Channel, Channel) {
        let (s1, r1) = new_local_channel();
        let (s2, r2) = new_local_channel();
        let ch1 = (s1, r2);
        let ch2 = (s2, r1);
        (ch1, ch2)
    }

    fn new_local_channel() -> Channel {
        let mut csprng = rand_old::rngs::OsRng {};
        let keypair = Keypair::generate(&mut csprng);
        let public_key = keypair.public.clone();

        let (s, r) = ductile::new_local_channel();

        let sender = SignedChannelSender { s, keypair };
        let receiver = SignedChannelReceiver { r, public_key };
        (Box::new(sender), Box::new(receiver))
    }

    pub struct ChannelServer(ductile::ChannelServer<Vec<u8>, Vec<u8>>);

    impl ChannelServer {
        pub fn bind(addr: impl ToSocketAddrs) -> Result<ChannelServer> {
            let s = ductile::ChannelServer::bind(addr)?;
            Ok(ChannelServer(s))
        }

        pub fn next(&mut self) -> Option<super::Channel> {
            let (s, r, _) = self.0.next()?;

            // generation and exchanging of public keys
            let mut csprng = rand_old::rngs::OsRng {};
            let keypair = Keypair::generate(&mut csprng);
            let my_public_key = keypair.public.clone();
            s.send_raw(&my_public_key.to_bytes()).unwrap();
            let public_key = r.recv_raw().unwrap();
            let public_key = PublicKey::from_bytes(&public_key).unwrap();

            let sender = Box::new(SignedChannelSender { s, keypair });
            let receiver = Box::new(SignedChannelReceiver { r, public_key });
            Some((sender, receiver))
        }
    }

    pub fn connect_channel(addr: impl ToSocketAddrs) -> Result<Channel> {
        let (s, r) = ductile::connect_channel(addr)?;

        // generation and exchanging of public keys
        let mut csprng = rand_old::rngs::OsRng {};
        let keypair = Keypair::generate(&mut csprng);
        let my_public_key = keypair.public.clone();
        let public_key = r.recv_raw()?;
        let public_key = PublicKey::from_bytes(&public_key)?;
        s.send_raw(&my_public_key.to_bytes())?;

        let sender = Box::new(SignedChannelSender { s, keypair });
        let receiver = Box::new(SignedChannelReceiver { r, public_key });
        Ok((sender, receiver))
    }

    mod tests {
        #[test]
        fn test_auth_channel() {
            use super::*;
            let (ch1, ch2) = local_channel_pair();

            let h1 = std::thread::spawn(move || -> Result<_> {
                let (s, r) = ch1;
                s.send(&[1, 2, 3, 4])?;
                r.recv()?;
                Ok(())
            });

            let h2 = std::thread::spawn(move || -> Result<_> {
                let (s, r) = ch2;
                s.send(&[5, 6, 7, 8])?;
                r.recv()?;
                Ok(())
            });

            h1.join().unwrap().unwrap();
            h2.join().unwrap().unwrap();
        }
    }
}
