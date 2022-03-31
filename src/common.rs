use ductile::{ChannelReceiver, ChannelSender};
use serde::Serialize;
pub type Channel<S> = (ChannelSender<S>, ChannelReceiver<S>);
pub type NeoChannel = (ChannelSender<dyn Serialize>, ChannelReceiver<dyn Serialize>);

pub type Error = Box<dyn std::error::Error>;
