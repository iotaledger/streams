use iota_streams_app::{
    message::{
        HasLink,
        LinkGenerator,
    },
};
use iota_streams_core::{
    prelude::Vec,
    sponge::prp::PRP,
};
use iota_streams_core_edsig::key_exchange::x25519;

#[cfg(all(feature = "tangle"))]
use iota_streams_app::{
    transport::tangle::{
        DefaultTangleLinkGenerator,
        TangleAddress,
    },
};

pub trait ChannelLinkGenerator<Link>
where
    Link: HasLink,
    Self: LinkGenerator<Link, (Vec<u8>, x25519::PublicKey, usize)> + LinkGenerator<Link, (<Link as HasLink>::Rel, x25519::PublicKey, usize)>,
{
}

#[cfg(all(feature = "tangle"))]
impl<F> ChannelLinkGenerator<TangleAddress> for DefaultTangleLinkGenerator<F> where F: PRP {}

/// Generic Channel Author API.
pub mod author;

/// Generic Channel Subscriber API.
pub mod subscriber;

/// Tangle-specific Channel API.
#[cfg(all(feature = "tangle"))]
pub mod tangle;
