use iota_streams_app::{
    message::{
        HasLink,
        LinkGenerator,
    },
    transport::tangle::{
        DefaultTangleLinkGenerator,
        TangleAddress,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
};
use iota_streams_core_edsig::signature::ed25519;

pub trait ChannelLinkGenerator<Link>
where
    Link: HasLink,
    Self: LinkGenerator<Link, ed25519::PublicKey> + LinkGenerator<Link, <Link as HasLink>::Rel>,
{
}
impl<F> ChannelLinkGenerator<TangleAddress> for DefaultTangleLinkGenerator<F>
where
    F: PRP,
{
}

/// Generic Channel Author API.
pub mod author;

/// Generic Channel Subscriber API.
pub mod subscriber;

/// Tangle-specific Channel API.
pub mod tangle;
