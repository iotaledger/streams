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
use iota_streams_core::sponge::prp::PRP;

pub trait ChannelLinkGenerator<Link>
where
    Link: HasLink,
    Self: LinkGenerator<Link, Vec<u8>> + LinkGenerator<Link, <Link as HasLink>::Rel>,
{
}
impl<F> ChannelLinkGenerator<TangleAddress> for DefaultTangleLinkGenerator<F> where F: PRP {}

/// Generic Channel Author API.
pub mod author;

/// Generic Channel Subscriber API.
pub mod subscriber;

/// Tangle-specific Channel API.
pub mod tangle;
