use iota_mam_app::message::{HasLink, LinkGenerator};
use iota_mam_app::transport::tangle::{DefaultTangleLinkGenerator, TangleAddress};
use iota_mam_core::{signature::mss};

pub trait ChannelLinkGenerator<Link>
where
    Link: HasLink,
    Self: LinkGenerator<Link, mss::PublicKey> + LinkGenerator<Link, <Link as HasLink>::Rel>,
{
}
impl ChannelLinkGenerator<TangleAddress> for DefaultTangleLinkGenerator {}

pub mod author;
pub mod subscriber;
pub mod tangle;
