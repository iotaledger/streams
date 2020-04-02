use iota_streams_app::message::{HasLink, LinkGenerator};
use iota_streams_app::transport::tangle::{DefaultTangleLinkGenerator, TangleAddress};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::{SpongosTbitWord, StringTbitWord},
    },
};
use iota_streams_core_mss::signature::mss;

pub trait ChannelLinkGenerator<TW, P, Link>
where
    TW: StringTbitWord + SpongosTbitWord + trinary::TritWord,
    P: mss::Parameters<TW>,
    Link: HasLink,
    Self: LinkGenerator<TW, Link, mss::PublicKey<TW, P>>
        + LinkGenerator<TW, Link, <Link as HasLink>::Rel>,
{
}
impl<TW, F, P> ChannelLinkGenerator<TW, P, TangleAddress<TW>> for DefaultTangleLinkGenerator<TW, F>
where
    TW: StringTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW> + Default,
    P: mss::Parameters<TW>,
{
}

/// Generic Channel Author API.
pub mod author;

/// Generic Channel Subscriber API.
pub mod subscriber;

/// Tangle-specific Channel API.
pub mod tangle;
