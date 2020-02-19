//! `Unsubscribe` message content. This message is published by a subscriber
//! willing to unsubscribe from this channel.
//!
//! ```pb3
//! message Unsubscribe {
//!     join link msgid;
//!     commit;
//!     squeeze tryte mac[27];
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the `Subscribe` message published by the subscriber.
//!
//! * `mac` -- authentication tag proving knowledge of the `unsubscribe_key` from the `Subscribe` message.

use failure::Fallible;
use iota_mam_app::message::{self, HasLink};
use iota_mam_core::spongos;
use iota_mam_protobuf3::{command::*, io, types::*};

/// Type of `Unsubscribe` message content.
pub const TYPE: &str = "MAM9CHANNEL9UNSUBSCRIBE";

pub struct ContentWrap<'a, Link: HasLink> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) _phantom: std::marker::PhantomData<Link>,
}

impl<'a, Link, Store> message::ContentWrap<Store> for ContentWrap<'a, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Fallible<&'c mut sizeof::Context> {
        let store = EmptyLinkStore::<<Link as HasLink>::Rel, ()>::default();
        let mac = Mac(spongos::MAC_SIZE);
        ctx.join(&store, self.link)?.commit()?.squeeze(&mac)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<OS>,
    ) -> Fallible<&'c mut wrap::Context<OS>> {
        let mac = Mac(spongos::MAC_SIZE);
        ctx.join(store, self.link)?.commit()?.squeeze(&mac)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<Link: HasLink> {
    pub link: <Link as HasLink>::Rel,
    _phantom: std::marker::PhantomData<Link>,
}

impl<Link> ContentUnwrap<Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
{
    pub fn new() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Link, Store> message::ContentUnwrap<Store> for ContentUnwrap<Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<IS>,
    ) -> Fallible<&'c mut unwrap::Context<IS>> {
        let mac = Mac(spongos::MAC_SIZE);
        ctx.join(store, &mut self.link)?.commit()?.squeeze(&mac)?;
        Ok(ctx)
    }
}
