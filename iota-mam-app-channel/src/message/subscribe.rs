//! `Subscribe` message content. This message is published by a user willing to become
//! a subscriber to this channel. It contains subscriber's NTRU public key that will be used
//! in keyload to encrypt session keys. Subscriber's NTRU public key is encrypted with
//! the `unsubscribe_key` which in turn is encapsulated for channel owner using
//! owner's NTRU public key. The resulting spongos state will be used for unsubscription.
//! Subscriber must trust channel owner's NTRU public key in order to maintain privacy.
//!
//! Channel Owner must maintain the resulting spongos state associated to the Subscriber's
//! NTRU public key.
//!
//! Note, in the `Channel` Application Subscriber doesn't have signature keys and thus
//! can't prove possesion of the NTRU private key with signature. Such proof can
//! be established in an interactive protocol by channel Owner's request.
//! Such protocol is out of scope. To be discussed.
//!
//! ```pb3
//! message Subscribe {
//!     join link msgid;
//!     ntrukem(key) tryte unsubscribe_key[3072];
//!     commit;
//!     mask tryte ntrupk[3072];
//!     commit;
//!     squeeze tryte mac[27];
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the `Announce` message containing channel owner's trusted NTRU public key.
//! This key is used to protect subscriber's identity by encrypting subscriber's NTRU public key.
//!
//! * `unsubscribe_key` -- encapsulated secret key that serves as encryption key and as password to unsubscribe from the channel.
//!
//! * `ntrupk` -- subscriber's NTRU public key.
//!
//! * `mac` -- authentication tag.
//!
//! Note, the `unsubscribe_key` is masked and verified in the `ntrukem` operation and
//! thus is not additionally `absorb`ed in this message.

use failure::Fallible;
use iota_mam_app::message::{self, HasLink};
use iota_mam_core::{key_encapsulation::ntru, prng, spongos};
use iota_mam_protobuf3::{command::*, io, types::*};

/// Type of `Subscribe` message content.
pub const TYPE: &str = "MAM9CHANNEL9SUBSCRIBE";

pub struct ContentWrap<'a, Link: HasLink> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub nonce: NTrytes,
    pub unsubscribe_key: NTrytes,
    pub(crate) subscriber_ntru_pk: &'a ntru::PublicKey,
    pub(crate) author_ntru_pk: &'a ntru::PublicKey,
    pub(crate) prng: &'a prng::PRNG,
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
        ctx.join(&store, self.link)?
            .ntrukem(self.author_ntru_pk, &self.unsubscribe_key)?
            .commit()?
            .mask(self.subscriber_ntru_pk)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<OS>,
    ) -> Fallible<&'c mut wrap::Context<OS>> {
        let mac = Mac(spongos::MAC_SIZE);
        ctx.join(store, self.link)?
            .ntrukem(
                (self.author_ntru_pk, self.prng, &self.nonce.0),
                &self.unsubscribe_key,
            )?
            .commit()?
            .mask(self.subscriber_ntru_pk)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<'a, Link: HasLink> {
    pub link: <Link as HasLink>::Rel,
    pub unsubscribe_key: NTrytes,
    pub subscriber_ntru_pk: ntru::PublicKey,
    author_ntru_sk: &'a ntru::PrivateKey,
    _phantom: std::marker::PhantomData<Link>,
}

impl<'a, Link> ContentUnwrap<'a, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
{
    pub fn new(author_ntru_sk: &'a ntru::PrivateKey) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            unsubscribe_key: NTrytes::zero(ntru::KEY_SIZE),
            subscriber_ntru_pk: ntru::PublicKey::default(),
            author_ntru_sk,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, Link, Store> message::ContentUnwrap<Store> for ContentUnwrap<'a, Link>
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
        ctx.join(store, &mut self.link)?
            .ntrukem(self.author_ntru_sk, &mut self.unsubscribe_key)?
            .commit()?
            .mask(&mut self.subscriber_ntru_pk)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}
