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
use iota_streams_app::message::{
    self,
    HasLink,
};
use iota_streams_core::{
    prng,
    sponge::{
        prp::PRP,
        spongos,
    },
    tbits::{
        trinary,
        word::{
            BasicTbitWord,
            SpongosTbitWord,
        },
    },
};
use iota_streams_core_ntru::key_encapsulation::ntru;
use iota_streams_protobuf3::{
    command::*,
    io,
    types::*,
};

/// Type of `Subscribe` message content.
pub const TYPE: &str = "STREAMS9CHANNEL9SUBSCRIBE";

pub struct ContentWrap<'a, TW, F, G, Link: HasLink> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub nonce: NTrytes<TW>,
    pub unsubscribe_key: NTrytes<TW>,
    pub(crate) subscriber_ntru_pk: &'a ntru::PublicKey<TW, F>,
    pub(crate) author_ntru_pk: &'a ntru::PublicKey<TW, F>,
    pub(crate) prng: &'a prng::Prng<TW, G>,
    pub(crate) _phantom: std::marker::PhantomData<Link>,
}

impl<'a, TW, F, G, Link, Store> message::ContentWrap<TW, F, Store> for ContentWrap<'a, TW, F, G, Link>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    G: PRP<TW> + Clone + Default,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<TW, F>) -> Fallible<&'c mut sizeof::Context<TW, F>> {
        let store = EmptyLinkStore::<TW, F, <Link as HasLink>::Rel, ()>::default();
        let mac = Mac(spongos::Spongos::<TW, F>::MAC_SIZE);
        ctx.join(&store, self.link)?
            .ntrukem(self.author_ntru_pk, &self.unsubscribe_key)?
            .commit()?
            .mask(self.subscriber_ntru_pk)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream<TW>>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<TW, F, OS>,
    ) -> Fallible<&'c mut wrap::Context<TW, F, OS>> {
        let mac = Mac(spongos::Spongos::<TW, F>::MAC_SIZE);
        ctx.join(store, self.link)?
            .ntrukem((self.author_ntru_pk, self.prng, &self.nonce.0), &self.unsubscribe_key)?
            .commit()?
            .mask(self.subscriber_ntru_pk)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<'a, TW, F, Link: HasLink> {
    pub link: <Link as HasLink>::Rel,
    pub unsubscribe_key: NTrytes<TW>,
    pub subscriber_ntru_pk: ntru::PublicKey<TW, F>,
    author_ntru_sk: &'a ntru::PrivateKey<TW, F>,
    _phantom: std::marker::PhantomData<Link>,
}

impl<'a, TW, F, Link> ContentUnwrap<'a, TW, F, Link>
where
    TW: BasicTbitWord,
    F: PRP<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<TW, F>,
{
    pub fn new(author_ntru_sk: &'a ntru::PrivateKey<TW, F>) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            unsubscribe_key: NTrytes::<TW>::zero(spongos::Spongos::<TW, F>::KEY_SIZE),
            subscriber_ntru_pk: ntru::PublicKey::<TW, F>::default(),
            author_ntru_sk,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, TW, F, Link, Store> message::ContentUnwrap<TW, F, Store> for ContentUnwrap<'a, TW, F, Link>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
{
    fn unwrap<'c, IS: io::IStream<TW>>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<&'c mut unwrap::Context<TW, F, IS>> {
        let mac = Mac(spongos::Spongos::<TW, F>::MAC_SIZE);
        ctx.join(store, &mut self.link)?
            .ntrukem(self.author_ntru_sk, &mut self.unsubscribe_key)?
            .commit()?
            .mask(&mut self.subscriber_ntru_pk)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}
