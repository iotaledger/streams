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
//!     ntrukem(key) byte unsubscribe_key[3072];
//!     commit;
//!     mask byte ntrupk[3072];
//!     commit;
//!     squeeze byte mac[27];
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

use anyhow::Result;
use iota_streams_app::message::{
    self,
    HasLink,
};
use iota_streams_core::{
    sponge::{
        prp::PRP,
        spongos,
    },
};
use iota_streams_core_edsig::{signature::ed25519, key_exchange::x25519};
use iota_streams_protobuf3::{
    command::*,
    io,
    types::*,
};

/// Type of `Subscribe` message content.
pub const TYPE: Uint8 = Uint8(5);

pub struct ContentWrap<'a, F, Link: HasLink> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub unsubscribe_key: NBytes,
    pub(crate) subscriber_sig_kp: &'a ed25519::Keypair,
    pub(crate) author_ke_pk: &'a x25519::PublicKey,
    pub(crate) _phantom: std::marker::PhantomData<(Link, F)>,
}

impl<'a, F, Link, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        ctx
            .join(&store, self.link)?
            .x25519(self.author_ke_pk, &self.unsubscribe_key)?
            .mask(&self.subscriber_sig_kp.public)?
            .ed25519(self.subscriber_sig_kp, HashSig)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx
            .join(store, self.link)?
            .x25519(self.author_ke_pk, &self.unsubscribe_key)?
            .mask(&self.subscriber_sig_kp.public)?
            .ed25519(self.subscriber_sig_kp, HashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<'a, F, Link: HasLink> {
    pub link: <Link as HasLink>::Rel,
    pub unsubscribe_key: NBytes,
    pub subscriber_sig_pk: ed25519::PublicKey,
    author_ke_sk: &'a x25519::StaticSecret,
    _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link> ContentUnwrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
{
    pub fn new(author_ke_sk: &'a x25519::StaticSecret) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            unsubscribe_key: NBytes::zero(spongos::Spongos::<F>::KEY_SIZE),
            subscriber_sig_pk: ed25519::PublicKey::from_bytes(&[0_u8; ed25519::PUBLIC_KEY_LENGTH]).unwrap(),
            author_ke_sk,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, F, Link, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx
            .join(store, &mut self.link)?
            .x25519(self.author_ke_sk, &mut self.unsubscribe_key)?
            .mask(&mut self.subscriber_sig_pk)?
            .ed25519(&self.subscriber_sig_pk, HashSig)?;
        Ok(ctx)
    }
}
