use failure::Fallible;
use std::cell::RefMut;

use super::*;
use iota_streams_core::{
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
    tbits::word::SpongosTbitWord,
};
use iota_streams_protobuf3::types::*;

/// Result of wrapping the message.
pub struct WrappedMessage<TW, F, Link> {
    pub message: TbinaryMessage<TW, F, Link>,
    pub(crate) spongos: Spongos<TW, F>,
}

impl<TW, F, Link> WrappedMessage<TW, F, Link>
where
    TW: SpongosTbitWord,
    F: PRP<TW>,
    Link: HasLink,
{
    /// Save link for the current wrapped message and accociated info into the store.
    pub fn commit<Store>(
        mut self,
        mut store: RefMut<Store>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<TbinaryMessage<TW, F, Link>>
    where
        Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
    {
        self.spongos.commit();
        store.update(self.message.link.rel(), self.spongos, info)?;
        Ok(self.message)
    }
}
