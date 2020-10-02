use anyhow::Result;
use core::cell::RefMut;

use super::*;
use iota_streams_core::sponge::{
    prp::PRP,
    spongos::Spongos,
};
use iota_streams_ddml::link_store::LinkStore;

/// Result of wrapping the message.
pub struct WrappedMessage<F, Link> {
    pub message: BinaryMessage<F, Link>,
    pub(crate) spongos: Spongos<F>,
}

impl<F, Link> WrappedMessage<F, Link>
where
    F: PRP,
    Link: HasLink,
{
    /// Save link for the current wrapped message and accociated info into the store.
    pub fn commit<Store>(
        mut self,
        mut store: RefMut<Store>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<BinaryMessage<F, Link>>
    where
        Store: LinkStore<F, <Link as HasLink>::Rel>,
    {
        self.spongos.commit();
        store.update(self.message.link.rel(), self.spongos, info)?;
        Ok(self.message)
    }
}
