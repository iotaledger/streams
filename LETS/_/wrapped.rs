use core::fmt;
use iota_streams_core::Result;

use super::*;
use iota_streams_core::sponge::{
    prp::PRP,
    spongos::Spongos,
};
use iota_streams_ddml::link_store::LinkStore;

/// Spongos state and representative Link identifier
struct WrapState<F, Link> {
    link: Link,
    pub(crate) spongos: Spongos<F>,
}

impl<F, Link> WrapState<F, Link>
where
    F: PRP,
    Link: HasLink,
{
    /// Save link for the current wrapped message and associated info into the store.
    fn commit<Store>(mut self, store: &mut Store, info: Store::Info) -> Result<Link>
    where
        Store: LinkStore<F, Link::Rel>,
    {
        self.spongos.commit();
        store.update(self.link.rel(), self.spongos, info)?;
        Ok(self.link)
    }
}

impl<F: PRP, Link> fmt::Debug for WrapState<F, Link>
where
    Link: HasLink + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WrapState({:?})[{:?}]", self.link, self.spongos)
    }
}

/// Result of wrapping the message.
struct WrappedMessage<F, Link: HasLink> {
    message: BinaryMessage<Link>,
    wrapped: WrapState<F, Link>,
}

// TODO: REMOVE
// impl<F: PRP, Link: HasLink> WrappedMessage<F, Link>
// {
// Save link for the current wrapped message and accociated info into the store.
// fn commit<Store>(
// mut self,
// mut store: RefMut<Store>,
// info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
// ) -> Result<BinaryMessage<F, Link>> where
// Store: LinkStore<F, <Link as HasLink>::Rel>,
// {
// self.wrapped.commit(store, info)?;
// Ok(self.message)
// }
// }
