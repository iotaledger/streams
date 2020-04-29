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

/// Result of unwrapping the message.
pub struct UnwrappedMessage<TW, F, Link, Content> {
    pub link: Link,
    pub content: Content,
    pub(crate) spongos: Spongos<TW, F>,
}

impl<TW, F, Link, Content> UnwrappedMessage<TW, F, Link, Content>
where
    TW: SpongosTbitWord,
    F: PRP<TW>,
    Link: HasLink,
{
    /// Save link for the current unwrapped message and accociated info into the store.
    pub fn commit<Store>(
        mut self,
        mut store: RefMut<Store>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<Content>
    where
        Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
    {
        self.spongos.commit();
        store.update(self.link.rel(), self.spongos, info)?;
        Ok(self.content)
    }
}
