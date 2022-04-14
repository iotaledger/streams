// Rust

// 3rd-party
use anyhow::Result;

// IOTA

// Streams
use spongos::{
    PRP, ddml::commands::unwrap, Spongos,
};

// Local
use crate::message::{hdf::HDF, pcf::PCF};

/// Result of wrapping the message.
pub(crate) struct Message<F, Address, Content> {
    hdf: HDF<Address>,
    pcf: PCF<Content>,
    // TODO: CONSIDER TRANSFORMING THIS INTO THE SAME APPLICATION-LEVEL TYPE AS PREPARED. THIS MEANS SPONGOS IS RETURNED IN PreparsedMessage::unwrap, instead of inside UunwrappedMessage
    spongos: Spongos<F>,
}

impl<F, Address, Content> Message<F, Address, Content> {
    pub(crate) fn new(hdf: HDF<Address>, pcf: PCF<Content>, spongos: Spongos<F>) -> Self {
        Self {
            hdf, pcf, spongos
        }
    }
}

// impl<F, L, Content> UnwrappedMessage<F, L, Content>
// where
//     F: PRP,
//     L: Link,
// {
    // TODO: REMOVE (COMMIT IS DONE IN PREPARSED)
    // /// Save link for the current unwrapped message and associated info into the store.
    // fn commit<Store>(mut self, store: &mut Store, info: Store::Info) -> Result<Content>
    // where
    //     Store: LinkStore<F, L::Rel>,
    // {
    //     self.spongos.commit();
    //     store.update(self.link.rel(), self.spongos, info)?;
    //     Ok(self.pcf.content)
    // }
// }
