// Rust
use alloc::vec::Vec;
use core::fmt;

// 3rd-party
use anyhow::Result;

// IOTA

// Streams
use spongos::{
    ddml::{
        commands::{
            unwrap,
            Absorb,
        },
        modifiers::External,
    },
    PRP,
};

// Local
use crate::{
    link::Linked,
    message::{
        content::ContentUnwrap,
        hdf::HDF,
        preparsed::PreparsedMessage,
    },
};

/// Binary network Message representation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct TransportMessage<Address, Body> {
    /// Link -- message address.
    address: Address,

    // TODO: REMOVE
    // /// Previous Link -- previous message address
    // prev_msg: Address,
    /// Message body -- header + content.
    body: Body,
}

impl<Address, Body> TransportMessage<Address, Body> {
    pub(crate) fn new(address: Address, body: Body) -> Self {
        Self { address, body }
    }

    fn map<B, F: FnOnce(Body) -> B>(self, f: F) -> TransportMessage<Address, B> {
        TransportMessage {
            address: self.address,
            body: f(self.body),
        }
    }

    fn body(&self) -> &Body {
        &self.body
    }

    fn address(&self) -> &Address {
        &self.address
    }

    // TODO: REMOVE
    // fn map_err<B, F: FnOnce(Body) -> Result<B>>(self, f: F) -> Result<GenericMessage<AbsLink, B>> {
    //     let body = f(self.body)?;
    //     Ok(GenericMessage {
    //         link: self.link,
    //         prev_link: self.prev_link,
    //         body,
    //     })
    // }
}

// TODO: USE SOMEWHERE ELSE
// impl<AbsLink, Body> fmt::Debug for TransportMessage<AbsLink, Body>
// where
//     AbsLink: fmt::Debug,
//     Body: fmt::Debug,
// {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "@{:?}[{:?}]->{:?}", self.address, self.body, self.prev_msg)
//     }
// }

// impl<Address, Body> fmt::Display for TransportMessage<Address, Body>
// where
//     Address: fmt::Display,
//     Body: fmt::Display,
// {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "@{}[{}]->{}", self.address, self.body, self.prev_msg)
//     }
// }

impl<Address, T> TransportMessage<Address, T>
where
    T: AsRef<[u8]>,
    Address: Default + Clone,
{
    async fn parse_header<'b, F>(&'b self) -> Result<PreparsedMessage<'b, F, Address>>
    // where
    //     AbsLink: Clone + AbsorbExternalFallback<F> + HasLink,
    where
        unwrap::Context<F, &'b [u8]>: for<'a> Absorb<&'a mut Address> + for<'a> Absorb<External<&'a Address>>,
        F: PRP,
    {
        let mut ctx = unwrap::Context::new(self.body().as_ref());
        // TODO: REMOVE ONCE SURE THE PREVIOUS IS NOT NECESSARY
        // let mut header =
        //     HDF::<Address>::new(self.address().clone()).with_previous_msg_link(Bytes(self.previous().to_bytes()));
        let mut header = HDF::<Address>::default().with_address(self.address().clone());

        header.unwrap(&mut ctx).await?;

        Ok(PreparsedMessage::new(header, ctx))
    }
}
