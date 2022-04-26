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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct TransportMessage<Body> {
    // TODO: CONSIDER REMOVING ADDRESS FROM TRANSPORTMESSAGE
    /// Link -- message address.
    // address: Address,

    // TODO: REMOVE
    // /// Previous Link -- previous message address
    // prev_msg: Address,
    /// Message body -- header + content.
    body: Body,
}

impl<Body> TransportMessage<Body> {
    pub(crate) fn new(body: Body) -> Self {
        Self { body }
    }

    fn map<B, F: FnOnce(Body) -> B>(self, f: F) -> TransportMessage<B> {
        TransportMessage {
            // address: self.address,
            body: f(self.body),
        }
    }

    fn body(&self) -> &Body {
        &self.body
    }

    // fn address(&self) -> &Address {
    //     &self.address
    // }

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

impl<T> TransportMessage<T>
where
    T: AsRef<[u8]>,
{
    pub async fn parse_header<'a, F, Address>(&'a self) -> Result<PreparsedMessage<'a, F, Address>>
    // where
    //     AbsLink: Clone + AbsorbExternalFallback<F> + HasLink,
    where
        // unwrap::Context<F, &'a [u8]>: for<'b> Absorb<&'b mut Address> + for<'b> Absorb<External<&'b Address>>,
        unwrap::Context<F, &'a [u8]>: ContentUnwrap<HDF<Address>>,
        F: PRP + Default,
        Address: Default,
    {
        let mut ctx = unwrap::Context::new(self.body().as_ref());
        // TODO: REMOVE ONCE SURE THE PREVIOUS IS NOT NECESSARY
        // let mut header =
        //     HDF::<Address>::new(self.address().clone()).with_previous_msg_link(Bytes(self.previous().to_bytes()));
        let mut header = HDF::default();

        ctx.unwrap(&mut header).await?;

        Ok(PreparsedMessage::new(header, ctx))
    }
}
