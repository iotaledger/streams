//! Customize Subscriber with default parameters for use over the Tangle.

use std::str::FromStr;
use iota_mam_core::{prng, trits::Trits};
use iota_mam_protobuf3::types::Trytes;
use crate::core::{*, msg::{*, header::Header}};
use crate::channel::api::{*, subscriber::*};
use crate::Result;
use super::*;

/// Subscriber type.
pub struct Subscriber {
    imp: SubscriberT<Address, Store, LinkGen>,
}

impl Subscriber {
    pub fn new(seed: &str, with_ntru: bool) -> Self {
        let nonce = Trits::from_str("TANGLESUBSCRIBER").unwrap();
        Self {
            imp: SubscriberT::gen(Store::default(), LinkGen::default(), prng::dbg_init_str(seed), &nonce, with_ntru)
        }
    }

    pub fn unwrap_announcement<'a>(&mut self, preparsed: PreparsedMessage<'a, Address>) -> Result<()> {
        self.imp.handle_announcement(preparsed, MsgInfo::Announce)?;
        Ok(())
    }

    pub fn unwrap_change_key<'a>(&mut self, preparsed: PreparsedMessage<'a, Address>) -> Result<()> {
        self.imp.handle_change_key(preparsed, MsgInfo::ChangeKey)?;
        Ok(())
    }

    pub fn unwrap_keyload<'a>(&mut self, preparsed: PreparsedMessage<'a, Address>) -> Result<()> {
        //self.imp.handle_keyload(preparsed, MsgInfo::Keyload)?;
        Ok(())
    }

    pub fn unwrap_signed_packet<'a>(&mut self, preparsed: PreparsedMessage<'a, Address>) -> Result<(Trytes, Trytes)> {
        self.imp.handle_signed_packet(preparsed, MsgInfo::SignedPacket)
    }

    pub fn unwrap_tagged_packet<'a>(&mut self, preparsed: PreparsedMessage<'a, Address>) -> Result<(Trytes, Trytes)> {
        self.imp.handle_tagged_packet(preparsed, MsgInfo::TaggedPacket)
    }
}
