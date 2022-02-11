use core::convert::{
    TryFrom,
    TryInto,
};

use iota_streams_core::{
    err,
    sponge::prp::PRP,
    Errors::BadMessageInfo,
    Result,
};
use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

/// Message associated info stored internally in User context, just message type indicator.
#[derive(Copy, Clone)]
pub enum MsgInfo {
    Announce,
    Keyload,
    SignedPacket,
    TaggedPacket,
    Subscribe,
    Unsubscribe,
    Sequence,
}

// Default instance is required by ddml unwrap logic as unwrap modifies/updates an existing object rather producing a
// new one.
impl Default for MsgInfo {
    fn default() -> Self {
        MsgInfo::Announce
    }
}

impl From<MsgInfo> for u8 {
    fn from(i: MsgInfo) -> Self {
        match i {
            MsgInfo::Announce => 0,
            MsgInfo::Keyload => 1,
            MsgInfo::SignedPacket => 2,
            MsgInfo::TaggedPacket => 3,
            MsgInfo::Subscribe => 4,
            MsgInfo::Unsubscribe => 5,
            MsgInfo::Sequence => 6,
        }
    }
}

impl From<&MsgInfo> for u8 {
    fn from(i: &MsgInfo) -> Self {
        (*i).into()
    }
}

impl TryFrom<u8> for MsgInfo {
    type Error = ();
    fn try_from(x: u8) -> Result<Self, ()> {
        match x {
            0 => Ok(MsgInfo::Announce),
            1 => Ok(MsgInfo::Keyload),
            2 => Ok(MsgInfo::SignedPacket),
            3 => Ok(MsgInfo::TaggedPacket),
            4 => Ok(MsgInfo::Subscribe),
            5 => Ok(MsgInfo::Unsubscribe),
            6 => Ok(MsgInfo::Sequence),
            _ => Err(()),
        }
    }
}

impl<F: PRP> AbsorbFallback<F> for MsgInfo {
    fn sizeof_absorb(&self, ctx: &mut sizeof::Context<F>) -> Result<()> {
        ctx.absorb(Uint8(0))?;
        Ok(())
    }
    fn wrap_absorb<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()> {
        ctx.absorb(Uint8(self.into()))?;
        Ok(())
    }
    fn unwrap_absorb<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()> {
        let mut x = Uint8(0);
        ctx.absorb(&mut x)?;
        match x.0.try_into() {
            Ok(i) => {
                *self = i;
                Ok(())
            }
            Err(_) => err!(BadMessageInfo(x.0)),
        }
    }
}
