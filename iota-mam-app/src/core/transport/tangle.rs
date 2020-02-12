//! Tangle-specific transport definitions.

use std::convert::AsRef;
use std::hash;
use std::string::ToString;

use iota_mam_core::{signature::mss, trits::Trits};
use iota_mam_protobuf3 as protobuf3;
use protobuf3::{command::*, types::*, io, sizeof, wrap, unwrap};

use crate::core::*;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct TangleAddress {
    appinst: AppInst,
    msgid: MsgId,
}

impl hash::Hash for TangleAddress {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.appinst.hash(state);
        self.msgid.hash(state);
    }
}

impl HasLink for TangleAddress {
    type Base = AppInst;
    fn base(&self) -> &AppInst {
        &self.appinst
    }

    type Rel = MsgId;
    fn rel(&self) -> &MsgId {
        &self.msgid
    }

    fn from_base_rel(base: &AppInst, rel: &MsgId) -> Self {
        Self {
            appinst: base.clone(),
            msgid: rel.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DefaultTangleLinkGenerator {
    appinst: AppInst,
    counter: usize,
}

impl DefaultTangleLinkGenerator {
    fn try_gen_msgid(&self, msgid: &MsgId) -> Result<MsgId> {
        let mut new = MsgId::default();
        wrap::Context::new(io::NoOStream)
            .absorb(External(&self.appinst.id))?
            .absorb(External(&msgid.id))?
            .absorb(External(Size(self.counter)))?
            .commit()?
            .squeeze(External(&mut new.id))?
            ;
        Ok(new)
    }
    fn gen_msgid(&self, msgid: &MsgId) -> MsgId {
        self.try_gen_msgid(msgid).map_or(MsgId::default(), |x|x)
    }
}

impl LinkGenerator<TangleAddress, mss::PublicKey> for DefaultTangleLinkGenerator {
    fn link_from(&mut self, mss_pk: &mss::PublicKey) -> TangleAddress {
        debug_assert_eq!(mss::PK_SIZE, mss_pk.pk.size());
        self.appinst.id.0 = mss_pk.pk.clone();

        self.counter += 1;
        TangleAddress {
            appinst: self.appinst.clone(),
            msgid: self.gen_msgid(&MsgId::default()),
        }
    }
}

impl LinkGenerator<TangleAddress, MsgId> for DefaultTangleLinkGenerator {
    fn link_from(&mut self, msgid: &MsgId) -> TangleAddress {
        self.counter += 1;
        TangleAddress {
            appinst: self.appinst.clone(),
            msgid: self.gen_msgid(msgid),
        }
    }
}


pub const APPINST_SIZE: usize = 243;

/// Application instance identifier.
/// Currently, 81-tryte string stored in `address` transaction field.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AppInst {
    pub(crate) id: NTrytes,
}

impl AppInst {
    pub fn id(&self) -> &Trits {
        &self.id.0
    }
}

impl AsRef<Trits> for AppInst {
    fn as_ref(&self) -> &Trits {
        &self.id.0
    }
}

impl Default for AppInst {
    fn default() -> Self {
        Self {
            id: NTrytes(Trits::zero(APPINST_SIZE)),
        }
    }
}

impl ToString for AppInst {
    fn to_string(&self) -> String {
        self.id.to_string()
    }
}

impl hash::Hash for AppInst {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// (appinst+msgid) is (address+tag) in terms of IOTA transaction which are stored
/// externally of message body, ie. in transaction header fields.
/// Thus the trait implemntation absorbs appinst+msgid as `external`.
impl AbsorbExternalFallback for TangleAddress {
    fn sizeof_absorb_external(&self, ctx: &mut sizeof::Context) -> Result<()> {
        ctx.absorb(External(&self.appinst.id))?.absorb(External(&self.msgid.id))?;
        Ok(())
    }
    fn wrap_absorb_external<OS: io::OStream>(&self, ctx: &mut wrap::Context<OS>) -> Result<()> {
        ctx.absorb(External(&self.appinst.id))?.absorb(External(&self.msgid.id))?;
        Ok(())
    }
    fn unwrap_absorb_external<IS: io::IStream>(&self, ctx: &mut unwrap::Context<IS>) -> Result<()> {
        ctx.absorb(External(&self.appinst.id))?.absorb(External(&self.msgid.id))?;
        Ok(())
    }
}

pub const MSGID_SIZE: usize = 81;

/// Message identifier unique within application instance.
/// Currently, 27-tryte string stored in `tag` transaction field.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct MsgId {
    pub(crate) id: NTrytes,
}

impl MsgId {
    pub fn id(&self) -> &Trits {
        &self.id.0
    }
}

impl AsRef<Trits> for MsgId {
    fn as_ref(&self) -> &Trits {
        &self.id.0
    }
}

impl Default for MsgId {
    fn default() -> Self {
        Self {
            id: NTrytes(Trits::zero(MSGID_SIZE)),
        }
    }
}

impl ToString for MsgId {
    fn to_string(&self) -> String {
        self.id.to_string()
    }
}

impl hash::Hash for MsgId {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Msgid is used for joinable links which in the trinary stream are simply
/// encoded (`skip`ped).
impl SkipFallback for MsgId {
    fn sizeof_skip(&self, ctx: &mut sizeof::Context) -> Result<()> {
        ctx.skip(&self.id)?;
        Ok(())
    }
    fn wrap_skip<OS: io::OStream>(&self, ctx: &mut wrap::Context<OS>) -> Result<()> {
        ctx.skip(&self.id)?;
        Ok(())
    }
    fn unwrap_skip<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()> {
        ctx.skip(&mut self.id)?;
        Ok(())
    }
}


