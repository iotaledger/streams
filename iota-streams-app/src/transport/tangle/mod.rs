//! Tangle-specific transport definitions.

use chrono::Utc;
use failure::Fallible;
use std::convert::AsRef;
use std::fmt;
use std::hash;
use std::string::ToString;

use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::{BasicTbitWord, SpongosTbitWord, StringTbitWord},
        Tbits,
    },
};
use iota_streams_core_mss::signature::mss;
use iota_streams_protobuf3::{command::*, io, types::*};

use crate::message::*;

pub struct TangleMessage<TW, F> {
    /// Encapsulated tbinary encoded message.
    pub tbinary_message: TbinaryMessage<TW, F, TangleAddress<TW>>,

    /// Timestamp is not an intrinsic part of Streams message; it's a part of the bundle.
    /// Timestamp is checked with Kerl as part of bundle essense trits.
    pub timestamp: i64,
}

impl<TW, F> TangleMessage<TW, F> {
    /// Create TangleMessage from TbinaryMessage and add the current timestamp.
    pub fn new(msg: TbinaryMessage<TW, F, TangleAddress<TW>>) -> Self {
        Self {
            tbinary_message: msg,
            timestamp: Utc::now().timestamp_millis(),
        }
    }
    /// Create TangleMessage from TbinaryMessage and an explicit timestamp.
    pub fn with_timestamp(msg: TbinaryMessage<TW, F, TangleAddress<TW>>, timestamp: i64) -> Self {
        Self {
            tbinary_message: msg,
            timestamp,
        }
    }
}

#[derive(Clone)]
pub struct TangleAddress<TW> {
    pub appinst: AppInst<TW>,
    pub msgid: MsgId<TW>,
}

impl<TW> fmt::Debug for TangleAddress<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{appinst: {:?}, msgid:{:?}}}", self.appinst, self.msgid)
    }
}

impl<TW> Default for TangleAddress<TW>
where
    TW: BasicTbitWord,
{
    fn default() -> Self {
        Self {
            appinst: AppInst::<TW>::default(),
            msgid: MsgId::<TW>::default(),
        }
    }
}

impl<TW> PartialEq for TangleAddress<TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.appinst == other.appinst && self.msgid == other.msgid
    }
}
impl<TW> Eq for TangleAddress<TW> where TW: BasicTbitWord {}

impl<TW> TangleAddress<TW> {
    pub fn new(appinst: AppInst<TW>, msgid: MsgId<TW>) -> Self {
        Self { appinst, msgid }
    }
}

impl<TW> hash::Hash for TangleAddress<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.appinst.hash(state);
        self.msgid.hash(state);
    }
}

impl<TW> HasLink for TangleAddress<TW>
where
    TW: BasicTbitWord,
{
    type Base = AppInst<TW>;
    fn base(&self) -> &AppInst<TW> {
        &self.appinst
    }

    type Rel = MsgId<TW>;
    fn rel(&self) -> &MsgId<TW> {
        &self.msgid
    }

    fn from_base_rel(base: &AppInst<TW>, rel: &MsgId<TW>) -> Self {
        Self {
            appinst: base.clone(),
            msgid: rel.clone(),
        }
    }
}

#[derive(Clone)]
pub struct DefaultTangleLinkGenerator<TW, F> {
    appinst: AppInst<TW>,
    counter: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<TW, F> Default for DefaultTangleLinkGenerator<TW, F>
where
    TW: BasicTbitWord,
{
    fn default() -> Self {
        Self {
            appinst: AppInst::<TW>::default(),
            counter: 0,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TW, F> DefaultTangleLinkGenerator<TW, F>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW> + Default,
{
    fn try_gen_msgid(&self, msgid: &MsgId<TW>) -> Fallible<MsgId<TW>> {
        let mut new = MsgId::default();
        wrap::Context::<TW, F, io::NoOStream>::new(io::NoOStream)
            .absorb(External(&self.appinst.id))?
            .absorb(External(&msgid.id))?
            .absorb(External(Size(self.counter)))?
            .commit()?
            .squeeze(External(&mut new.id))?;
        Ok(new)
    }
    fn gen_msgid(&self, msgid: &MsgId<TW>) -> MsgId<TW> {
        self.try_gen_msgid(msgid)
            .map_or(MsgId::<TW>::default(), |x| x)
    }
}

impl<TW, F, P> LinkGenerator<TW, TangleAddress<TW>, mss::PublicKey<TW, P>>
    for DefaultTangleLinkGenerator<TW, F>
where
    TW: StringTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW> + Default,
    P: mss::Parameters<TW>,
{
    fn link_from(&mut self, mss_pk: &mss::PublicKey<TW, P>) -> TangleAddress<TW> {
        debug_assert_eq!(P::PUBLIC_KEY_SIZE, mss_pk.tbits().size());
        self.appinst.id.0 = mss_pk.tbits().clone();

        self.counter += 1;
        TangleAddress {
            appinst: self.appinst.clone(),
            msgid: self.gen_msgid(&MsgId::<TW>::default()),
        }
    }

    fn header_from(
        &mut self,
        arg: &mss::PublicKey<TW, P>,
        content_type: &str,
    ) -> header::Header<TW, TangleAddress<TW>> {
        header::Header::new_with_type(self.link_from(arg), content_type)
    }
}

impl<TW, F> LinkGenerator<TW, TangleAddress<TW>, MsgId<TW>> for DefaultTangleLinkGenerator<TW, F>
where
    TW: StringTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW> + Default,
{
    fn link_from(&mut self, msgid: &MsgId<TW>) -> TangleAddress<TW> {
        self.counter += 1;
        TangleAddress {
            appinst: self.appinst.clone(),
            msgid: self.gen_msgid(msgid),
        }
    }
    fn header_from(
        &mut self,
        arg: &MsgId<TW>,
        content_type: &str,
    ) -> header::Header<TW, TangleAddress<TW>> {
        header::Header::new_with_type(self.link_from(arg), content_type)
    }
}

pub const APPINST_SIZE: usize = 243;

/// Application instance identifier.
/// Currently, 81-tryte string stored in `address` transaction field.
#[derive(Clone)]
pub struct AppInst<TW> {
    pub(crate) id: NTrytes<TW>,
}

impl<TW> fmt::Debug for AppInst<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.id)
    }
}

impl<TW> PartialEq for AppInst<TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl<TW> Eq for AppInst<TW> where TW: BasicTbitWord {}

impl<TW> AppInst<TW> {
    pub fn tbits(&self) -> &Tbits<TW> {
        &self.id.0
    }
}

impl<TW> AsRef<Tbits<TW>> for AppInst<TW> {
    fn as_ref(&self) -> &Tbits<TW> {
        &self.id.0
    }
}

impl<TW> Default for AppInst<TW>
where
    TW: BasicTbitWord,
{
    fn default() -> Self {
        Self {
            id: NTrytes(Tbits::zero(APPINST_SIZE)),
        }
    }
}

impl<TW> ToString for AppInst<TW>
where
    TW: StringTbitWord,
{
    fn to_string(&self) -> String {
        self.id.to_string()
    }
}

impl<TW> hash::Hash for AppInst<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// (appinst+msgid) is (address+tag) in terms of IOTA transaction which are stored
/// externally of message body, ie. in transaction header fields.
/// Thus the trait implemntation absorbs appinst+msgid as `external`.
impl<TW, F> AbsorbExternalFallback<TW, F> for TangleAddress<TW>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn sizeof_absorb_external(&self, ctx: &mut sizeof::Context<TW, F>) -> Fallible<()> {
        ctx.absorb(External(&self.appinst.id))?
            .absorb(External(&self.msgid.id))?;
        Ok(())
    }
    fn wrap_absorb_external<OS: io::OStream<TW>>(
        &self,
        ctx: &mut wrap::Context<TW, F, OS>,
    ) -> Fallible<()> {
        ctx.absorb(External(&self.appinst.id))?
            .absorb(External(&self.msgid.id))?;
        Ok(())
    }
    fn unwrap_absorb_external<IS: io::IStream<TW>>(
        &self,
        ctx: &mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<()> {
        ctx.absorb(External(&self.appinst.id))?
            .absorb(External(&self.msgid.id))?;
        Ok(())
    }
}

pub const MSGID_SIZE: usize = 81;

/// Message identifier unique within application instance.
/// Currently, 27-tryte string stored in `tag` transaction field.
#[derive(Clone)]
pub struct MsgId<TW> {
    pub(crate) id: NTrytes<TW>,
}

impl<TW> fmt::Debug for MsgId<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.id)
    }
}

impl<TW> PartialEq for MsgId<TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl<TW> Eq for MsgId<TW> where TW: BasicTbitWord {}

impl<TW> MsgId<TW> {
    pub fn tbits(&self) -> &Tbits<TW> {
        &self.id.0
    }
}

impl<TW> AsRef<Tbits<TW>> for MsgId<TW> {
    fn as_ref(&self) -> &Tbits<TW> {
        &self.id.0
    }
}

impl<TW> Default for MsgId<TW>
where
    TW: BasicTbitWord,
{
    fn default() -> Self {
        Self {
            id: NTrytes(Tbits::zero(MSGID_SIZE)),
        }
    }
}

impl<TW> ToString for MsgId<TW>
where
    TW: StringTbitWord,
{
    fn to_string(&self) -> String {
        self.id.to_string()
    }
}

impl<TW> hash::Hash for MsgId<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Msgid is used for joinable links which in the tbinary stream are simply
/// encoded (`skip`ped).
impl<TW, F> SkipFallback<TW, F> for MsgId<TW>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn sizeof_skip(&self, ctx: &mut sizeof::Context<TW, F>) -> Fallible<()> {
        ctx.skip(&self.id)?;
        Ok(())
    }
    fn wrap_skip<OS: io::OStream<TW>>(&self, ctx: &mut wrap::Context<TW, F, OS>) -> Fallible<()> {
        ctx.skip(&self.id)?;
        Ok(())
    }
    fn unwrap_skip<IS: io::IStream<TW>>(
        &mut self,
        ctx: &mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<()> {
        ctx.skip(&mut self.id)?;
        Ok(())
    }
}

//#[cfg(feature = "tangle")]
pub mod client;
