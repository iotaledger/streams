//! Tangle-specific transport definitions.

use anyhow::Result;
use core::{
    convert::AsRef,
    fmt,
    hash,
    str::FromStr,
};

use iota_streams_core::{
    prelude::Vec,
    sponge::prp::PRP,
};
// TODO: should ed25519 or x25519 public key used for link generation?
use iota_streams_core_edsig::key_exchange::x25519;
use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

use crate::message::*;

/// Number of bytes to be placed in each transaction (Maximum HDF Payload Count)
pub const PAYLOAD_BYTES: usize = 1090;

pub struct TangleMessage<F> {
    /// Encapsulated binary encoded message.
    pub binary_message: BinaryMessage<F, TangleAddress>,

    /// Timestamp is not an intrinsic part of Streams message; it's a part of the bundle.
    /// Timestamp is checked with Kerl as part of bundle essense trits.
    pub timestamp: i64,
}

#[cfg(feature = "std")]
impl<F> TangleMessage<F> {
    /// Create TangleMessage from BinaryMessage and add the current timestamp.
    pub fn new(msg: BinaryMessage<F, TangleAddress>) -> Self {
        Self {
            binary_message: msg,
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }
}

impl<F> TangleMessage<F> {
    /// Create TangleMessage from BinaryMessage and an explicit timestamp.
    pub fn with_timestamp(msg: BinaryMessage<F, TangleAddress>, timestamp: i64) -> Self {
        Self {
            binary_message: msg,
            timestamp,
        }
    }
}

#[derive(Clone)]
pub struct TangleAddress {
    pub appinst: AppInst,
    pub msgid: MsgId,
}

impl TangleAddress {
    pub fn from_str(appinst_str: &str, msgid_str: &str) -> Result<Self, ()> {
        let appinst = AppInst::from_str(appinst_str)?;
        let msgid = MsgId::from_str(msgid_str)?;
        Ok(TangleAddress { appinst, msgid })
    }
}

impl fmt::Debug for TangleAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{appinst: {:?}, msgid:{:?}}}", self.appinst, self.msgid)
    }
}

impl fmt::Display for TangleAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{appinst: {}, msgid:{}}}", self.appinst, self.msgid)
    }
}

impl Default for TangleAddress {
    fn default() -> Self {
        Self {
            appinst: AppInst::default(),
            msgid: MsgId::default(),
        }
    }
}

impl PartialEq for TangleAddress {
    fn eq(&self, other: &Self) -> bool {
        self.appinst == other.appinst && self.msgid == other.msgid
    }
}
impl Eq for TangleAddress {}

impl TangleAddress {
    pub fn new(appinst: AppInst, msgid: MsgId) -> Self {
        Self { appinst, msgid }
    }
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

#[derive(Clone)]
pub struct DefaultTangleLinkGenerator<F> {
    appinst: AppInst,
    _phantom: core::marker::PhantomData<F>,
}

impl<F> Default for DefaultTangleLinkGenerator<F> {
    fn default() -> Self {
        Self {
            appinst: AppInst::default(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F> DefaultTangleLinkGenerator<F> {
    pub fn reset_appinst(&mut self, appinst: AppInst) {
        self.appinst = appinst;
    }
}

impl<F> DefaultTangleLinkGenerator<F>
where
    F: PRP,
{
    fn try_gen_msgid(&self, msgid: &MsgId, pk: &x25519::PublicKey, seq: usize) -> Result<MsgId> {
        let mut new = MsgId::default();
        //println!("Making new id with: {:?}, {:?}, {:?}", msgid.id.to_string(), multi_branch, seq);
        wrap::Context::<F, io::NoOStream>::new(io::NoOStream)
            .absorb(External(&self.appinst.id))?
            .absorb(External(pk))?
            .absorb(External(&msgid.id))?
            .absorb(External(Size(seq)))?
            //TODO: do we need `flags` here
            //.absorb(External(Uint8(flags)))?
            .commit()?
            .squeeze(External(&mut new.id))?;
        Ok(new)
    }
    fn gen_msgid(&self, msgid: &MsgId, pk: &x25519::PublicKey, seq: usize) -> MsgId {
        self.try_gen_msgid(msgid, pk, seq)
            .map_or(MsgId::default(), |x| x)
    }
}

impl<F> LinkGenerator<TangleAddress, (Vec<u8>, x25519::PublicKey, usize)> for DefaultTangleLinkGenerator<F>
where
    F: PRP,
{
    //TODO: turn into a tuple of refs instead of ref to a tuple to avoid arg copying
    fn link_from(&mut self, arg: &(Vec<u8>, x25519::PublicKey, usize)) -> TangleAddress {
        let (appinst, pk, seq) = arg;
        self.appinst.id.0 = appinst.to_vec();
        TangleAddress {
            appinst: self.appinst.clone(),
            msgid: self.gen_msgid(&MsgId::default(), pk, *seq),
        }
    }

    fn header_from(
        &mut self,
        arg: &(Vec<u8>, x25519::PublicKey, usize),
        content_type: Uint8,
        payload_length: usize,
    ) -> hdf::HDF<TangleAddress> {
        hdf::HDF::new_with_fields(self.link_from(arg),
                                  content_type,
                                  payload_length,
                                  arg.2
        )}
}

impl<F> LinkGenerator<TangleAddress, (MsgId, x25519::PublicKey, usize)> for DefaultTangleLinkGenerator<F>
where
    F: PRP,
{
    fn link_from(&mut self, arg: &(MsgId, x25519::PublicKey, usize)) -> TangleAddress {
        let (msgid, pk, seq) = arg;
        TangleAddress {
            appinst: self.appinst.clone(),
            msgid: self.gen_msgid(msgid, pk, *seq),
        }
    }
    fn header_from(
        &mut self,
        arg: &(MsgId, x25519::PublicKey, usize),
        content_type: Uint8,
        payload_length: usize,
    ) -> hdf::HDF<TangleAddress> {
        hdf::HDF::new_with_fields(self.link_from(arg),
                                  content_type,
                                  payload_length,
                                  arg.2
        )}
}

// ed25519 public key size in bytes
pub const APPINST_SIZE: usize = 32;

/// Application instance identifier.
/// Currently, 81-byte string stored in `address` transaction field.
#[derive(Clone)]
pub struct AppInst {
    pub(crate) id: NBytes,
}

impl FromStr for AppInst {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        // TODO: format for `s`: Bech32 (https://github.com/rust-bitcoin/rust-bech32)
        // currently lowercase hex
        hex::decode(s).map_or(Err(()), |x| Ok(AppInst { id: NBytes(x) }))
    }
}

impl fmt::Debug for AppInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.id)
    }
}

impl fmt::Display for AppInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.id.0))
    }
}

impl PartialEq for AppInst {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for AppInst {}

impl AppInst {
    pub fn tbits(&self) -> &Vec<u8> {
        &self.id.0
    }
}

impl AsRef<Vec<u8>> for AppInst {
    fn as_ref(&self) -> &Vec<u8> {
        &self.id.0
    }
}

impl Default for AppInst {
    fn default() -> Self {
        Self {
            id: NBytes(vec![0; APPINST_SIZE]),
        }
    }
}

// impl ToString for AppInst
// {
// fn to_string(&self) -> String {
// self.id.to_string()
// }
// }

impl hash::Hash for AppInst {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// (appinst+msgid) is (address+tag) in terms of IOTA transaction which are stored
/// externally of message body, ie. in transaction header fields.
/// Thus the trait implemntation absorbs appinst+msgid as `external`.
impl<F> AbsorbExternalFallback<F> for TangleAddress
where
    F: PRP,
{
    fn sizeof_absorb_external(&self, ctx: &mut sizeof::Context<F>) -> Result<()> {
        ctx.absorb(External(&self.appinst.id))?
            .absorb(External(&self.msgid.id))?;
        Ok(())
    }
    fn wrap_absorb_external<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()> {
        ctx.absorb(External(&self.appinst.id))?
            .absorb(External(&self.msgid.id))?;
        Ok(())
    }
    fn unwrap_absorb_external<IS: io::IStream>(&self, ctx: &mut unwrap::Context<F, IS>) -> Result<()> {
        ctx.absorb(External(&self.appinst.id))?
            .absorb(External(&self.msgid.id))?;
        Ok(())
    }
}

pub const MSGID_SIZE: usize = 12;

/// Message identifier unique within application instance.
/// Currently, 27-byte string stored in `tag` transaction field.
#[derive(Clone)]
pub struct MsgId {
    // TODO: change to [u8; MSGID_SIZE],
    pub(crate) id: NBytes,
}

impl FromStr for MsgId {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        // TODO: format for `s`: Bech32 (https://github.com/rust-bitcoin/rust-bech32)
        // currently lowercase hex
        hex::decode(s).map_or(Err(()), |x| Ok(MsgId { id: NBytes(x) }))
    }
}

impl From<NBytes> for MsgId {
    fn from(b: NBytes) -> Self {
        Self { id: b }
    }
}

impl fmt::Debug for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.id)
    }
}

impl fmt::Display for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.id.0))
    }
}

impl PartialEq for MsgId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for MsgId {}

impl MsgId {
    pub fn tbits(&self) -> &Vec<u8> {
        &self.id.0
    }
}

impl AsRef<Vec<u8>> for MsgId {
    fn as_ref(&self) -> &Vec<u8> {
        &self.id.0
    }
}

impl Default for MsgId {
    fn default() -> Self {
        Self {
            id: NBytes(vec![0; MSGID_SIZE]),
        }
    }
}

// impl ToString for MsgId
// {
// fn to_string(&self) -> String {
// self.id.to_string()
// }
// }

impl hash::Hash for MsgId {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Msgid is used for joinable links which in the binary stream are simply
/// encoded (`skip`ped).
impl<F> SkipFallback<F> for MsgId {
    fn sizeof_skip(&self, ctx: &mut sizeof::Context<F>) -> Result<()> {
        ctx.skip(&self.id)?;
        Ok(())
    }
    fn wrap_skip<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()> {
        ctx.skip(&self.id)?;
        Ok(())
    }
    fn unwrap_skip<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()> {
        ctx.skip(&mut self.id)?;
        Ok(())
    }
}

#[cfg(all(feature = "tangle", feature = "async"))]
pub mod client;
