//! Tangle-specific transport definitions.

use anyhow::Result;
use core::{
    convert::AsRef,
    fmt,
    hash,
    str::FromStr,
};

use iota_streams_core::{
    prelude::typenum::{
        U12,
        U40,
    },
    sponge::prp::PRP,
};
use iota_streams_core_edsig::signature::ed25519;
use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

use crate::message::{
    BinaryMessage,
    HasLink,
    LinkGenerator,
};

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
        write!(f, "<{:?}:{:?}>", self.appinst, self.msgid)
    }
}

impl fmt::Display for TangleAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}:{}>", self.appinst, self.msgid)
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
    addr: TangleAddress,
    _phantom: core::marker::PhantomData<F>,
}

impl<F> Default for DefaultTangleLinkGenerator<F> {
    fn default() -> Self {
        Self {
            addr: TangleAddress::default(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F> DefaultTangleLinkGenerator<F> {
    pub fn reset_addr(&mut self, addr: TangleAddress) {
        self.addr = addr;
    }
}

impl<F: PRP> DefaultTangleLinkGenerator<F> {
    fn gen_msgid(&self, msgid: &MsgId, pk: &ed25519::PublicKey, seq: usize) -> MsgId {
        let mut new = MsgId::default();
        // println!("Making new id with: {:?}, {:?}, {:?}", msgid.id.to_string(), multi_branch, seq);
        wrap::Context::<F, io::NoOStream>::new(io::NoOStream)
            .absorb(External(&self.addr.appinst.id))
            .unwrap()
            .absorb(External(pk))
            .unwrap()
            .absorb(External(&msgid.id))
            .unwrap()
            .absorb(External(Size(seq)))
            .unwrap()
            // TODO: do we need `flags` here
            //.absorb(External(Uint8(flags)))?
            .commit()
            .unwrap()
            .squeeze(External(&mut new.id))
            .unwrap();
        new
    }
}

// Used by Author to generate a new application instance: channels address and announcement message identifier
impl<'a, F: PRP> LinkGenerator<TangleAddress, (&'a ed25519::PublicKey, u64)> for DefaultTangleLinkGenerator<F> {
    fn link_from(&mut self, arg: (&ed25519::PublicKey, u64)) -> TangleAddress {
        let (pk, channel_idx) = arg;
        self.addr.appinst = AppInst::new(pk, channel_idx);
        self.addr.msgid = self.gen_msgid(&self.addr.msgid, pk, 0);
        self.addr.clone()
    }
}

// Used by Subscriber to initialize link generator with the same state as Author
impl<F: PRP> LinkGenerator<TangleAddress, TangleAddress> for DefaultTangleLinkGenerator<F> {
    fn link_from(&mut self, arg: TangleAddress) -> TangleAddress {
        self.addr = arg;
        self.addr.clone()
    }
}

// Used by Author to generate announcement message id, it's just stored internally by link generator
impl<F: PRP> LinkGenerator<TangleAddress, ()> for DefaultTangleLinkGenerator<F> {
    fn link_from(&mut self, _arg: ()) -> TangleAddress {
        self.addr.clone()
    }
}

// Used by users to pseudo-randomly generate a new message link from additional arguments
impl<'a, F> LinkGenerator<TangleAddress, (&'a MsgId, &'a ed25519::PublicKey, usize)> for DefaultTangleLinkGenerator<F>
where
    F: PRP,
{
    fn link_from(&mut self, arg: (&MsgId, &ed25519::PublicKey, usize)) -> TangleAddress {
        let (msgid, pk, seq) = arg;
        TangleAddress {
            appinst: self.addr.appinst.clone(),
            msgid: self.gen_msgid(msgid, pk, seq),
        }
    }
}

// ed25519 public key size in bytes + 64-bit additional index
pub type AppInstSize = U40;
pub const APPINST_SIZE: usize = 40;

/// Application instance identifier.
/// Currently, 81-byte string stored in `address` transaction field.
#[derive(Clone)]
pub struct AppInst {
    pub(crate) id: NBytes<AppInstSize>,
}

impl AppInst {
    pub fn new(pk: &ed25519::PublicKey, channel_idx: u64) -> Self {
        let mut id = [0_u8; APPINST_SIZE];
        id[..32].copy_from_slice(pk.as_bytes());
        id[32..].copy_from_slice(&channel_idx.to_be_bytes());
        Self {
            id: unsafe { core::mem::transmute(id) },
        }
    }
}

impl<'a> From<&'a [u8]> for AppInst {
    fn from(v: &[u8]) -> AppInst {
        AppInst {
            // TODO: Implement safer TryFrom or force check for length at call site.
            id: *<&NBytes<AppInstSize>>::from(v),
        }
    }
}

// impl TryFrom<[u8; 32]> for AppInst {
// type Error = ();
// fn try_from(v: [u8; 32]) -> Result<Self, ()> {
// if v.len() == AppInstSize::to_usize() {
// Ok(Self{ id: NBytes(v) })
// } else {
// Err(())
// }
// }
// }

impl FromStr for AppInst {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        // TODO: format for `s`: Bech32 (https://github.com/rust-bitcoin/rust-bech32)
        // currently lowercase hex
        hex::decode(s).map_or(Err(()), |x| {
            if x.len() == AppInstSize::USIZE {
                Ok(AppInst {
                    id: *<&NBytes<AppInstSize>>::from(&x[..]),
                })
            } else {
                Err(())
            }
        })
    }
}

impl fmt::Debug for AppInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.id))
    }
}

impl fmt::Display for AppInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.id))
    }
}

impl PartialEq for AppInst {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for AppInst {}

impl AsRef<[u8]> for AppInst {
    fn as_ref(&self) -> &[u8] {
        self.id.as_ref()
    }
}

impl Default for AppInst {
    fn default() -> Self {
        Self { id: NBytes::default() }
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

pub type MsgIdSize = U12;
pub const MSGID_SIZE: usize = 12;

/// Message identifier unique within application instance.
/// Currently, 27-byte string stored in `tag` transaction field.
#[derive(Clone)]
pub struct MsgId {
    pub(crate) id: NBytes<MsgIdSize>,
}

impl<'a> From<&'a [u8]> for MsgId {
    fn from(v: &[u8]) -> MsgId {
        MsgId {
            // TODO: Implement safer TryFrom or force check for length at call site.
            id: *<&NBytes<MsgIdSize>>::from(v),
        }
    }
}

impl FromStr for MsgId {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        // TODO: format for `s`: Bech32 (https://github.com/rust-bitcoin/rust-bech32)
        // currently lowercase hex
        hex::decode(s).map_or(Err(()), |x| {
            if x.len() == MsgIdSize::USIZE {
                Ok(MsgId {
                    id: *<&NBytes<MsgIdSize>>::from(&x[..]),
                })
            } else {
                Err(())
            }
        })
    }
}

impl From<NBytes<MsgIdSize>> for MsgId {
    fn from(b: NBytes<MsgIdSize>) -> Self {
        Self { id: b }
    }
}

impl fmt::Debug for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.id))
    }
}

impl fmt::Display for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.id))
    }
}

impl PartialEq for MsgId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for MsgId {}

impl AsRef<[u8]> for MsgId {
    fn as_ref(&self) -> &[u8] {
        self.id.as_ref()
    }
}

impl Default for MsgId {
    fn default() -> Self {
        Self { id: NBytes::default() }
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

impl<F: PRP> AbsorbFallback<F> for MsgId {
    fn sizeof_absorb(&self, ctx: &mut sizeof::Context<F>) -> Result<()> {
        ctx.absorb(&self.id)?;
        Ok(())
    }
    fn wrap_absorb<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()> {
        ctx.absorb(&self.id)?;
        Ok(())
    }
    fn unwrap_absorb<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()> {
        ctx.absorb(&mut self.id)?;
        Ok(())
    }
}

#[cfg(feature = "client")]
pub mod client;
