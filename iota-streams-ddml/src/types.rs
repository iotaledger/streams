use anyhow::{
    bail,
    Result,
};
use core::{
    convert::{
        AsMut,
        AsRef,
    },
    fmt,
    hash,
};
use digest::{
    generic_array::{
        typenum::U64,
        GenericArray,
    },
    Digest,
};

use iota_streams_core::{
    prelude::{
        HashMap,
        Vec,
    },
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
};

use crate::io;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Uint8(pub u8);

impl fmt::Display for Uint8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Uint16(pub u16);

/// Fixed-size array of bytes, the size is known at compile time and is not encoded in trinary representation.
// TODO: PartialEq, Eq, Debug
#[derive(Clone)]
pub struct NBytes(pub Vec<u8>);

impl fmt::Debug for NBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for NBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl PartialEq for NBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for NBytes {}

impl NBytes {
    pub fn zero(n: usize) -> Self {
        Self(vec![0; n])
    }
}

// impl ToString for NBytes
// {
// fn to_string(&self) -> String {
// (self.0).to_string()
// }
// }

impl hash::Hash for NBytes {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}

/// Variable-size array of bytes, the size is not known at compile time and is encoded in trinary representation.
// TODO: PartialEq, Eq, Clone, Debug
#[derive(Clone)]
pub struct Bytes(pub Vec<u8>);

impl Default for Bytes {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Bytes {}

// impl ToString for Bytes
// {
// fn to_string(&self) -> String {
// (self.0).to_string()
// }
// }

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO:
        write!(f, "{:?}", self.0)
    }
}

impl hash::Hash for Bytes {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}

/// The value wrapped in Mac is just the size of message authentication tag (MAC) in trits.
/// The actual trits are not important. The requested amount of trits is squeezed
/// from Spongos and encoded in the trinary stream during Wrap operation.
/// During Unwrap operation the requested amount of trits is squeezed from Spongos
/// and compared to the trits encoded in the trinary stream.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct Mac(pub usize);

/// Mssig command modifier, it instructs Context to squeeze external hash value, commit
/// spongos state, sign squeezed hash and encode (without absorbing!) signature.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct HashSig;

// impl Default for Mac {
// fn default() -> Self {
// Self(spongos::MAC_SIZE)
// }
// }

/// PB3 `size_t` type, unsigned.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Size(pub usize);

/// Max value of `size_t` type: `(27^13 - 1) / 2`.
pub const SIZE_MAX: usize = 2_026_277_576_509_488_133;

/// Number of bytes needed to encode a value of `size_t` type.
pub fn size_bytes(mut n: usize) -> usize {
    let mut d = 0_usize;
    while n > 0 {
        n = n >> 8;
        d += 1;
    }
    d
}

pub fn sizeof_sizet(n: usize) -> usize {
    size_bytes(n) + 1
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Size({})", self.0)
    }
}

/// PB3 `external` modifier, it changes behaviour of commands in the following way.
/// The external field is not encoded in trinary representation and the value is stored in the environment implicitly.
#[derive(PartialEq, Eq, Copy, Clone, Debug, Default)]
pub struct External<T>(pub T);

#[derive(Default)]
pub(crate) struct Prehashed(pub GenericArray<u8, U64>);

impl Digest for Prehashed {
    type OutputSize = U64;

    fn new() -> Self {
        Self::default()
    }

    fn input<B: AsRef<[u8]>>(&mut self, _data: B) {}

    fn chain<B: AsRef<[u8]>>(self, _data: B) -> Self {
        self
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.0
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        self.0.clone()
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn output_size() -> usize {
        64
    }

    fn digest(_data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        GenericArray::default()
    }
}

/// The `link` type is generic and transport-specific. Links can be address+tag pair
/// when messages are published in the Tangle. Or links can be a URL when HTTP is used.
/// Or links can be a message sequence number in a stream/socket.
pub trait LinkStore<F, Link> {
    /// Additional data associated with the current message link/spongos state.
    /// This type is implementation specific, meaning different configurations
    /// of a Streams Application can use different Info types.
    type Info;

    /// Lookup link in the store and return spongos state and associated info.
    fn lookup(&self, _link: &Link) -> Result<(Spongos<F>, Self::Info)> {
        bail!("Link not found.");
    }

    /// Put link into the store together with spongos state and associated info.
    ///
    /// Implementations should handle the case where link is already in the store,
    /// but spongos state is different. Such situation can indicate an attack,
    /// integrity violation (how exactly?), or internal error.
    ///
    /// Overwriting the spongos state means "forgetting the old and accepting the new".
    ///
    /// Not updating the spongos state means immutability -- "the first one makes the history".
    fn update(&mut self, link: &Link, spongos: Spongos<F>, info: Self::Info) -> Result<()>;

    /// Remove link and associated info from the store.
    fn erase(&mut self, _link: &Link) {}
}

/// Empty "dummy" link store that stores no links.
#[derive(Copy, Clone, Debug)]
pub struct EmptyLinkStore<F, Link, Info>(core::marker::PhantomData<(F, Link, Info)>);

impl<F, Link, Info> Default for EmptyLinkStore<F, Link, Info> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<F, Link, Info> LinkStore<F, Link> for EmptyLinkStore<F, Link, Info> {
    type Info = Info;
    fn update(&mut self, _link: &Link, _spongos: Spongos<F>, _info: Self::Info) -> Result<()> {
        Ok(())
    }
}

/// Link store that contains a single link.
/// This link store can be used in Streams Applications supporting a list-like "thread"
/// of messages without access to the history as the link to the last message is stored.
#[derive(Clone, Debug, Default)]
pub struct SingleLinkStore<F, Link, Info> {
    /// The link to the last message in the thread.
    link: Link,

    /// Inner spongos state is stored to save up space.
    spongos: Vec<u8>,

    /// Associated info.
    info: Info,

    _phantom: core::marker::PhantomData<F>,
}

impl<F, Link, Info> LinkStore<F, Link> for SingleLinkStore<F, Link, Info>
where
    F: PRP + Clone,
    Link: Clone + Eq,
    Info: Clone,
{
    type Info = Info;
    fn lookup(&self, link: &Link) -> Result<(Spongos<F>, Self::Info)> {
        if self.link == *link {
            Ok((Spongos::<F>::from_inner(self.spongos.clone()), self.info.clone()))
        } else {
            bail!("Link not found.");
        }
    }
    fn update(&mut self, link: &Link, spongos: Spongos<F>, info: Self::Info) -> Result<()> {
        let inner = spongos.to_inner();
        self.link = link.clone();
        self.spongos = inner;
        self.info = info;
        Ok(())
    }
    fn erase(&mut self, _link: &Link) {
        // Can't really erase link.
    }
}

pub struct DefaultLinkStore<F, Link, Info> {
    map: HashMap<Link, (Vec<u8>, Info)>,
    _phantom: core::marker::PhantomData<F>,
}

impl<F, Link, Info> Default for DefaultLinkStore<F, Link, Info>
where
    F: PRP,
    Link: Eq + hash::Hash,
{
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F, Link, Info> LinkStore<F, Link> for DefaultLinkStore<F, Link, Info>
where
    F: PRP + Clone,
    Link: Eq + hash::Hash + Clone,
    Info: Clone,
{
    type Info = Info;

    /// Add info for the link.
    fn lookup(&self, link: &Link) -> Result<(Spongos<F>, Info)> {
        if let Some((inner, info)) = self.map.get(link).cloned() {
            Ok((Spongos::from_inner(inner), info))
        } else {
            bail!("Link not found")
        }
    }

    /// Try to retrieve info for the link.
    fn update(&mut self, link: &Link, spongos: Spongos<F>, info: Info) -> Result<()> {
        let inner = spongos.to_inner();
        self.map.insert(link.clone(), (inner, info));
        Ok(())
    }

    /// Remove info for the link.
    fn erase(&mut self, link: &Link) {
        self.map.remove(link);
    }
}

use crate::command::{
    sizeof,
    unwrap,
    wrap,
};

pub struct Fallback<T>(pub T);

impl<T> From<T> for Fallback<T> {
    fn from(t: T) -> Self {
        Self(t)
    }
}

impl<'a, T> From<&'a T> for &'a Fallback<T> {
    fn from(t: &T) -> Self {
        unsafe { core::mem::transmute(t) }
    }
}

impl<'a, T> From<&'a mut T> for &'a mut Fallback<T> {
    fn from(t: &mut T) -> Self {
        unsafe { core::mem::transmute(t) }
    }
}

// impl<T> Into<T> for Fallback<T> {
// fn into(t: Self) -> T {
// t.0
// }
// }

impl<T> AsRef<T> for Fallback<T> {
    fn as_ref(&self) -> &T {
        &(self.0)
    }
}

impl<T> AsMut<T> for Fallback<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut (self.0)
    }
}

/// Trait allows for custom (non-standard DDML) types to be Absorb.
pub trait AbsorbFallback<F> {
    fn sizeof_absorb(&self, ctx: &mut sizeof::Context<F>) -> Result<()>;
    fn wrap_absorb<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()>;
    fn unwrap_absorb<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()>;
}

/// Trait allows for custom (non-standard DDML) types to be AbsorbExternal.
/// It is usually implemented for "absolute" link types that are not specified
/// in DDML and domain specific.
///
/// Note, that "absolute" links are absorbed in the message header.
pub trait AbsorbExternalFallback<F> {
    fn sizeof_absorb_external(&self, ctx: &mut sizeof::Context<F>) -> Result<()>;
    fn wrap_absorb_external<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()>;
    fn unwrap_absorb_external<IS: io::IStream>(&self, ctx: &mut unwrap::Context<F, IS>) -> Result<()>;
}

/// Trait allows for custom (non-standard DDML) types to be Absorb.
/// It is usually implemented for "relative" link types that are not specified
/// in DDML and domain specific.
///
/// Note, that "relative" links are usually skipped and joined in the message content.
pub trait SkipFallback<F> {
    fn sizeof_skip(&self, ctx: &mut sizeof::Context<F>) -> Result<()>;
    fn wrap_skip<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()>;
    fn unwrap_skip<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()>;
}
