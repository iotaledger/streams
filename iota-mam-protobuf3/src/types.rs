use std::convert::TryFrom;
use std::hash;
use std::string::ToString;
use failure::bail;

use iota_mam_core::trits::Trits;
use iota_mam_core::spongos::{self, Spongos};

use crate::Result;
use crate::io;

/// PB3 integer type `tryte` is signed and is represented with `Trint3`, not `Tryte` which is unsigned.
/// PB3 integer type `trint` is 6-trit wide and is represented with `Trint6`.
pub use iota_mam_core::trits::{Trint3, Trint6, Trint9, Trint18};

/// Fixed-size array of trytes, the size is known at compile time and is not encoded in trinary representation.
/// The inner buffer size (in trits) must be multiple of 3.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct NTrytes(pub Trits);

impl NTrytes {
    pub fn zero(n: usize) -> Self {
        Self(Trits::zero(n))
    }
}

impl ToString for NTrytes {
    fn to_string(&self) -> String {
        (self.0).to_string()
    }
}

impl hash::Hash for NTrytes {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}

/// Variable-size array of trytes, the size is not known at compile time and is encoded in trinary representation.
/// The inner buffer size (in trits) must be multiple of 3.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Trytes(pub Trits);

impl Default for Trytes {
    fn default() -> Self {
        Self(Trits::zero(0))
    }
}

impl ToString for Trytes {
    fn to_string(&self) -> String {
        (self.0).to_string()
    }
}

impl hash::Hash for Trytes {
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
pub struct MssHashSig;

impl Default for Mac {
    fn default() -> Self {
        Self(spongos::MAC_SIZE)
    }
}

/// PB3 `size_t` type, unsigned.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Size(pub usize);

/// Max value of `size_t` type: `(27^13 - 1) / 2`.
pub const SIZE_MAX: usize = 2_026_277_576_509_488_133;

/// Number of trytes needed to encode a value of `size_t` type.
pub fn size_trytes(n: usize) -> usize {
    // Larger values wouldn't fit into max of 13 trytes.
    assert!(n <= SIZE_MAX);

    // `(27^12 - 1) / 2`.
    const M12: usize = 75_047_317_648_499_560;
    if n > M12 {
        // Handle special case in order to avoid overflow in `m` below.
        return 13;
    }

    let mut d: usize = 0;
    let mut m: usize = 1;
    while n > (m - 1) / 2 {
        // Can't overflow.
        m *= 27;
        d += 1;
    }

    d
}

pub fn sizeof_sizet(n: usize) -> usize {
    3 * (size_trytes(n) + 1)
}

/// PB3 `external` modifier, it changes behaviour of commands in the following way.
/// The external field is not encoded in trinary representation and the value is stored in the environment implicitly.
#[derive(PartialEq, Eq, Copy, Clone, Debug, Default)]
pub struct External<T>(pub T);

/// The `link` type is generic and transport-specific. Links can be address+tag pair
/// when messages are published in the Tangle. Or links can be a URL when HTTP is used.
/// Or links can be a message sequence number in a stream/socket.
pub trait LinkStore<Link> {
    /// Additional data associated with the current message link/spongos state.
    /// This type is implementation specific, meaning different configurations
    /// of a MAM Application can use different Info types.
    type Info;

    /// Lookup link in the store and return spongos state and associated info.
    fn lookup(&self, link: &Link) -> Result<(Spongos, Self::Info)> {
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
    fn update(&mut self, link: &Link, spongos: Spongos, info: Self::Info) -> Result<()>;

    /// Remove link and associated info from the store.
    fn erase(&mut self, link: &Link) {
    }
}

/// Empty "dummy" link store that stores no links.
#[derive(Copy, Clone, Debug, Default)]
pub struct EmptyLinkStore<Link, Info>(std::marker::PhantomData<(Link, Info)>);

impl<Link, Info> LinkStore<Link> for EmptyLinkStore<Link, Info> {
    type Info = Info;
    fn update(&mut self, _link: &Link, _spongos: Spongos, _info: Self::Info) -> Result<()> {
        Ok(())
    }
}

/// Link store that contains a single link.
/// This link store can be used in MAM Applications supporting a list-like "thread"
/// of messages without access to the history as the link to the last message is stored.
#[derive(Clone, Debug, Default)]
pub struct SingleLinkStore<Link, Info>{
    /// The link to the last message in the thread.
    link: Link,

    /// Inner spongos state is stored to save up space.
    spongos: spongos::Inner,

    /// Associated info.
    info: Info,
}

impl<Link, Info> LinkStore<Link> for SingleLinkStore<Link, Info> where
    Link: Clone + Eq, Info: Clone,
{
    type Info = Info;
    fn lookup(&self, link: &Link) -> Result<(Spongos, Self::Info)> {
        if self.link == *link {
            Ok(((&self.spongos).into(), self.info.clone()))
        } else {
            bail!("Link not found.");
        }
    }
    fn update(&mut self, link: &Link, spongos: Spongos, info: Self::Info) -> Result<()> {
        if let Ok(inner) = spongos::Inner::try_from(&spongos) {
            self.link = link.clone();
            self.spongos = inner;
            self.info = info;
            Ok(())
        } else {
            bail!("Internal error: spongos state must be committed before being put into SingleLinkStore.")
        }
    }
    fn erase(&mut self, link: &Link) {
        // Can't really erase link.
    }
}

use std::collections::HashMap;

pub struct DefaultLinkStore<Link, Info> {
    map: HashMap<Link, (spongos::Inner, Info)>,
}

impl<Link, Info> Default for DefaultLinkStore<Link, Info> where Link: Eq + hash::Hash {
    fn default() -> Self {
        Self { map: HashMap::new() }
    }
}

impl<Link, Info> LinkStore<Link> for DefaultLinkStore<Link, Info> where
    Link: Eq + hash::Hash + Clone, Info: Clone,
{
    type Info = Info;

    /// Add info for the link.
    fn lookup(&self, link: &Link) -> Result<(Spongos, Info)> {
        if let Some((inner, info)) = self.map.get(link).cloned() {
            Ok((inner.into(), info))
        } else {
            bail!("Link not found")
        }
    }

    /// Try to retrieve info for the link.
    fn update(&mut self, link: &Link, spongos: Spongos, info: Info) -> Result<()> {
        if let Ok(inner) = spongos::Inner::try_from(&spongos) {
            self.map.insert(link.clone(), (inner, info));
            Ok(())
        } else {
            bail!("Internal error: spongos state must be committed before being put into SingleLinkStore.")
        }
    }

    /// Remove info for the link.
    fn erase(&mut self, link: &Link) {
        self.map.remove(link);
    }
}

use crate::command::{sizeof, wrap, unwrap};

/// Trait allows for custom (non-standard Protobuf3) types to be Absorb.
pub trait AbsorbFallback {
    fn sizeof_absorb(&self, ctx: &mut sizeof::Context) -> Result<()>;
    fn wrap_absorb<OS: io::OStream>(&self, ctx: &mut wrap::Context<OS>) -> Result<()>;
    fn unwrap_absorb<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()>;
}

/// Trait allows for custom (non-standard Protobuf3) types to be AbsorbExternal.
/// It is usually implemented for "absolute" link types that are not specified
/// in Protobuf3 and domain specific.
///
/// Note, that "absolute" links are absorbed in the message header.
pub trait AbsorbExternalFallback {
    fn sizeof_absorb_external(&self, ctx: &mut sizeof::Context) -> Result<()>;
    fn wrap_absorb_external<OS: io::OStream>(&self, ctx: &mut wrap::Context<OS>) -> Result<()>;
    fn unwrap_absorb_external<IS: io::IStream>(&self, ctx: &mut unwrap::Context<IS>) -> Result<()>;
}

/// Trait allows for custom (non-standard Protobuf3) types to be Absorb.
/// It is usually implemented for "relative" link types that are not specified
/// in Protobuf3 and domain specific.
///
/// Note, that "relative" links are usually skipped and joined in the message content.
pub trait SkipFallback {
    fn sizeof_skip(&self, ctx: &mut sizeof::Context) -> Result<()>;
    fn wrap_skip<OS: io::OStream>(&self, ctx: &mut wrap::Context<OS>) -> Result<()>;
    fn unwrap_skip<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()>;
}
