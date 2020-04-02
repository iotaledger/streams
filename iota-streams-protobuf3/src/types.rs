use failure::{bail, Fallible};
use std::convert::{AsMut, AsRef};
use std::fmt;
use std::hash;
use std::string::ToString;

use iota_streams_core::{
    sponge::{prp::PRP, spongos::Spongos},
    tbits::{
        word::{BasicTbitWord, SpongosTbitWord, StringTbitWord},
        Tbits,
    },
};

use crate::io;

/// PB3 integer type `tryte` is signed and is represented with `Trint3`, not `Tryte` which is unsigned.
/// PB3 integer type `trint` is 6-trit wide and is represented with `Trint6`.
pub use iota_streams_core::tbits::trinary::{Trint18, Trint3, Trint6, Trint9};

/// Fixed-size array of trytes, the size is known at compile time and is not encoded in trinary representation.
/// The inner buffer size (in trits) must be multiple of 3.
//TODO: PartialEq, Eq, Debug
#[derive(Clone)]
pub struct NTrytes<TW>(pub Tbits<TW>);

impl<TW> fmt::Debug for NTrytes<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<TW> PartialEq for NTrytes<TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<TW> Eq for NTrytes<TW> where TW: BasicTbitWord {}

impl<TW> NTrytes<TW>
where
    TW: BasicTbitWord,
{
    pub fn zero(n: usize) -> Self {
        Self(Tbits::<TW>::zero(n))
    }
}

impl<TW> ToString for NTrytes<TW>
where
    TW: StringTbitWord,
{
    fn to_string(&self) -> String {
        (self.0).to_string()
    }
}

/*
impl fmt::Display for NTrytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{}]", (self.0).size(), (self.0).slice())
    }
}
*/

impl<TW> hash::Hash for NTrytes<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}

/// Variable-size array of trytes, the size is not known at compile time and is encoded in trinary representation.
/// The inner buffer size (in trits) must be multiple of 3.
//TODO: PartialEq, Eq, Clone, Debug
#[derive(Clone)]
pub struct Trytes<TW>(pub Tbits<TW>);

impl<TW> Default for Trytes<TW>
where
    TW: BasicTbitWord,
{
    fn default() -> Self {
        Self(Tbits::<TW>::zero(0))
    }
}

impl<TW> PartialEq for Trytes<TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<TW> Eq for Trytes<TW> where TW: BasicTbitWord {}

impl<TW> ToString for Trytes<TW>
where
    TW: StringTbitWord,
{
    fn to_string(&self) -> String {
        (self.0).to_string()
    }
}

/*
impl fmt::Display for Trytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{}]", (self.0).size(), (self.0).slice())
    }
}
*/

impl<TW> hash::Hash for Trytes<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
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

/*
impl Default for Mac {
    fn default() -> Self {
        Self(spongos::MAC_SIZE)
    }
}
 */

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
pub trait LinkStore<TW, F, Link> {
    /// Additional data associated with the current message link/spongos state.
    /// This type is implementation specific, meaning different configurations
    /// of a Streams Application can use different Info types.
    type Info;

    /// Lookup link in the store and return spongos state and associated info.
    fn lookup(&self, _link: &Link) -> Fallible<(Spongos<TW, F>, Self::Info)> {
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
    fn update(&mut self, link: &Link, spongos: Spongos<TW, F>, info: Self::Info) -> Fallible<()>;

    /// Remove link and associated info from the store.
    fn erase(&mut self, _link: &Link) {}
}

/// Empty "dummy" link store that stores no links.
#[derive(Copy, Clone, Debug)]
pub struct EmptyLinkStore<TW, F, Link, Info>(std::marker::PhantomData<(TW, F, Link, Info)>);

impl<TW, F, Link, Info> Default for EmptyLinkStore<TW, F, Link, Info> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<TW, F, Link, Info> LinkStore<TW, F, Link> for EmptyLinkStore<TW, F, Link, Info> {
    type Info = Info;
    fn update(
        &mut self,
        _link: &Link,
        _spongos: Spongos<TW, F>,
        _info: Self::Info,
    ) -> Fallible<()> {
        Ok(())
    }
}

/// Link store that contains a single link.
/// This link store can be used in Streams Applications supporting a list-like "thread"
/// of messages without access to the history as the link to the last message is stored.
#[derive(Clone, Debug, Default)]
pub struct SingleLinkStore<TW, F, Link, Info>
where
    F: PRP<TW>,
{
    /// The link to the last message in the thread.
    link: Link,

    /// Inner spongos state is stored to save up space.
    spongos: F::Inner,

    /// Associated info.
    info: Info,
}

impl<TW, F, Link, Info> LinkStore<TW, F, Link> for SingleLinkStore<TW, F, Link, Info>
where
    TW: BasicTbitWord + SpongosTbitWord,
    F: PRP<TW> + Clone,
    F::Inner: Clone,
    Link: Clone + Eq,
    Info: Clone,
{
    type Info = Info;
    fn lookup(&self, link: &Link) -> Fallible<(Spongos<TW, F>, Self::Info)> {
        if self.link == *link {
            Ok((
                Spongos::<TW, F>::from_inner(self.spongos.clone()),
                self.info.clone(),
            ))
        } else {
            bail!("Link not found.");
        }
    }
    fn update(&mut self, link: &Link, spongos: Spongos<TW, F>, info: Self::Info) -> Fallible<()> {
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

use std::collections::HashMap;

pub struct DefaultLinkStore<TW, F, Link, Info>
where
    F: PRP<TW>,
{
    map: HashMap<Link, (F::Inner, Info)>,
}

impl<TW, F, Link, Info> Default for DefaultLinkStore<TW, F, Link, Info>
where
    F: PRP<TW>,
    Link: Eq + hash::Hash,
{
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<TW, F, Link, Info> LinkStore<TW, F, Link> for DefaultLinkStore<TW, F, Link, Info>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Clone,
    F::Inner: Clone,
    Link: Eq + hash::Hash + Clone,
    Info: Clone,
{
    type Info = Info;

    /// Add info for the link.
    fn lookup(&self, link: &Link) -> Fallible<(Spongos<TW, F>, Info)> {
        if let Some((inner, info)) = self.map.get(link).cloned() {
            Ok((Spongos::from_inner(inner), info))
        } else {
            bail!("Link not found")
        }
    }

    /// Try to retrieve info for the link.
    fn update(&mut self, link: &Link, spongos: Spongos<TW, F>, info: Info) -> Fallible<()> {
        let inner = spongos.to_inner();
        self.map.insert(link.clone(), (inner, info));
        Ok(())
    }

    /// Remove info for the link.
    fn erase(&mut self, link: &Link) {
        self.map.remove(link);
    }
}

use crate::command::{sizeof, unwrap, wrap};

pub struct Fallback<T>(pub T);

impl<T> From<T> for Fallback<T> {
    fn from(t: T) -> Self {
        Self(t)
    }
}

impl<'a, T> From<&'a T> for &'a Fallback<T> {
    fn from(t: &T) -> Self {
        unsafe { std::mem::transmute(t) }
    }
}

impl<'a, T> From<&'a mut T> for &'a mut Fallback<T> {
    fn from(t: &mut T) -> Self {
        unsafe { std::mem::transmute(t) }
    }
}

/*
impl<T> Into<T> for Fallback<T> {
    fn into(t: Self) -> T {
        t.0
    }
}
 */

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

/// Trait allows for custom (non-standard Protobuf3) types to be Absorb.
pub trait AbsorbFallback<TW, F> {
    fn sizeof_absorb(&self, ctx: &mut sizeof::Context<TW, F>) -> Fallible<()>;
    fn wrap_absorb<OS: io::OStream<TW>>(&self, ctx: &mut wrap::Context<TW, F, OS>) -> Fallible<()>;
    fn unwrap_absorb<IS: io::IStream<TW>>(
        &mut self,
        ctx: &mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<()>;
}

/// Trait allows for custom (non-standard Protobuf3) types to be AbsorbExternal.
/// It is usually implemented for "absolute" link types that are not specified
/// in Protobuf3 and domain specific.
///
/// Note, that "absolute" links are absorbed in the message header.
pub trait AbsorbExternalFallback<TW, F> {
    fn sizeof_absorb_external(&self, ctx: &mut sizeof::Context<TW, F>) -> Fallible<()>;
    fn wrap_absorb_external<OS: io::OStream<TW>>(
        &self,
        ctx: &mut wrap::Context<TW, F, OS>,
    ) -> Fallible<()>;
    fn unwrap_absorb_external<IS: io::IStream<TW>>(
        &self,
        ctx: &mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<()>;
}

/// Trait allows for custom (non-standard Protobuf3) types to be Absorb.
/// It is usually implemented for "relative" link types that are not specified
/// in Protobuf3 and domain specific.
///
/// Note, that "relative" links are usually skipped and joined in the message content.
pub trait SkipFallback<TW, F> {
    fn sizeof_skip(&self, ctx: &mut sizeof::Context<TW, F>) -> Fallible<()>;
    fn wrap_skip<OS: io::OStream<TW>>(&self, ctx: &mut wrap::Context<TW, F, OS>) -> Fallible<()>;
    fn unwrap_skip<IS: io::IStream<TW>>(
        &mut self,
        ctx: &mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<()>;
}
