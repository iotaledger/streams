use anyhow::Result;
use core::{
    convert::{
        AsMut,
        AsRef,
    },
    fmt,
    hash,
};

use iota_streams_core::{
    prelude::{
        Vec,
        digest::Digest,
    },
};

// Reexport some often used types
pub use iota_streams_core::prelude::{
    generic_array::{GenericArray, ArrayLength,},
    typenum::{U16, U32, U64, marker_traits::Unsigned},
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
#[derive(Clone, PartialEq, Eq, Debug, Default, Hash)]
pub struct NBytes<N: ArrayLength<u8>>(GenericArray<u8, N>);

impl<N> Copy for NBytes<N> where
    N: ArrayLength<u8>,
    N::ArrayType: Copy
{}

impl<N: ArrayLength<u8>> NBytes<N> {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl<N: ArrayLength<u8>> AsRef<[u8]> for NBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<N: ArrayLength<u8>> AsMut<[u8]> for NBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<N: ArrayLength<u8>> From<GenericArray<u8, N>> for NBytes<N> {
    fn from(ga: GenericArray<u8, N>) -> Self {
        NBytes(ga)
    }
}

impl<'a, N: ArrayLength<u8>> From<&'a GenericArray<u8, N>> for &'a NBytes<N> {
    fn from(ga: &GenericArray<u8, N>) -> Self {
        unsafe { &*(ga.as_ptr() as *const NBytes<N>) }
    }
}

impl<'a, N: ArrayLength<u8>> From<&'a mut GenericArray<u8, N>> for &'a mut NBytes<N> {
    fn from(ga: &mut GenericArray<u8, N>) -> Self {
        unsafe { &mut *(ga.as_mut_ptr() as *mut NBytes<N>) }
    }
}

impl<N: ArrayLength<u8>> Into<GenericArray<u8, N>> for NBytes<N> {
    fn into(self) -> GenericArray<u8, N> {
        self.0
    }
}

impl<'a, N: ArrayLength<u8>> From<&'a [u8]> for &'a NBytes<N> {
    fn from(slice: &[u8]) -> &NBytes<N> {
        unsafe { &*(slice.as_ptr() as *const NBytes<N>) }
    }
}

impl<'a, N: ArrayLength<u8>> From<&'a mut [u8]> for &'a mut NBytes<N> {
    fn from(slice: &mut [u8]) -> &mut NBytes<N> {
        unsafe { &mut *(slice.as_mut_ptr() as *mut NBytes<N>) }
    }
}

/*
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
 */

/*
impl TryFrom<Vec<u8>> for NBytes {
    type Error = ();
    fn try_from(v: Vec<u8>) -> Result<Self, ()> {
        Self(v)
    }
}
 */

// impl ToString for NBytes
// {
// fn to_string(&self) -> String {
// (self.0).to_string()
// }
// }

/*
impl hash::Hash for NBytes {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}
 */

/// Variable-size array of bytes, the size is not known at compile time and is encoded in trinary representation.
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct Bytes(pub Vec<u8>);

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    fn update(&mut self, _data: impl AsRef<[u8]>) {}

    fn chain(self, _data: impl AsRef<[u8]>) -> Self {
        self
    }

    fn finalize(self) -> GenericArray<u8, Self::OutputSize> {
        self.0
    }

    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
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

// Can't impl Into<T> for Fallback<T> due to conflict with core::convert::Into impl for T

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
