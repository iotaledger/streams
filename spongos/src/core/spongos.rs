use alloc::vec::Vec;
use core::{
    fmt,
    ops::Mul,
};

use anyhow::{
    ensure,
    Result,
};
use digest::Digest;
use generic_array::{
    typenum::{
        Prod,
        Unsigned,
        U2,
    },
    ArrayLength,
    GenericArray,
};

use super::prp::PRP;
use crate::Error::{
    LengthMismatch,
    SpongosNotCommitted,
};

// use crate::{
//     prelude::{
//         digest::Digest,
//         generic_array::{
//             typenum::{
//                 Unsigned as _,
//                 U2,
//             },
//             ArrayLength,
//             GenericArray,
//         },
//         Vec,
//     },
//     try_or,
//     Errors::{
//         LengthMismatch,
//         SpongosNotCommitted,
//     },
//     Result,
// };

fn xor(s: &mut [u8], x: &[u8]) {
    for (si, xi) in s.iter_mut().zip(x.iter()) {
        *si ^= *xi;
    }
}

fn encrypt_xor(s: &mut [u8], x: &[u8], y: &mut [u8]) {
    for (si, (xi, yi)) in s.iter_mut().zip(x.iter().zip(y.iter_mut())) {
        *yi = *si ^ *xi;
        *si = *yi;
    }
}

fn decrypt_xor(s: &mut [u8], y: &[u8], x: &mut [u8]) {
    for (si, (yi, xi)) in s.iter_mut().zip(y.iter().zip(x.iter_mut())) {
        *xi = *si ^ *yi;
        *si = *yi;
    }
}

fn encrypt_xor_inplace(s: &mut [u8], x: &mut [u8]) {
    for (si, xi) in s.iter_mut().zip(x.iter_mut()) {
        *xi ^= *si;
        *si = *xi;
    }
}

fn decrypt_xor_inplace(s: &mut [u8], y: &mut [u8]) {
    for (si, yi) in s.iter_mut().zip(y.iter_mut()) {
        let t = *yi;
        *yi ^= *si;
        *si = t;
    }
}

fn copy(s: &[u8], y: &mut [u8]) {
    for (si, yi) in s.iter().zip(y.iter_mut()) {
        *yi = *si;
    }
}

fn equals(s: &[u8], x: &[u8]) -> bool {
    let mut eq = true;
    for (si, xi) in s.iter().zip(x.iter()) {
        eq = (*si == *xi) && eq;
    }
    eq
}

/// Sponge fixed key size in buf.
type KeySize<F> = <F as PRP>::CapacitySize;
pub(crate) type KeyType<F> = GenericArray<u8, KeySize<F>>;

/// Sponge fixed nonce size in buf.
type NonceSize<F> = <F as PRP>::CapacitySize;
pub(crate) type NonceType<F> = GenericArray<u8, NonceSize<F>>;

/// Sponge fixed hash size in buf.
type HashSize<F> = <F as PRP>::CapacitySize;

/// Sponge fixed MAC size in buf.
type MacSize<F> = <F as PRP>::CapacitySize;

type Capacity<F> = GenericArray<u8, <F as PRP>::CapacitySize>;
type Rate<F> = GenericArray<u8, <F as PRP>::RateSize>;

#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Spongos<F> {
    /// Spongos transform together with its internal state.
    s: F,

    /// Current position (offset in bytes) within the outer state.
    pos: usize,
}

impl<F> Spongos<F>
where
    F: Default,
{
    /// Create a Spongos object, initialize state with zero trits.
    pub fn init() -> Self {
        Self::init_with_state(F::default())
    }
}

impl<F> Spongos<F> {
    /// Create a Spongos object with an explicit state.
    fn init_with_state(s: F) -> Self {
        Self { s, pos: 0 }
    }
}

impl<F: PRP> Spongos<F> {
    fn outer_min_mut(&mut self, n: usize) -> &mut [u8] {
        let m = core::cmp::min(self.pos + n, F::RateSize::USIZE);
        &mut self.s.outer_mut()[self.pos..m]
    }

    /// Update Spongos after processing the current piece of data of `n` trits.
    fn update(&mut self, n: usize) {
        self.pos += n;
        if F::RateSize::USIZE == self.pos {
            self.commit();
        }
    }

    /// Absorb a slice into Spongos object.
    pub fn absorb<T>(&mut self, xr: T)
    where
        T: AsRef<[u8]>,
    {
        let mut x = xr.as_ref();
        while !x.is_empty() {
            let s = self.outer_min_mut(x.len());
            let n = s.len();
            xor(s, &x[..n]);
            x = &x[n..];
            self.update(n);
        }
    }

    /// Squeeze a byte slice from Spongos object.
    pub(crate) fn squeeze_mut<T>(&mut self, mut yr: T)
    where
        T: AsMut<[u8]>,
    {
        let mut y = yr.as_mut();
        while !y.is_empty() {
            let s = self.outer_min_mut(y.len());
            let n = s.len();
            copy(s, &mut y[..n]);
            y = &mut y[n..];
            self.update(n);
        }
    }

    /// Squeeze a trit slice from Spongos object and compare.
    pub(crate) fn squeeze_eq<T>(&mut self, yr: T) -> bool
    where
        T: AsRef<[u8]>,
    {
        let mut y = yr.as_ref();
        let mut eq = true;
        while !y.is_empty() {
            let s = self.outer_min_mut(y.len());
            let n = s.len();
            eq = equals(s, &y[..n]) && eq;
            y = &y[n..];
            self.update(n);
        }
        eq
    }

    pub(crate) fn squeeze<R>(&mut self) -> R
    where
        R: AsMut<[u8]> + Default,
    {
        let mut output = Default::default();
        self.squeeze_mut(&mut output);
        output
    }

    // TODO: REMOVE
    // /// Squeeze array, length inferred from output type.
    // fn squeeze_arr<N: ArrayLength<u8>>(&mut self) -> GenericArray<u8, N> {
    //     let mut y = GenericArray::default();
    //     self.squeeze(&mut y);
    //     y
    // }

    /// Squeeze vector, length is known at runtime.
    pub(crate) fn squeeze_n(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0; n];
        self.squeeze_mut(&mut v);
        v
    }

    pub fn sponge<T, R>(&mut self, data: T) -> R
    where
        T: AsRef<[u8]>,
        R: AsMut<[u8]> + Default,
    {
        let mut r = Default::default();
        self.sponge_mut(data, &mut r);
        r
    }

    pub(crate) fn sponge_mut<T, R>(&mut self, data: T, r: R)
    where
        T: AsRef<[u8]>,
        R: AsMut<[u8]>,
    {
        self.absorb(data);
        self.commit();
        self.squeeze_mut(r)
    }

    fn hash<T, R>(data: T) -> R
    where
        F: PRP,
        T: AsRef<[u8]>,
        R: AsMut<[u8]> + Default,
    {
        Self::init().sponge(data)
    }

    /// Encrypt a byte slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub(crate) fn encrypt_mut<P, C>(&mut self, plain: P, mut cipher: C) -> Result<()>
    where
        P: AsRef<[u8]>,
        C: AsMut<[u8]>,
    {
        let mut plain = plain.as_ref();
        let mut cipher = cipher.as_mut();
        ensure!(plain.len() == cipher.len(), LengthMismatch(plain.len(), cipher.len()));
        while !plain.is_empty() {
            let s = self.outer_min_mut(plain.len());
            let n = s.len();
            encrypt_xor(s, &plain[..n], &mut cipher[..n]);
            plain = &plain[n..];
            cipher = &mut cipher[n..];
            self.update(n);
        }
        Ok(())
    }

    /// Encrypt in-place a byte slice with Spongos object.
    pub(crate) fn encrypt_inplace<T>(&mut self, mut xyr: T)
    where
        T: AsMut<[u8]>,
    {
        let mut xy = xyr.as_mut();
        while !xy.is_empty() {
            let s = self.outer_min_mut(xy.len());
            let n = s.len();
            encrypt_xor_inplace(s, &mut xy[..n]);
            xy = &mut xy[n..];
            self.update(n);
        }
    }

    // TODO: REMOVE
    // fn encrypt_arr<N: ArrayLength<u8>>(&mut self, x: &GenericArray<u8, N>) -> Result<GenericArray<u8, N>> {
    //     let mut y = GenericArray::default();
    //     self.encrypt(x, &mut y)?;
    //     Ok(y)
    // }
    fn encrypt<T, R>(&mut self, plain: T) -> Result<R>
    where
        T: AsRef<[u8]>,
        R: AsMut<[u8]> + Default,
    {
        let mut cipher = Default::default();
        self.encrypt_mut(plain, &mut cipher)?;
        Ok(cipher)
    }

    pub(crate) fn encrypt_n<T>(&mut self, x: T) -> Result<Vec<u8>>
    where
        T: AsRef<[u8]>,
    {
        let mut y = vec![0; x.as_ref().len()];
        self.encrypt_mut(x, &mut y)?;
        Ok(y)
    }

    /// Decrypt a byte slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub(crate) fn decrypt_mut<C, P>(&mut self, cipher: C, mut plain: P) -> Result<()>
    where
        C: AsRef<[u8]>,
        P: AsMut<[u8]>,
    {
        let mut cipher = cipher.as_ref();
        let mut plain = plain.as_mut();
        ensure!(plain.len() == cipher.len(), LengthMismatch(plain.len(), cipher.len()));
        while !plain.is_empty() {
            let spongos = self.outer_min_mut(cipher.len());
            let n = spongos.len();
            decrypt_xor(spongos, &cipher[..n], &mut plain[..n]);
            cipher = &cipher[n..];
            plain = &mut plain[n..];
            self.update(n);
        }
        Ok(())
    }

    /// Decrypt in-place a byte slice with Spongos object.
    pub(crate) fn decrypt_inplace<T>(&mut self, mut xyr: T)
    where
        T: AsMut<[u8]>,
    {
        let mut xy = xyr.as_mut();
        while !xy.is_empty() {
            let s = self.outer_min_mut(xy.len());
            let n = s.len();
            decrypt_xor_inplace(s, &mut xy[..n]);
            xy = &mut xy[n..];
            self.update(n);
        }
    }

    fn decrypt<T, R>(&mut self, mut ciphertext: T) -> Result<R>
    where
        T: AsRef<[u8]>,
        R: AsMut<[u8]> + Default,
    {
        let mut plaintext = Default::default();
        self.decrypt_mut(ciphertext, &mut plaintext)?;
        Ok(plaintext)
    }

    // TODO: REMOVE
    // /// Decrypt buf.
    // fn decrypt_arr<N: ArrayLength<u8>>(&mut self, y: impl AsRef<[u8]>) -> Result<GenericArray<u8, N>> {
    //     let mut x = GenericArray::default();
    //     self.decrypt(y, &mut x)?;
    //     Ok(x)
    // }

    pub(crate) fn decrypt_n<T>(&mut self, y: T) -> Result<Vec<u8>>
    where
        T: AsRef<[u8]>,
    {
        let mut x = vec![0; y.as_ref().len()];
        self.decrypt_mut(y, &mut x)?;
        Ok(x)
    }

    /// Force transform even if for incomplete (but non-empty!) outer state.
    /// Commit with empty outer state has no effect.
    pub(crate) fn commit(&mut self) {
        if self.pos != 0 {
            for o in &mut self.s.outer_mut()[self.pos..] {
                *o = 0
            }
            self.s.transform();
            self.pos = 0;
        }
    }

    /// Check whether spongos state is committed.
    fn is_committed(&self) -> bool {
        0 == self.pos
    }

    /// Join two Spongos objects.
    ///
    /// Joiner (self) absorbs data squeezed from joinee.
    /// Be aware that before squeezing the joinee, this is commited, its outer state is zeroed, and a transformation is
    /// performed. This means the joinee will be mutated. if this is not desirable, make sure to clone the joinee beforehand.
    pub(crate) fn join(&mut self, joinee: &mut Self) {
        joinee.commit();
        // Clear outer state, this is equivalent to having joinee initialized from inner state
        // as join must work in the same way for full and trimmed spongos.
        for o in joinee.s.outer_mut() {
            *o = 0;
        }
        joinee.s.transform();
        let x: Capacity<F> = joinee.squeeze();
        self.absorb(x.as_ref());
    }

    /// Only `inner` part of the state may be serialized.
    /// State must be committed.
    fn to_inner(&self) -> Result<Inner<F>> {
        // TODO: RENAME OR SOMETHING (OPTION: MAKE COMMITING A COMPILER CHECK)
        ensure!(self.is_committed(), SpongosNotCommitted);
        Ok(self.s.inner().clone().into())
    }
}

impl<F> Spongos<F>
where
    F: Clone,
{
    /// Fork Spongos object into another.
    /// Essentially this just creates a clone of self.
    fn fork_at(&self, fork: &mut Self) {
        fork.clone_from(self);
    }

    /// Fork Spongos object into a new one.
    /// Essentially this just creates a clone of self.
    pub(crate) fn fork(&self) -> Self {
        self.clone()
    }
}

// TODO: REVIEW
impl<F: PRP> From<Inner<F>> for Spongos<F> {
    fn from(inner: Inner<F>) -> Self {
        Self {
            s: F::from_inner(&inner.into()),
            pos: 0,
        }
    }
}

// TODO: REMOVE
// impl<F: PRP> From<&Inner<F>> for Spongos<F> {
//     fn from(inner: &Inner<F>) -> Self {
//         Self {
//             s: F::from_inner(inner.into()),
//             pos: 0,
//         }
//     }
// }
// impl<F: PRP> From<Spongos<F>> for Inner<F> {
//     fn from(spongos: Spongos<F>) -> Self {
//         spongos.into_inner().unwrap()
//     }
// }

// TODO: REMOVE
// impl<F: PRP> From<&Spongos<F>> for Inner<F> {
//     fn from(inner: &Spongos<F>) -> Self {
//         inner.to_inner().unwrap()
//     }
// }

impl<F: PRP> fmt::Debug for Spongos<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // write!(f, "{}[{:?}]", self.pos, hex::encode(self.s.outer().as_ref()))
        // write!(f, "[{}:{}]",
        //       hex::encode(&self.s.outer().as_ref()[..self.pos]),
        //       hex::encode(&self.s.outer().as_ref()[self.pos..]))
        write!(
            f,
            "[{}:{}|{}]",
            hex::encode(&self.s.outer().as_ref()[..self.pos]),
            hex::encode(&self.s.outer().as_ref()[self.pos..]),
            hex::encode(self.s.inner().as_ref())
        )
    }
}

// TODO: REMOVE
// /// Shortcut for `Spongos::init`.
// fn init<F>() -> Spongos<F>
// where
//     F: PRP + Default,
// {
//     Spongos::init()
// }

/// Hash data with Spongos.
fn hash<F, T, R>(data: T) -> R
where
    F: PRP,
    T: AsRef<[u8]>,
    R: AsMut<[u8]> + Default,
{
    Spongos::<F>::hash(data)
}

impl<F> Digest for Spongos<F>
where
    F: PRP,
    // TODO: REMOVE
    F::CapacitySize: Mul<U2>,
    <F::CapacitySize as Mul<U2>>::Output: ArrayLength<u8>,
{
    // This would normally result in U64, ie 512 bits needed for ed25519prehashed.
    // type OutputSize = <F::CapacitySize as Mul<U2>>::Output;
    type OutputSize = Prod<F::CapacitySize, U2>;

    fn new() -> Self {
        Spongos::init()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.absorb(data.as_ref());
    }

    fn chain(mut self, data: impl AsRef<[u8]>) -> Self {
        self.absorb(data.as_ref());
        self
    }

    fn finalize(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.commit();
        self.squeeze()
    }

    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        self.commit();
        self.squeeze()
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn output_size() -> usize {
        64
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        Self::init().sponge(data)
    }
}

/// Convenience wrapper for storing Spongos inner state.
#[derive(Clone, PartialEq, Eq, Default, Hash)]
struct Inner<F: PRP> {
    /// Represents inner state of spongos automaton.
    inner: Capacity<F>,
}

impl<F: PRP> Inner<F> {
    fn arr(&self) -> &Capacity<F> {
        &self.inner
    }

    fn arr_mut(&mut self) -> &mut Capacity<F> {
        &mut self.inner
    }
}

impl<F: PRP> AsRef<[u8]> for Inner<F> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<F: PRP> AsMut<[u8]> for Inner<F> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
    }
}

impl<F: PRP> From<Capacity<F>> for Inner<F> {
    fn from(bytes: Capacity<F>) -> Self {
        Self { inner: bytes }
    }
}

impl<F: PRP> From<Inner<F>> for Capacity<F> {
    fn from(inner: Inner<F>) -> Self {
        inner.inner
    }
}

// TODO: REMOVE
// impl<'a, F: PRP> From<&'a Inner<F>> for &'a GenericArray<u8, F::CapacitySize> {
//     fn from(inner: &'a Inner<F>) -> Self {
//         &(*inner).inner
//     }
// }
