use core::{
    fmt,
    ops::Mul,
};

use super::prp::{
    Inner,
    PRP,
};
use crate::{
    prelude::{
        digest::Digest,
        generic_array::{
            typenum::{
                Unsigned as _,
                U2,
            },
            ArrayLength,
            GenericArray,
        },
        Vec,
    },
    try_or,
    Errors::{
        LengthMismatch,
        SpongosNotCommitted,
    },
    Result,
};

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

fn encrypt_xor_mut(s: &mut [u8], x: &mut [u8]) {
    for (si, xi) in s.iter_mut().zip(x.iter_mut()) {
        *xi ^= *si;
        *si = *xi;
    }
}

fn decrypt_xor_mut(s: &mut [u8], y: &mut [u8]) {
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
pub type KeySize<F> = <F as PRP>::CapacitySize;
pub type KeyType<F> = GenericArray<u8, KeySize<F>>;

/// Sponge fixed nonce size in buf.
pub type NonceSize<F> = <F as PRP>::CapacitySize;
pub type NonceType<F> = GenericArray<u8, NonceSize<F>>;

/// Sponge fixed hash size in buf.
pub type HashSize<F> = <F as PRP>::CapacitySize;

/// Sponge fixed MAC size in buf.
pub type MacSize<F> = <F as PRP>::CapacitySize;

#[derive(Clone)]
pub struct Spongos<F> {
    /// Spongos transform together with its internal state.
    s: F,

    /// Current position (offset in bytes) within the outer state.
    pos: usize,
}

impl<F: PRP> Spongos<F> {
    /// Create a Spongos object, initialize state with zero trits.
    pub fn init() -> Self {
        Self::init_with_state(F::default())
    }

    /// Create a Spongos object with an explicit state.
    pub fn init_with_state(s: F) -> Self {
        Self { s, pos: 0 }
    }

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
    pub fn absorb(&mut self, xr: impl AsRef<[u8]>) {
        let mut x = xr.as_ref();
        while !x.is_empty() {
            let s = self.outer_min_mut(x.len());
            let n = s.len();
            xor(s, &x[..n]);
            x = &x[n..];
            self.update(n);
        }
    }

    /// Squeeze a trit slice from Spongos object.
    pub fn squeeze(&mut self, mut yr: impl AsMut<[u8]>) {
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
    pub fn squeeze_eq(&mut self, yr: impl AsRef<[u8]>) -> bool {
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

    /// Squeeze array, length inferred from output type.
    pub fn squeeze_arr<N: ArrayLength<u8>>(&mut self) -> GenericArray<u8, N> {
        let mut y = GenericArray::default();
        self.squeeze(&mut y);
        y
    }

    /// Squeeze vector, length is known at runtime.
    pub fn squeeze_n(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0; n];
        self.squeeze(&mut v);
        v
    }

    /// Encrypt a byte slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub fn encrypt(&mut self, xr: impl AsRef<[u8]>, mut yr: impl AsMut<[u8]>) -> Result<()> {
        let mut x = xr.as_ref();
        let mut y = yr.as_mut();
        try_or!(x.len() == y.len(), LengthMismatch(x.len(), y.len()))?;
        while !x.is_empty() {
            let s = self.outer_min_mut(x.len());
            let n = s.len();
            encrypt_xor(s, &x[..n], &mut y[..n]);
            x = &x[n..];
            y = &mut y[n..];
            self.update(n);
        }
        Ok(())
    }

    /// Encrypt in-place a trit slice with Spongos object.
    pub fn encrypt_mut(&mut self, mut xyr: impl AsMut<[u8]>) {
        let mut xy = xyr.as_mut();
        while !xy.is_empty() {
            let s = self.outer_min_mut(xy.len());
            let n = s.len();
            encrypt_xor_mut(s, &mut xy[..n]);
            xy = &mut xy[n..];
            self.update(n);
        }
    }

    /// Encrypt buf.
    pub fn encrypt_arr<N: ArrayLength<u8>>(&mut self, x: &GenericArray<u8, N>) -> Result<GenericArray<u8, N>> {
        let mut y = GenericArray::default();
        self.encrypt(x, &mut y)?;
        Ok(y)
    }

    pub fn encrypt_n(&mut self, x: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut y = vec![0; x.as_ref().len()];
        self.encrypt(x, &mut y)?;
        Ok(y)
    }

    /// Decrypt a byte slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub fn decrypt(&mut self, yr: impl AsRef<[u8]>, mut xr: impl AsMut<[u8]>) -> Result<()> {
        let mut y = yr.as_ref();
        let mut x = xr.as_mut();
        try_or!(x.len() == y.len(), LengthMismatch(x.len(), y.len()))?;
        while !x.is_empty() {
            let s = self.outer_min_mut(y.len());
            let n = s.len();
            decrypt_xor(s, &y[..n], &mut x[..n]);
            y = &y[n..];
            x = &mut x[n..];
            self.update(n);
        }
        Ok(())
    }

    /// Decrypt in-place a byte slice with Spongos object.
    pub fn decrypt_mut(&mut self, mut xyr: impl AsMut<[u8]>) {
        let mut xy = xyr.as_mut();
        while !xy.is_empty() {
            let s = self.outer_min_mut(xy.len());
            let n = s.len();
            decrypt_xor_mut(s, &mut xy[..n]);
            xy = &mut xy[n..];
            self.update(n);
        }
    }

    /// Decrypt buf.
    pub fn decrypt_arr<N: ArrayLength<u8>>(&mut self, y: impl AsRef<[u8]>) -> Result<GenericArray<u8, N>> {
        let mut x = GenericArray::default();
        self.decrypt(y, &mut x)?;
        Ok(x)
    }

    pub fn decrypt_n(&mut self, y: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut x = vec![0; y.as_ref().len()];
        self.decrypt(y, &mut x)?;
        Ok(x)
    }

    /// Force transform even if for incomplete (but non-empty!) outer state.
    /// Commit with empty outer state has no effect.
    pub fn commit(&mut self) {
        if self.pos != 0 {
            for o in &mut self.s.outer_mut()[self.pos..] {
                *o = 0
            }
            self.s.transform();
            self.pos = 0;
        }
    }

    /// Check whether spongos state is committed.
    pub fn is_committed(&self) -> bool {
        0 == self.pos
    }

    /// Join two Spongos objects.
    /// Joiner -- self -- object absorbs data squeezed from joinee.
    pub fn join(&mut self, joinee: &mut Self) {
        joinee.commit();
        // Clear outer state, this is equivalent to having joinee initialized from inner state
        // as join must work in the same way for full and trimmed spongos.
        for o in joinee.s.outer_mut() {
            *o = 0;
        }
        joinee.s.transform();
        let mut x = GenericArray::<u8, F::CapacitySize>::default();
        joinee.squeeze(x.as_mut());
        self.absorb(x.as_ref());
    }

    /// Fork Spongos object into another.
    /// Essentially this just creates a clone of self.
    pub fn fork_at(&self, fork: &mut Self) {
        fork.clone_from(self);
    }

    /// Fork Spongos object into a new one.
    /// Essentially this just creates a clone of self.
    pub fn fork(&self) -> Self {
        self.clone()
    }

    /// Only `inner` part of the state may be serialized.
    /// State should be committed.
    pub fn to_inner(&self) -> Result<Inner<F>> {
        try_or!(self.is_committed(), SpongosNotCommitted)?;
        Ok(self.s.inner().clone().into())
    }
}

impl<F: PRP> Default for Spongos<F> {
    fn default() -> Self {
        Self::init()
    }
}

impl<F: PRP> From<Inner<F>> for Spongos<F> {
    fn from(inner: Inner<F>) -> Self {
        Self {
            s: F::from_inner(&inner.into()),
            pos: 0,
        }
    }
}

impl<F: PRP> From<&Inner<F>> for Spongos<F> {
    fn from(inner: &Inner<F>) -> Self {
        Self {
            s: F::from_inner(inner.into()),
            pos: 0,
        }
    }
}

impl<F: PRP> From<Spongos<F>> for Inner<F> {
    fn from(inner: Spongos<F>) -> Self {
        inner.to_inner().unwrap()
    }
}

impl<F: PRP> From<&Spongos<F>> for Inner<F> {
    fn from(inner: &Spongos<F>) -> Self {
        inner.to_inner().unwrap()
    }
}

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

/// Shortcut for `Spongos::init`.
pub fn init<F>() -> Spongos<F>
where
    F: PRP,
{
    Spongos::init()
}

/// Hash (one piece of) data with Spongos.
pub fn hash_data<F>(x: &[u8], y: &mut [u8])
where
    F: PRP,
{
    let mut s = Spongos::<F>::init();
    s.absorb(x);
    s.commit();
    s.squeeze(y);
}

impl<F: PRP> Digest for Spongos<F>
where
    F::CapacitySize: Mul<U2>,
    <F::CapacitySize as Mul<U2>>::Output: ArrayLength<u8>,
{
    // This would normally result in U64, ie 512 bits needed for ed25519prehashed.
    type OutputSize = <F::CapacitySize as Mul<U2>>::Output;

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
        let mut data = GenericArray::default();
        self.squeeze(data.as_mut_slice());
        data
    }

    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        self.commit();
        let mut data = GenericArray::default();
        self.squeeze(data.as_mut_slice());
        data
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn output_size() -> usize {
        64
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut result = GenericArray::default();
        hash_data::<F>(data, result.as_mut_slice());
        result
    }
}
