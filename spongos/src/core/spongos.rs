use core::{fmt, ops::Mul};
use digest::Digest;
use generic_array::{
    typenum::{Prod, Unsigned, U2},
    ArrayLength, GenericArray,
};

use super::prp::PRP;
use crate::{
    error::{Error::LengthMismatch, Result},
    KeccakF1600,
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

type Capacity<F> = GenericArray<u8, <F as PRP>::CapacitySize>;
type Rate<F> = GenericArray<u8, <F as PRP>::RateSize>;

/// State management for binary streams.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Spongos<F = KeccakF1600> {
    /// Spongos transform together with its internal state.
    s: F,

    /// Current position (offset in bytes) within the outer state.
    pos: usize,
}

impl<F> Spongos<F>
where
    F: Default,
{
    /// Create a [`Spongos`] object, initialize state with zero bytes.
    pub fn init() -> Self {
        Self::init_with_state(F::default())
    }
}

impl<F> Spongos<F> {
    /// Create a [`Spongos`] object with an explicit state.
    fn init_with_state(s: F) -> Self {
        Self { s, pos: 0 }
    }
}

impl<F: PRP> Spongos<F> {
    /// Retrieves `n` bytes from outer, provided there are enough bytes to satisfy the request. If
    /// not the outer position - `Ratesize` number of bytes are retrieved instead.
    fn outer_min_mut(&mut self, n: usize) -> &mut [u8] {
        let m = core::cmp::min(self.pos + n, F::RateSize::USIZE);
        &mut self.s.outer_mut()[self.pos..m]
    }

    /// Update [`Spongos`] after processing the current piece of data of `n` bytes.
    fn update(&mut self, n: usize) {
        self.pos += n;
        if F::RateSize::USIZE == self.pos {
            self.commit();
        }
    }

    /// Absorb a slice into [`Spongos`] object.
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

    /// Squeeze a byte slice from [`Spongos`] object.
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

    /// Squeeze a byte slice from [`Spongos`] object and compare.
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

    /// Squeezes a generic byte slice from [`Spongos`] object.
    pub fn squeeze<R>(&mut self) -> R
    where
        R: AsMut<[u8]> + Default,
    {
        let mut output = Default::default();
        self.squeeze_mut(&mut output);
        output
    }

    /// Absorb bytes into [`Spongos`] and squeeze out a new byte slice.
    pub fn sponge<T, R>(&mut self, data: T) -> R
    where
        T: AsRef<[u8]>,
        R: AsMut<[u8]> + Default,
    {
        let mut r = Default::default();
        self.sponge_mut(data, &mut r);
        r
    }

    /// Absorb bytes into mutable [`Spongos`] and squeeze out a new byte slice.
    pub(crate) fn sponge_mut<T, R>(&mut self, data: T, r: R)
    where
        T: AsRef<[u8]>,
        R: AsMut<[u8]>,
    {
        self.absorb(data);
        self.commit();
        self.squeeze_mut(r)
    }

    /// Encrypt a byte slice with mutable [`Spongos`] object.
    /// Input and output slices must be non-overlapping.
    pub(crate) fn encrypt_mut<P, C>(&mut self, plain: P, mut cipher: C) -> Result<()>
    where
        P: AsRef<[u8]>,
        C: AsMut<[u8]>,
    {
        let mut plain = plain.as_ref();
        let mut cipher = cipher.as_mut();

        if plain.len() != cipher.len() {
            return Err(LengthMismatch(plain.len(), cipher.len()));
        }

        while !plain.is_empty() {
            let spongos = self.outer_min_mut(plain.len());
            let n = spongos.len();
            encrypt_xor(spongos, &plain[..n], &mut cipher[..n]);
            plain = &plain[n..];
            cipher = &mut cipher[n..];
            self.update(n);
        }
        Ok(())
    }

    /// Encrypt a byte slice with [`Spongos`] object.
    /// Input and output slices must be non-overlapping.
    pub fn encrypt<T>(&mut self, plain: &T) -> Result<T>
    where
        T: AsRef<[u8]> + AsMut<[u8]> + Default,
    {
        let mut cipher = Default::default();
        self.encrypt_mut(plain, &mut cipher)?;
        Ok(cipher)
    }

    /// Decrypt a byte slice with mutable [`Spongos`] object.
    /// Input and output slices must be non-overlapping.
    pub(crate) fn decrypt_mut<C, P>(&mut self, cipher: C, mut plain: P) -> Result<()>
    where
        C: AsRef<[u8]>,
        P: AsMut<[u8]>,
    {
        let mut cipher = cipher.as_ref();
        let mut plain = plain.as_mut();

        if plain.len() != cipher.len() {
            return Err(LengthMismatch(plain.len(), cipher.len()));
        }

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

    /// Decrypt a byte slice with [`Spongos`] object.
    /// Input and output slices must be non-overlapping.
    pub fn decrypt<T>(&mut self, ciphertext: &T) -> Result<T>
    where
        T: AsRef<[u8]> + AsMut<[u8]> + Default,
    {
        let mut plaintext = Default::default();
        self.decrypt_mut(ciphertext, &mut plaintext)?;
        Ok(plaintext)
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

    /// Check whether [`Spongos`] state is committed.
    pub fn is_committed(&self) -> bool {
        0 == self.pos
    }

    /// Join two [`Spongos`] objects.
    ///
    /// Joiner (self) absorbs data squeezed from joinee.
    /// Be aware that before squeezing the joinee, this is commited, its outer state is zeroed, and
    /// a transformation is performed. This means the joinee will be mutated. if this is not
    /// desirable, make sure to clone the joinee beforehand.
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

    /// Returns a reference to the `PRP` outer state
    pub(crate) fn outer(&self) -> &Rate<F> {
        self.s.outer()
    }

    /// Returns a reference to the `PRP` inner state
    pub(crate) fn inner(&self) -> &Capacity<F> {
        self.s.inner()
    }

    /// Returns a mutable reference to the `PRP` outer state
    pub(crate) fn outer_mut(&mut self) -> &mut Rate<F> {
        self.s.outer_mut()
    }

    /// Returns a mutable reference to the `PRP` inner state
    pub(crate) fn inner_mut(&mut self) -> &mut Capacity<F> {
        self.s.inner_mut()
    }
}

impl<F> Spongos<F>
where
    F: Clone,
{
    /// Fork [`Spongos`] object into a new one.
    /// Essentially this just creates a clone of self.
    pub(crate) fn fork(&self) -> Self {
        self.clone()
    }
}

impl<F: PRP> fmt::Debug for Spongos<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}:{}|{}]",
            hex::encode(&self.s.outer().as_ref()[..self.pos]),
            hex::encode(&self.s.outer().as_ref()[self.pos..]),
            hex::encode(self.s.inner().as_ref())
        )
    }
}

impl<F> Digest for Spongos<F>
where
    F: PRP + Default,
    F::CapacitySize: Mul<U2>,
    <F::CapacitySize as Mul<U2>>::Output: ArrayLength<u8>,
{
    // This would normally result in U64, ie 512 bits needed for ed25519prehashed.
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
        Self::OutputSize::USIZE
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut s = Self::new();
        Digest::update(&mut s, data);
        s.finalize()
    }
}
