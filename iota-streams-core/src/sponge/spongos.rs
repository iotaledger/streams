use core::fmt;

use super::prp::PRP;
use crate::{
    hash::Hash,
    prelude::{
        Vec,
        digest::Digest,
        generic_array::{
            typenum::U64,
            GenericArray,
        },
    },
};

/// Implemented as a separate from `Spongos` struct in order to deal with life-times.
pub struct Outer {
    /// Current position (offset in bytes) within the outer state.
    pos: usize,

    /// Outer state is stored externally due to Troika implementation.
    /// It is injected into Troika state before transform and extracted after.
    buf: Vec<u8>,
}

impl Clone for Outer {
    fn clone(&self) -> Self {
        Self {
            pos: self.pos,
            buf: self.buf.clone(),
        }
    }
}

impl Outer {
    /// Create a new outer state with a given rate (size).
    pub fn new(rate: usize) -> Self {
        Self {
            pos: 0,
            buf: vec![0; rate],
        }
    }

    /// `outer_mut` must not be assigned to a variable.
    /// It must be used via `self.outer.slice_mut()` as `self.outer.pos` may change
    /// and it must be kept in sync with `outer_mut` object.
    pub fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.pos..]
    }

    pub fn slice_min_mut(&mut self, n: usize) -> &mut [u8] {
        let m = core::cmp::min(self.pos + n, self.buf.len());
        &mut self.buf[self.pos..m]
    }

    pub fn commit(&mut self) -> &mut [u8] {
        for o in &mut self.buf[self.pos..] {
            *o = 0
        }
        self.pos = 0;
        &mut self.buf[..]
    }

    /// Rate (total size) of the outer state.
    pub fn rate(&self) -> usize {
        self.buf.len()
    }

    /// Available size of the outer tbits.
    pub fn avail(&self) -> usize {
        self.buf.len() - self.pos
    }
}

impl fmt::Debug for Outer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{:?}]", self.pos, self.buf)
    }
}

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

pub struct Spongos<F> {
    /// Spongos transform together with its internal state.
    s: F,

    /// Outer state.
    outer: Outer,
}

impl<F> Clone for Spongos<F>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            s: self.s.clone(),
            outer: self.outer.clone(),
        }
    }
}

impl<F> Spongos<F>
where
    F: PRP,
{
    /// Sponge fixed key size in buf.
    pub const KEY_SIZE: usize = F::CAPACITY_BITS / 8;

    /// Sponge fixed nonce size in buf.
    pub const NONCE_SIZE: usize = Self::KEY_SIZE;

    /// Sponge fixed hash size in buf.
    pub const HASH_SIZE: usize = F::CAPACITY_BITS / 8;

    /// Sponge fixed MAC size in buf.
    pub const MAC_SIZE: usize = F::CAPACITY_BITS / 8;

    /// Create a Spongos object, initialize state with zero trits.
    pub fn init() -> Self {
        Self::init_with_state(F::default())
    }

    /// Create a Spongos object with an explicit state.
    pub fn init_with_state(s: F) -> Self {
        Self {
            s,
            outer: Outer::new(F::RATE),
        }
    }

    pub fn from_inner(inner: Vec<u8>) -> Self {
        Self::init_with_state(inner.into())
    }

    /// Update Spongos after processing the current piece of data of `n` trits.
    fn update(&mut self, n: usize) {
        assert!(!(F::RATE < self.outer.pos + n));
        self.outer.pos += n;
        if F::RATE == self.outer.pos {
            self.commit();
        }
    }

    /// Absorb a slice into Spongos object.
    pub fn absorb(&mut self, mut x: &[u8]) {
        while !x.is_empty() {
            let s = self.outer.slice_min_mut(x.len());
            let n = s.len();
            xor(s, &x[..n]);
            x = &x[n..];
            self.update(n);
        }
    }

    /// Absorb buf.
    pub fn absorb_buf(&mut self, x: &Vec<u8>) {
        self.absorb(&x[..])
    }

    pub fn absorb_ref<X: AsRef<[u8]>>(&mut self, x: X) {
        self.absorb(x.as_ref())
    }

    /// Squeeze a trit slice from Spongos object.
    pub fn squeeze(&mut self, mut y: &mut [u8]) {
        while !y.is_empty() {
            let s = self.outer.slice_min_mut(y.len());
            let n = s.len();
            copy(s, &mut y[..n]);
            y = &mut y[n..];
            self.update(n);
        }
    }

    /// Squeeze a trit slice from Spongos object and compare.
    pub fn squeeze_eq(&mut self, mut y: &[u8]) -> bool {
        let mut eq = true;
        while !y.is_empty() {
            let s = self.outer.slice_min_mut(y.len());
            let n = s.len();
            eq = equals(s, &y[..n]) && eq;
            y = &y[n..];
            self.update(n);
        }
        eq
    }

    /// Squeeze buf.
    pub fn squeeze_buf(&mut self, n: usize) -> Vec<u8> {
        let mut y = vec![0; n];
        self.squeeze(&mut y[..]);
        y
    }

    /// Squeeze buf and compare.
    pub fn squeeze_eq_buf(&mut self, y: &Vec<u8>) -> bool {
        self.squeeze_eq(&y[..])
    }

    /// Encrypt a trit slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub fn encrypt(&mut self, mut x: &[u8], mut y: &mut [u8]) {
        assert_eq!(x.len(), y.len());
        while !x.is_empty() {
            let s = self.outer.slice_min_mut(x.len());
            let n = s.len();
            encrypt_xor(s, &x[..n], &mut y[..n]);
            x = &x[n..];
            y = &mut y[n..];
            self.update(n);
        }
    }

    /// Encrypt in-place a trit slice with Spongos object.
    pub fn encrypt_mut(&mut self, mut xy: &mut [u8]) {
        while !xy.is_empty() {
            let s = self.outer.slice_min_mut(xy.len());
            let n = s.len();
            encrypt_xor_mut(s, &mut xy[..n]);
            xy = &mut xy[n..];
            self.update(n);
        }
    }

    /// Encrypt buf.
    pub fn encrypt_buf(&mut self, x: &Vec<u8>) -> Vec<u8> {
        let mut y = vec![0; x.len()];
        self.encrypt(&x[..], &mut y[..]);
        y
    }

    /// Encrypt buf in-place.
    pub fn encrypt_buf_mut(&mut self, xy: &mut Vec<u8>) {
        self.encrypt_mut(&mut xy[..]);
    }

    /// Decrypt a byte slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub fn decrypt(&mut self, mut y: &[u8], mut x: &mut [u8]) {
        assert_eq!(x.len(), y.len());
        while !x.is_empty() {
            let s = self.outer.slice_min_mut(y.len());
            let n = s.len();
            decrypt_xor(s, &y[..n], &mut x[..n]);
            y = &y[n..];
            x = &mut x[n..];
            self.update(n);
        }
    }

    /// Decrypt in-place a byte slice with Spongos object.
    pub fn decrypt_mut(&mut self, mut xy: &mut [u8]) {
        while !xy.is_empty() {
            let s = self.outer.slice_min_mut(xy.len());
            let n = s.len();
            decrypt_xor_mut(s, &mut xy[..n]);
            xy = &mut xy[n..];
            self.update(n);
        }
    }

    /// Decrypt buf.
    pub fn decrypt_buf(&mut self, y: &Vec<u8>) -> Vec<u8> {
        let mut x = vec![0; y.len()];
        self.decrypt(&y[..], &mut x[..]);
        x
    }

    /// Decrypt buf in-place.
    pub fn decrypt_buf_mut(&mut self, xy: &mut Vec<u8>) {
        self.decrypt_mut(&mut xy[..]);
    }

    /// Force transform even if for incomplete (but non-empty!) outer state.
    /// Commit with empty outer state has no effect.
    pub fn commit(&mut self) {
        if self.outer.pos != 0 {
            let o = self.outer.commit();
            self.s.transform(o);
        }
    }

    /// Check whether spongos state is committed.
    pub fn is_committed(&self) -> bool {
        0 == self.outer.pos
    }

    /// Join two Spongos objects.
    /// Joiner -- self -- object absorbs data squeezed from joinee.
    pub fn join(&mut self, joinee: &mut Self) {
        let mut x = vec![0; F::CAPACITY_BITS / 8];
        joinee.squeeze(&mut x[..]);
        self.absorb(&x[..]);
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
    pub fn to_inner(&self) -> Vec<u8> {
        assert!(self.is_committed());
        let r = self.s.clone().into();
        r
    }
}

impl<F> Default for Spongos<F>
where
    F: PRP,
{
    fn default() -> Self {
        Self::init()
    }
}

impl<F> fmt::Debug for Spongos<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.outer)
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

impl<F> Hash for Spongos<F>
where
    F: PRP,
{
    /// Hash value size in buf.
    const HASH_SIZE: usize = F::CAPACITY_BITS / 8;

    fn init() -> Self {
        init::<F>()
    }

    fn update(&mut self, data: &[u8]) {
        self.absorb(data);
    }

    fn done(&mut self, hash_value: &mut [u8]) {
        self.commit();
        self.squeeze(hash_value);
    }
}

pub fn rehash<F: PRP>(h: &mut [u8]) {
    let mut s = Spongos::<F>::init();
    s.absorb(h);
    s.commit();
    s.squeeze(h);
}

impl<F: PRP> Digest for Spongos<F> {
    type OutputSize = U64;

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
