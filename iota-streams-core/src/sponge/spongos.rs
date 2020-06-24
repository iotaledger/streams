//use std::convert::{AsMut, AsRef, From, TryFrom};
use std::fmt;
//use std::hash;

use super::prp::PRP;
use crate::{
    hash::Hash,
};

/// Implemented as a separate from `Spongos` struct in order to deal with life-times.
pub struct Outer {
    /// Current position (offset in bytes) within the outer state.
    pos: usize,

    /// Outer state is stored externally due to Troika implementation.
    /// It is injected into Troika state before transform and extracted after.
    bytes: Vec<u8>,
}

impl Clone for Outer
{
    fn clone(&self) -> Self {
        Self {
            pos: self.pos,
            bytes: self.bytes.clone(),
        }
    }
}

impl Outer
{
    /// Create a new outer state with a given rate (size).
    pub fn new(rate: usize) -> Self {
        Self {
            pos: 0,
            bytes: Vec::with_capacity(rate),
        }
    }

    /// `outer_mut` must not be assigned to a variable.
    /// It must be used via `self.outer.slice_mut()` as `self.outer.pos` may change
    /// and it must be kept in sync with `outer_mut` object.
    pub fn slice_mut(&mut self) -> &mut [u8] {
        //debug_assert!(self.trits.size() >= RATE);
        //debug_assert!(self.pos <= RATE);
        &mut self.bytes[self.pos..]
    }

    pub fn slice_min_mut(&mut self, n: usize) -> &mut [u8] {
        //TODO: test `_min` [..n]
        &mut self.slice_mut()[..n]
    }

    /// Rate (total size) of the outer state.
    pub fn rate(&self) -> usize {
        self.bytes.len()
    }

    /// Available size of the outer tbits.
    pub fn avail(&self) -> usize {
        self.bytes.len() - self.pos
    }
}

impl fmt::Debug for Outer
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{:?}]", self.pos, self.bytes)
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
    /// Sponge fixed key size in bytes.
    pub const KEY_SIZE: usize = F::CAPACITY_BITS / 8;

    /// Sponge fixed nonce size in bytes.
    pub const NONCE_SIZE: usize = Self::KEY_SIZE;

    /// Sponge fixed hash size in bytes.
    pub const HASH_SIZE: usize = F::CAPACITY_BITS / 8;

    /// Sponge fixed MAC size in bytes.
    pub const MAC_SIZE: usize = F::CAPACITY_BITS / 8;
}

impl<F> Spongos<F>
where
    F: PRP + Default,
{
    /// Create a Spongos object, initialize state with zero trits.
    pub fn init() -> Self {
        Self::init_with_state(F::default())
    }
}

impl<F> Default for Spongos<F>
where
    F: PRP + Default,
{
    fn default() -> Self {
        Self::init()
    }
}

impl<F> Spongos<F>
where
    F: PRP,
{
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

    /// Absorb bytes.
    pub fn absorb_bytes(&mut self, x: &Vec<u8>) {
        self.absorb(&x[..])
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

    /// Squeeze bytes.
    pub fn squeeze_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut y = Vec::with_capacity(n);
        self.squeeze(&mut y[..]);
        y
    }

    /// Squeeze bytes and compare.
    pub fn squeeze_eq_bytes(&mut self, y: &Vec<u8>) -> bool {
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

    /// Encrypt bytes.
    pub fn encrypt_bytes(&mut self, x: &Vec<u8>) -> Vec<u8> {
        let mut y = Vec::with_capacity(x.len());
        self.encrypt(&x[..], &mut y[..]);
        y
    }

    /// Encrypt bytes in-place.
    pub fn encrypt_bytes_mut(&mut self, xy: &mut Vec<u8>) {
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

    /// Decrypt bytes.
    pub fn decrypt_bytes(&mut self, y: &Vec<u8>) -> Vec<u8> {
        let mut x = Vec::with_capacity(y.len());
        self.decrypt(&y[..], &mut x[..]);
        x
    }

    /// Decrypt bytes in-place.
    pub fn decrypt_bytes_mut(&mut self, xy: &mut Vec<u8>) {
        self.decrypt_mut(&mut xy[..]);
    }

    /// Force transform even if for incomplete (but non-empty!) outer state.
    /// Commit with empty outer state has no effect.
    pub fn commit(&mut self) {
        if self.outer.pos != 0 {
            let mut o = self.outer.slice_mut();
            self.s.transform(&mut o);
            self.outer.pos = 0;
        }
    }

    /// Check whether spongos state is committed.
    pub fn is_committed(&self) -> bool {
        0 == self.outer.pos
    }

    /// Join two Spongos objects.
    /// Joiner -- self -- object absorbs data squeezed from joinee.
    pub fn join(&mut self, joinee: &mut Self) {
        let mut x = Vec::with_capacity(F::CAPACITY_BITS / 8);
        joinee.squeeze(&mut x[..]);
        self.absorb(&x[..]);
    }
}

impl<F> Spongos<F>
where
    F: PRP + Clone,
{
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
        assert!(false, "Spongos::to_inner not implemented");
        //TODO:
        //self.s.clone().into()
        Vec::new()
    }
}

impl<F> fmt::Debug for Spongos<F>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.outer)
    }
}

/// Shortcut for `Spongos::init`.
pub fn init<F>() -> Spongos<F>
where
    F: PRP + Default,
{
    Spongos::init()
}

/*
/// Size of inner state.
pub const INNER_SIZE: usize = CAPACITY;
 */

/// Hash (one piece of) data with Spongos.
pub fn hash_data<F>(x: &[u8], y: &mut [u8])
where
    F: PRP + Default,
{
    let mut s = Spongos::<F>::init();
    s.absorb(x);
    s.commit();
    s.squeeze(y);
}

/*
/// Hash a concatenation of pieces of data with Spongos.
pub fn hash_datas(xs: &[TritSlice], y: TritSliceMut) {
    let mut s = Spongos::init();
    for x in xs {
        s.absorb(*x);
    }
    s.commit();
    s.squeeze(&mut y);
}
 */

impl<F> Hash for Spongos<F>
where
    F: PRP + Clone + Default,
{
    /// Hash value size in bytes.
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

/*
pub fn hash_tbits<F>(data: &Tbits) -> Tbits
where
    F: PRP + Clone + Default,
{
    let mut s = Spongos::<F>::init();
    s.absorb(data.slice());
    s.commit();
    s.squeeze_tbits(Spongos::<F>::HASH_SIZE)
}

pub fn rehash_tbits<F>(h: &mut Tbits)
where
    F: PRP + Clone + Default,
{
    let mut s = Spongos::<F>::init();
    s.absorb(h.slice());
    s.commit();
    s.squeeze(&mut h.slice_mut());
}
 */
