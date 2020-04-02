use std::fmt;
use std::hash;
use std::ops;
use std::str::FromStr;
use std::string::ToString;

use super::{slice::*, word::*};

/// Container for tbits using a certain tbit encoding.
/// Access to the individual tbits should be performed via `TbitConstSliceT` and `TbitMutSliceT` types.
#[derive(Clone)]
pub struct Tbits<TW> {
    n: usize,
    buf: std::vec::Vec<TW>,
}

impl<TW> Tbits<TW>
where
    TW: BasicTbitWord,
{
    /// Create a container filled with `n` zero tbits.
    pub fn zero(n: usize) -> Self {
        Self {
            n,
            buf: vec![TW::ZERO_WORD; (n + TW::SIZE - 1) / TW::SIZE],
        }
    }

    /// Create an empty container.
    pub fn new() -> Self {
        Self {
            n: 0,
            buf: Vec::new(),
        }
    }

    /// Create container and initialize tbits by copying from slice `t`.
    pub fn from_slice(t: TbitSlice<TW>) -> Self {
        let mut x = Self::zero(t.size());
        t.copy(&mut x.slice_mut());
        x
    }

    pub fn from_tbits(ts: &[TW::Tbit]) -> Self {
        let mut x = Self::zero(ts.len());
        x.slice_mut().put_tbits(ts);
        x
    }

    pub fn from_slices(ts: &[TbitSlice<TW>]) -> Self {
        let size = ts.iter().fold(0, |size, t| size + t.size());
        let mut x = Self::zero(size);
        ts.iter().fold(x.slice_mut(), |slice, t| {
            let (mut head, tail) = slice.split_at(t.size());
            t.copy(&mut head);
            tail
        });
        x
    }

    /// Create a container with `n` tbits and cycle `t` to fill it.
    pub fn cycle_tbits(n: usize, t: &Self) -> Self {
        let mut x = Self::zero(n);
        x.slice_mut().cycle(t.slice());
        x
    }

    pub fn set_zero(&mut self) {
        for tw in self.buf.iter_mut() {
            *tw = TW::ZERO_WORD;
        }
    }

    /// Return a constant slice object to the tbits in the container.
    pub fn slice(&self) -> TbitSlice<TW> {
        TbitSlice::from_raw_ptr(self.size(), self.buf.as_ptr())
    }

    /// Return a mutable slice object to the tbits in the container.
    pub fn slice_mut(&mut self) -> TbitSliceMut<TW> {
        TbitSliceMut::from_raw_ptr(self.size(), self.buf.as_mut_ptr())
    }

    /// Return internal buffer length, ie. the number of tbit words.
    pub fn buf_len(&self) -> usize {
        self.buf.len()
    }

    /// Return the number of tbits in the container.
    pub fn size(&self) -> usize {
        self.n
    }

    /// Is container empty?
    pub fn is_empty(&self) -> bool {
        0 == self.n
    }
}

impl<TW> Tbits<TW>
where
    TW: StringTbitWord,
{
    /// Create a container with `n` tbits and cycle `s` to fill it.
    pub fn cycle_str(n: usize, s: &str) -> Self {
        //Self::from_str(s).map_or(Self::zero(n), |t| Self::cycle_tbits(n, &t))
        Self::cycle_tbits(n, &Self::from_str(s).unwrap_or(Self::zero(0)))
    }

    /// Compare to ASCII string.
    pub fn eq_str(&self, s: &str) -> bool {
        self.slice().eq_str(s)
    }

    /*
    /// Increment tbits.
    pub fn inc(&mut self) -> bool {
        self.slice_mut().inc()
    }
     */
}

impl<TW> FromStr for Tbits<TW>
where
    TW: StringTbitWord,
{
    type Err = ();
    /// Try parse and create tbits from ASCII-encoded tryte string `s`.
    fn from_str(s: &str) -> Result<Self, ()> {
        // Optimistically alloc memory first.
        let mut t = Self::zero(TW::TBITS_PER_CHAR * s.len());
        if t.slice_mut().from_str(s) {
            Ok(t)
        } else {
            Err(())
        }
    }
}

impl<TW> ToString for Tbits<TW>
where
    TW: StringTbitWord,
{
    /// ASCII convert trytes.
    fn to_string(&self) -> String {
        self.slice().to_str()
    }
}

impl<TW> PartialEq for Tbits<TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.slice() == other.slice()
    }
}
impl<TW> Eq for Tbits<TW> where TW: BasicTbitWord {}

impl<TW> hash::Hash for Tbits<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.slice().hash(state);
    }
}

/*
impl<TW> fmt::Display for Tbits<TW>
where
    TW: StringTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.slice().fmt(f)
    }
}
 */

impl<TW> fmt::Debug for Tbits<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{:?}]", self.n, self.slice())
    }
}

impl<TW> ops::Add for &Tbits<TW>
where
    TW: BasicTbitWord + Copy,
{
    type Output = Tbits<TW>;
    fn add(self, rhs: &Tbits<TW>) -> Self::Output {
        let n = self.size();
        let mut tbits = Tbits::zero(n + rhs.size());
        let (mut left, mut right) = tbits.slice_mut().split_at(n);
        self.slice().copy(&mut left);
        rhs.slice().copy(&mut right);
        tbits
    }
}

impl<TW> ops::AddAssign<&Tbits<TW>> for Tbits<TW>
where
    TW: BasicTbitWord,
{
    fn add_assign(&mut self, rhs: &Tbits<TW>) {
        let n = self.n;
        self.n += rhs.n;
        self.buf
            .resize((self.n + TW::SIZE - 1) / TW::SIZE, TW::ZERO_WORD);
        let mut right = self.slice_mut().drop(n);
        rhs.slice().copy(&mut right);
    }
}

impl<'a, TW: 'a> TbitSlice<'a, TW>
where
    TW: BasicTbitWord,
{
    /// Clone tbits chunks.
    pub fn tbits_chunks(mut self, chunk_size: usize) -> Vec<Tbits<TW>> {
        // Can't divide by zero.
        assert!(chunk_size != 0);
        let chunks_count = (self.size() + chunk_size - 1) / chunk_size;
        let mut v = Vec::with_capacity(chunks_count);
        while !self.is_empty() {
            v.push(Tbits::from_slice(self.take_min(chunk_size)));
            self = self.drop_min(chunk_size);
        }
        v
    }
}
/*
pub type DefaultTbitWord = Tbit;
pub type Tbits = Tbits<DefaultTbitWord>;
pub type TbitSlice<'a> = TbitSlice<'a, DefaultTbitWord>;
pub type TbitSliceMut<'a> = TbitSliceMut<'a, DefaultTbitWord>;
 */
