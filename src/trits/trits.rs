use std::fmt;
use std::hash::{Hash, Hasher};

use super::{defs::*, slice::*, word::*};

/// Container for trits using a certain trit encoding.
/// Access to the individual trits should be performed via `TritConstSliceT` and `TritMutSliceT` types.
#[derive(Clone)]
pub struct TritsT<TW> {
    n: usize,
    buf: std::vec::Vec<TW>,
}

impl<TW> TritsT<TW>
where
    TW: TritWord + Copy,
{
    /// Create a container filled with `n` zero trits.
    pub fn zero(n: usize) -> Self {
        Self {
            n,
            buf: vec![TW::zero(); (n + TW::SIZE - 1) / TW::SIZE],
        }
    }

    /// Create container and initialize trits by copying from slice `t`.
    pub fn from_slice(t: TritSliceT<TW>) -> Self {
        let mut x = Self::zero(t.size());
        t.copy(x.slice_mut());
        x
    }

    /// Create a container with `n` trits and cycle `t` to fill it.
    pub fn cycle_trits(n: usize, t: &Self) -> Self {
        let mut x = Self::zero(n);
        x.slice_mut().cycle(t.slice());
        x
    }

    /// Create a container with `n` trits and cycle `s` to fill it.
    pub fn cycle_str(n: usize, s: &str) -> Self {
        //Self::from_str(s).map_or(Self::zero(n), |t| Self::cycle_trits(n, &t))
        Self::cycle_trits(n, &Self::from_str(s).unwrap_or(Self::zero(0)))
    }

    /// Try parse and create trits from ASCII-encoded tryte string `s`.
    pub fn from_str(s: &str) -> Option<Self> {
        let mut t = Self::zero(3 * s.len());
        if t.slice_mut().from_str(s) {
            Some(t)
        } else {
            None
        }
    }

    /// ASCII convert trytes.
    pub fn to_str(&self) -> String {
        self.slice().to_str()
    }

    /// Return a constant slice object to the trits in the container.
    pub fn slice(&self) -> TritSliceT<TW> {
        TritSliceT::from_raw_ptr(self.size(), self.buf.as_ptr())
    }
    /// Return a mutable slice object to the trits in the container.
    pub fn slice_mut(&mut self) -> TritSliceMutT<TW> {
        TritSliceMutT::from_raw_ptr(self.size(), self.buf.as_mut_ptr())
    }
    /// Return internal buffer length, ie. the number of trit words.
    pub fn buf_len(&self) -> usize {
        self.buf.len()
    }
    /// Return the number of trits in the container.
    pub fn size(&self) -> usize {
        self.n
    }
    /// Is container empty?
    pub fn is_empty(&self) -> bool {
        0 == self.n
    }
}

impl<TW> PartialEq for TritsT<TW>
where
    TW: TritWord + Copy,
{
    fn eq(&self, other: &Self) -> bool {
        self.slice() == other.slice()
    }
}
impl<TW> Eq for TritsT<TW> where TW: TritWord + Copy {}

impl<TW> Hash for TritsT<TW>
where
    TW: TritWord + Copy + Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.n.hash(state);
        self.buf.hash(state);
    }
}

impl<TW> fmt::Display for TritsT<TW>
where
    TW: TritWord + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.slice().fmt(f)
    }
}

impl<TW> fmt::Debug for TritsT<TW>
where
    TW: TritWord + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{:?}]", self.n, self.slice())
    }
}

pub type DefaultTritWord = Trit;
pub type Trits = TritsT<DefaultTritWord>;
pub type TritSlice<'a> = TritSliceT<'a, DefaultTritWord>;
pub type TritSliceMut<'a> = TritSliceMutT<'a, DefaultTritWord>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str() {
        let mut ts = Trits::zero(15);
        assert!(ts.slice_mut().from_str("9ANMZ"));
        let s = ts.slice().to_str();
        assert_eq!(s, "9ANMZ");

        let mut trits = [0; 15];
        ts.slice().get_trits(&mut trits);
        assert_eq!(trits, [0, 0, 0, 1, 0, 0, 2, 2, 2, 1, 1, 1, 2, 0, 0]);

        assert_eq!(0, Trits::from_str("9").unwrap().slice().get3());
        assert_eq!(1, Trits::from_str("A").unwrap().slice().get3());
        assert_eq!(2, Trits::from_str("B").unwrap().slice().get3());
        assert_eq!(13, Trits::from_str("M").unwrap().slice().get3());
        assert_eq!(-13, Trits::from_str("N").unwrap().slice().get3());
        assert_eq!(-1, Trits::from_str("Z").unwrap().slice().get3());

        assert_eq!("AAA", Trits::cycle_str(9, "A").to_str());
        assert_eq!("AAAA", Trits::cycle_str(10, "A").to_str());
    }

    #[test]
    fn mutate() {
        let mut t = TritsT::<Trit> { n: 1, buf: vec![1] };
        let m = t.slice_mut();
        let s = m.as_const();

        // The following definition of slice is refused: mutable borrow occurs.
        //let s = t.slice();

        m.put1(1);
        assert_eq!(1, s.get1());
        m.put1(0);
        assert_eq!(0, s.get1());

        // The following line is refused: cannot borrow `t.buf` as mutable more than once at a time.
        //t.buf.push(0);

        assert_eq!(0, s.get1());
    }
}
