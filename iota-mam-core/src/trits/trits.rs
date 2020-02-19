use std::fmt;
use std::hash;
use std::ops;
use std::str::FromStr;

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
    TW: BasicTritWord + Copy,
{
    /// Create a container filled with `n` zero trits.
    pub fn zero(n: usize) -> Self {
        Self {
            n,
            buf: vec![TW::zero(); (n + TW::SIZE - 1) / TW::SIZE],
        }
    }

    /// Create an empty container.
    pub fn new() -> Self {
        Self {
            n: 0,
            buf: Vec::new(),
        }
    }

    /// Create container and initialize trits by copying from slice `t`.
    pub fn from_slice(t: TritSliceT<TW>) -> Self {
        let mut x = Self::zero(t.size());
        t.copy(x.slice_mut());
        x
    }

    pub fn from_trits(ts: &[Trit]) -> Self {
        let mut x = Self::zero(ts.len());
        x.slice_mut().put_trits(ts);
        x
    }

    pub fn from_slices(ts: &[TritSliceT<TW>]) -> Self {
        let size = ts.iter().fold(0, |size, t| size + t.size());
        let mut x = Self::zero(size);
        ts.iter()
            .fold(x.slice_mut(), |slice, t| slice.drop(t.copy_min(slice)));
        x
    }

    /// Create a container with `n` trits and cycle `t` to fill it.
    pub fn cycle_trits(n: usize, t: &Self) -> Self {
        let mut x = Self::zero(n);
        x.slice_mut().cycle(t.slice());
        x
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

impl<TW> TritsT<TW>
where
    TW: TritWord + Copy,
{
    /// Create a container with `n` trits and cycle `s` to fill it.
    pub fn cycle_str(n: usize, s: &str) -> Self {
        //Self::from_str(s).map_or(Self::zero(n), |t| Self::cycle_trits(n, &t))
        Self::cycle_trits(n, &Self::from_str(s).unwrap_or(Self::zero(0)))
    }

    /// ASCII convert trytes.
    pub fn to_str(&self) -> String {
        self.slice().to_string()
    }

    /// Compare to ASCII string.
    pub fn eq_str(&self, s: &str) -> bool {
        self.slice().eq_str(s)
    }

    /// Increment trits.
    pub fn inc(&mut self) -> bool {
        self.slice_mut().inc()
    }
}

impl<TW> FromStr for TritsT<TW>
where
    TW: TritWord + Copy,
{
    type Err = ();
    /// Try parse and create trits from ASCII-encoded tryte string `s`.
    fn from_str(s: &str) -> Result<Self, ()> {
        // Optimistically alloc memory first.
        let mut t = Self::zero(3 * s.len());
        if t.slice_mut().from_str(s) {
            Ok(t)
        } else {
            Err(())
        }
    }
}

impl<TW> PartialEq for TritsT<TW>
where
    TW: BasicTritWord + Copy,
{
    fn eq(&self, other: &Self) -> bool {
        self.slice() == other.slice()
    }
}
impl<TW> Eq for TritsT<TW> where TW: BasicTritWord + Copy {}

impl<TW> hash::Hash for TritsT<TW>
where
    TW: BasicTritWord,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.slice().hash(state);
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
    TW: BasicTritWord + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{:?}]", self.n, self.slice())
    }
}

impl<TW> ops::Add for &TritsT<TW>
where
    TW: TritWord + Copy,
{
    type Output = TritsT<TW>;
    fn add(self, rhs: &TritsT<TW>) -> Self::Output {
        let mut trits = TritsT::zero(self.size() + rhs.size());
        self.slice().copy(trits.slice_mut().take(self.size()));
        rhs.slice().copy(trits.slice_mut().drop(self.size()));
        trits
    }
}

impl<TW> ops::AddAssign<&TritsT<TW>> for TritsT<TW>
where
    TW: TritWord + Copy,
{
    fn add_assign(&mut self, rhs: &TritsT<TW>) {
        let mut trits = TritsT::zero(self.size() + rhs.size());
        self.slice().copy(trits.slice_mut().take(self.size()));
        rhs.slice().copy(trits.slice_mut().drop(self.size()));
        *self = trits;
    }
}

pub type DefaultTritWord = Trit;
pub type Trits = TritsT<DefaultTritWord>;
pub type TritSlice<'a> = TritSliceT<'a, DefaultTritWord>;
pub type TritSliceMut<'a> = TritSliceMutT<'a, DefaultTritWord>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn add() {
        assert_eq!(
            Trits::from_str("AB").unwrap(),
            &Trits::from_str("A").unwrap() + &Trits::from_str("B").unwrap()
        );
        let mut a = Trits::from_str("A").unwrap();
        a += &Trits::from_str("B").unwrap();
        assert_eq!(a, Trits::from_str("AB").unwrap());
    }

    #[test]
    fn str() {
        let mut ts = Trits::zero(15);
        assert!(ts.slice_mut().from_str("9ANMZ"));
        let s = ts.slice().to_string();
        assert_eq!(s, "9ANMZ");

        let mut trits = vec![Trit(0); 15];
        ts.slice().get_trits(&mut trits);
        assert_eq!(
            trits,
            vec![0, 0, 0, 1, 0, 0, 2, 2, 2, 1, 1, 1, 2, 0, 0]
                .into_iter()
                .map(|u| Trit(u))
                .collect::<Vec<Trit>>()
        );

        assert_eq!(Trint3(0), Trits::from_str("9").unwrap().slice().get3());
        assert_eq!(Trint3(1), Trits::from_str("A").unwrap().slice().get3());
        assert_eq!(Trint3(2), Trits::from_str("B").unwrap().slice().get3());
        assert_eq!(Trint3(13), Trits::from_str("M").unwrap().slice().get3());
        assert_eq!(Trint3(-13), Trits::from_str("N").unwrap().slice().get3());
        assert_eq!(Trint3(-1), Trits::from_str("Z").unwrap().slice().get3());

        assert_eq!("AAA", Trits::cycle_str(9, "A").to_string());
        assert_eq!("AAAA", Trits::cycle_str(10, "A").to_string());
    }

    #[test]
    fn eq_str() {
        for n in 0..4 {
            let mut t = Trits::zero(n);
            loop {
                let s = t.to_string();
                assert!(Trits::from_str(&s).map_or_else(|_| false, |t| t.eq_str(&s)));
                if !t.inc() {
                    break;
                }
            }
        }
    }

    #[test]
    fn mutate() {
        let mut t = TritsT::<Trit> {
            n: 1,
            buf: vec![Trit(1)],
        };
        let m = t.slice_mut();
        let s = m.as_const();

        // The following definition of slice is refused: mutable borrow occurs.
        //let s = t.slice();

        m.put1(Trint1(1));
        assert_eq!(Trint1(1), s.get1());
        m.put1(Trint1(0));
        assert_eq!(Trint1(0), s.get1());

        // The following line is refused: cannot borrow `t.buf` as mutable more than once at a time.
        //t.buf.push(0);

        assert_eq!(Trint1(0), s.get1());
    }

    #[test]
    fn slices() {
        let a = Trits::from_str("AAA").unwrap();
        let b = Trits::from_str("B").unwrap();
        let c = Trits::from_str("CC").unwrap();
        let abc = Trits::from_slices(&[a.slice(), b.slice(), c.slice()]);
        assert_eq!(abc, Trits::from_str("AAABCC").unwrap());
    }
}
