//! Lightweight abstraction, a trinary equivalent of `Write` trait allowing access to trinary slices.

use failure::{bail, ensure, Fallible};
use iota_mam_core::trits::{
    word::TritWord, DefaultTritWord, TritSlice, TritSliceMut, TritSliceMutT, TritSliceT,
};

/// Write
pub trait OStreamT<TW> {
    /// Try advance and panic in case of error.
    fn advance<'a>(&'a mut self, n: usize) -> TritSliceMutT<'a, TW> {
        let r = self.try_advance(n);
        assert!(r.is_ok());
        r.unwrap()
    }

    /// Try put n trits into the stream, returning a slice to the buffer.
    fn try_advance<'a>(&'a mut self, n: usize) -> Fallible<TritSliceMutT<'a, TW>>;

    /// Commit advanced buffers to the internal sink.
    fn commit(&mut self);

    /// Dump stream debug info.
    fn dump(&self) -> String {
        String::new()
    }
}

/// Read
pub trait IStreamT<TW> {
    /// Try advance and panic in case of error.
    fn advance<'a>(&'a mut self, n: usize) -> TritSliceT<'a, TW> {
        let r = self.try_advance(n);
        assert!(r.is_ok());
        r.unwrap()
    }

    /// Try get n trits from the stream, returning a slice to the buffer.
    fn try_advance<'a>(&'a mut self, n: usize) -> Fallible<TritSliceT<'a, TW>>;

    /// Commit advanced buffers from the internal sources.
    fn commit(&mut self);

    /// Dump stream debug info.
    fn dump(&self) -> String {
        String::new()
    }
}

pub trait OStream: OStreamT<DefaultTritWord> {}

pub trait IStream: IStreamT<DefaultTritWord> {}

impl<'b, TW> OStreamT<TW> for TritSliceMutT<'b, TW>
where
    TW: Copy + TritWord,
{
    fn try_advance<'a>(&'a mut self, n: usize) -> Fallible<TritSliceMutT<'a, TW>> {
        ensure!(n <= self.size(), "Output slice too short.");
        Ok(self.advance(n))
    }
    fn commit(&mut self) {}
    fn dump(&self) -> String {
        format!("{:?}", self)
    }
}
impl<'b> OStream for TritSliceMut<'b> {}

impl<'b, TW> IStreamT<TW> for TritSliceT<'b, TW>
where
    TW: Copy + TritWord,
{
    fn try_advance<'a>(&'a mut self, n: usize) -> Fallible<TritSliceT<'a, TW>> {
        ensure!(n <= self.size(), "Input slice too short.");
        Ok(self.advance(n))
    }
    fn commit(&mut self) {}
    fn dump(&self) -> String {
        format!("{:?}", self)
    }
}
impl<'b> IStream for TritSlice<'b> {}

pub struct NoOStream;

impl<TW> OStreamT<TW> for NoOStream {
    fn advance<'a>(&'a mut self, n: usize) -> TritSliceMutT<'a, TW> {
        assert!(false, "Advance can't be implemented for NoOStream");
        self.try_advance(n).unwrap()
    }
    fn try_advance<'a>(&'a mut self, _n: usize) -> Fallible<TritSliceMutT<'a, TW>> {
        bail!("Advance can't be implemented for NoOStream")
    }
    fn commit(&mut self) {}
}
impl OStream for NoOStream {}

pub struct NoIStream;

impl<TW> IStreamT<TW> for NoIStream {
    fn advance<'a>(&'a mut self, n: usize) -> TritSliceT<'a, TW> {
        assert!(false, "Advance can't be implemented for NoIStream");
        self.try_advance(n).unwrap()
    }
    fn try_advance<'a>(&'a mut self, _n: usize) -> Fallible<TritSliceT<'a, TW>> {
        bail!("Advance can't be implemented for NoIStream")
    }
    fn commit(&mut self) {}
}

impl IStream for NoIStream {}

#[cfg(test)]
mod test {
    use super::*;
    use iota_mam_core::spongos::Spongos;
    use iota_mam_core::trits::{TritSlice, TritSliceMut, Trits};
    use std::str::FromStr;

    fn wrap_absorb_trits<OS: OStream>(x: TritSlice, s: &mut Spongos, os: &mut OS) -> () {
        let n = x.size();
        let t = os.advance(n);
        x.copy(t);
        s.absorb(x);
    }

    fn unwrap_absorb_trits<IS: IStream>(
        x: TritSliceMut,
        s: &mut Spongos,
        is: &mut IS,
    ) -> Fallible<()> {
        let n = x.size();
        let t = is.try_advance(n)?;
        t.copy(x);
        s.absorb(x.as_const());
        Ok(())
    }

    #[test]
    pub fn wrap_unwrap() {
        let x = Trits::from_str("ABC").unwrap();
        let mut y = Trits::zero(x.size());

        let mut buf = Trits::zero(x.size());

        let tag = {
            let mut s = Spongos::init();
            let mut b = buf.slice_mut();
            wrap_absorb_trits(x.slice(), &mut s, &mut b);
            s.squeeze_trits(81);
        };

        let tag2 = {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let r = unwrap_absorb_trits(y.slice_mut(), &mut s, &mut b);
            assert!(r.is_ok());
            s.squeeze_trits(81);
        };

        assert_eq!(x, y);
        assert_eq!(tag, tag2);
    }
}
