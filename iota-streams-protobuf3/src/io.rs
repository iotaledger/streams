//! Lightweight abstraction, a trinary equivalent of `Write` trait allowing access to trinary slices.

use anyhow::{
    bail,
    ensure,
    Result,
};

use iota_streams_core::prelude::String;

/// Write
pub trait OStream {
    /// Try advance and panic in case of error.
    fn advance<'a>(&'a mut self, n: usize) -> &'a mut [u8] {
        let r = self.try_advance(n);
        assert!(r.is_ok());
        r.unwrap()
    }

    /// Try put n tbits into the stream, returning a slice to the buffer.
    fn try_advance<'a>(&'a mut self, n: usize) -> Result<&'a mut [u8]>;

    /// Commit advanced buffers to the internal sink.
    fn commit(&mut self);

    /// Dump stream debug info.
    fn dump(&self) -> String {
        String::new()
    }
}

/// Read
pub trait IStream {
    /// Try advance and panic in case of error.
    fn advance<'a>(&'a mut self, n: usize) -> &'a [u8] {
        let r = self.try_advance(n);
        assert!(r.is_ok());
        r.unwrap()
    }

    /// Try get n tbits from the stream, returning a slice to the buffer.
    fn try_advance<'a>(&'a mut self, n: usize) -> Result<&'a [u8]>;

    /// Commit advanced buffers from the internal sources.
    fn commit(&mut self);

    /// Dump stream debug info.
    fn dump(&self) -> String {
        String::new()
    }
}

impl<'b> OStream for &'b mut [u8] {
    fn try_advance<'a>(&'a mut self, n: usize) -> Result<&'a mut [u8]> {
        ensure!(n <= self.len(), "Output slice too short.");
        let (head, tail) = (*self).split_at_mut(n);
        unsafe {
            *self = core::mem::transmute::<&'a mut [u8], &'b mut [u8]>(tail);
        }
        Ok(head)
    }
    fn commit(&mut self) {}
    fn dump(&self) -> String {
        format!("{:?}", self)
    }
}

impl<'b> IStream for &'b [u8] {
    fn try_advance<'a>(&'a mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.len(), "Input slice too short.");
        let (head, tail) = (*self).split_at(n);
        unsafe {
            *self = core::mem::transmute::<&'a [u8], &'b [u8]>(tail);
        }
        Ok(head)
    }
    fn commit(&mut self) {}
    fn dump(&self) -> String {
        format!("{:?}", self)
    }
}

pub struct NoOStream;

impl OStream for NoOStream {
    fn advance<'a>(&'a mut self, n: usize) -> &'a mut [u8] {
        assert!(false, "Advance can't be implemented for NoOStream");
        self.try_advance(n).unwrap()
    }
    fn try_advance<'a>(&'a mut self, _n: usize) -> Result<&'a mut [u8]> {
        bail!("Advance can't be implemented for NoOStream")
    }
    fn commit(&mut self) {}
}

pub struct NoIStream;

impl IStream for NoIStream {
    fn advance<'a>(&'a mut self, n: usize) -> &'a [u8] {
        assert!(false, "Advance can't be implemented for NoIStream");
        self.try_advance(n).unwrap()
    }
    fn try_advance<'a>(&'a mut self, _n: usize) -> Result<&'a [u8]> {
        bail!("Advance can't be implemented for NoIStream")
    }
    fn commit(&mut self) {}
}

/*
#[cfg(test)]
mod test {
    use super::*;
    use iota_streams_core::{
        sponge::{
            prp::PRP,
            spongos::Spongos,
        },
    };
    use std::str::FromStr;

    fn wrap_absorb_tbits<F, OS: OStream>(x: TbitSlice, s: &mut Spongos<F>, os: &mut OS) -> ()
    where
        TW: SpongosTbitWord,
        F: PRP,
    {
        let n = x.size();
        let t = os.advance(n);
        x.copy(&t);
        s.absorb(x);
    }

    fn unwrap_absorb_tbits<F, IS: IStream>(
        x: TbitSliceMut,
        s: &mut Spongos<F>,
        is: &mut IS,
    ) -> Result<()>
    where
        TW: SpongosTbitWord,
        F: PRP,
    {
        let n = x.size();
        let t = is.try_advance(n)?;
        t.copy(&x);
        s.absorb(unsafe { x.as_const() });
        Ok(())
    }

    fn do_wrap_unwrap<F>()
    where
        TW: SpongosTbitWord + StringTbitWord,
        F: PRP + Default,
    {
        let x = Tbits::::from_str("ABC").unwrap();
        let mut y = Tbits::::zero(x.size());

        let mut buf = Tbits::::zero(x.size());

        let tag = {
            let mut s = Spongos::<F>::init();
            let mut b = buf.slice_mut();
            wrap_absorb_tbits(x.slice(), &mut s, &mut b);
            s.squeeze_tbits(81);
        };

        let tag2 = {
            let mut s = Spongos::<F>::init();
            let mut b = buf.slice();
            let r = unwrap_absorb_tbits(y.slice_mut(), &mut s, &mut b);
            assert!(r.is_ok());
            s.squeeze_tbits(81);
        };

        assert_eq!(x, y);
        assert_eq!(tag, tag2);
    }

    #[test]
    pub fn wrap_unwrap() {
        use iota_streams_core::{
            sponge::prp::troika::Troika,
            tbits::trinary::Trit,
        };
        do_wrap_unwrap::<Trit, Troika>();
    }
}
 */
