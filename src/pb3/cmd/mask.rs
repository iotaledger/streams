//! PB3 `mask` command.

use super::wrp::{Unwrap, Wrap};
use crate::pb3::err::{guard, Err, Result};
use crate::spongos::Spongos;
use crate::trits::{self, TritSlice, TritSliceMut};

/// PB3 types that can be masked.
pub trait Mask
where
    Self: Sized,
{
    fn wrap_mask(&self, s: &mut Spongos, b: &mut TritSliceMut);

    fn unwrap_mask(&mut self, s: &mut Spongos, b: &mut TritSlice) -> Result<()> {
        let v = Self::unwrap_mask_sized(s, b)?;
        *self = v;
        Ok(())
    }

    fn unwrap_mask_sized(s: &mut Spongos, b: &mut TritSlice) -> Result<Self>;
}

/// `mask` helper.
pub(crate) struct WrapMask<'a> {
    pub(crate) s: &'a mut Spongos,
}

impl<'a> Wrap for WrapMask<'a> {
    /// Encode tryte and `encr` in-place.
    fn wrap3(&mut self, b: &mut TritSliceMut, d: trits::Trint3) {
        let b0 = b.advance(3);
        b0.put3(d);
        self.s.encr(b0.as_const(), b0);
    }

    /// `encr` trits into the buffer.
    fn wrapn(&mut self, b: &mut TritSliceMut, t: TritSlice) {
        self.s.encr(t, b.advance(t.size()));
    }
}

impl<'a> Unwrap for WrapMask<'a> {
    /// `decr` codeword into a temp buffer and decode tryte.
    fn unwrap3(&mut self, b: &mut TritSlice) -> Result<trits::Trint3> {
        guard(3 <= b.size(), Err::Eof)?;
        let b0 = b.advance(3);
        let mut d = trits::Trits::zero(3);
        self.s.decr(b0, d.slice_mut());
        Ok(d.slice().get3())
    }

    /// `decr` trits from the buffer.
    fn unwrapn(&mut self, b: &mut TritSlice, t: TritSliceMut) -> Result<()> {
        guard(t.size() <= b.size(), Err::Eof)?;
        self.s.decr(b.advance(t.size()), t);
        Ok(())
    }
}
