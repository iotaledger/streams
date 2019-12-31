//! PB3 `absorb` and `absorb external` command.

use crate::pb3::err::{Err, guard, Result};
use crate::spongos::{Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};
use super::wrp::{Wrap, Unwrap};

/// PB3 types that can be absorbed.
pub trait Absorb where Self: Sized {

    fn wrap_absorb(&self, s: &mut Spongos, b: &mut TritMutSlice);

    fn unwrap_absorb(&mut self, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
        let v = Self::unwrap_absorb_sized(s, b)?;
        *self = v;
        Ok(())
    }

    fn unwrap_absorb_sized(s: &mut Spongos, b: &mut TritConstSlice) -> Result<Self>;
}

/// `absorb` helper.
pub(crate) struct WrapAbsorb<'a> {
    pub(crate) s: &'a mut Spongos,
}

impl<'a> Wrap for WrapAbsorb<'a> {

    /// Encode tryte and absorb codeword.
    fn wrap3(&mut self, b: &mut TritMutSlice, d: trits::Trint3) {
        let b0 = b.advance(3);
        b0.put3(d);
        self.s.absorb(b0.as_const());
    }

    /// Absorb trits and copy into the buffer.
    fn wrapn(&mut self, b: &mut TritMutSlice, t: TritConstSlice) {
        self.s.absorb(t);
        t.copy(b.advance(t.size()));
    }
}

impl<'a> Unwrap for WrapAbsorb<'a> {

    /// Absorb codeword and decode tryte.
    fn unwrap3(&mut self, b: &mut TritConstSlice) -> Result<trits::Trint3> {
        guard(3 <= b.size(), Err::Eof)?;
        let b0 = b.advance(3);
        self.s.absorb(b0);
        Ok(b0.get3())
    }

    /// Copy trits from the buffer and absorb.
    fn unwrapn(&mut self, b: &mut TritConstSlice, t: TritMutSlice) -> Result<()> {
        guard(t.size() <= b.size(), Err::Eof)?;
        b.advance(t.size()).copy(t);
        self.s.absorb(t.as_const());
        Ok(())
    }
}

/// PB3 external types that can be absorbed.
pub trait AbsorbExternal {

    fn slice(&self) -> TritConstSlice;

    fn wrap_absorb_external(&self, s: &mut Spongos) {
        s.absorb(self.slice());
    }

    fn unwrap_absorb_external(&self, s: &mut Spongos) {
        s.absorb(self.slice());
    }
}
